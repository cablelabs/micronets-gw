import asyncio
import logging
import locale
import subprocess
import threading
import traceback
import re
import netaddr
from queue import Queue, Empty
from subprocess import Popen, PIPE
from ipaddress import IPv4Network, IPv4Address
from pathlib import Path

logger = logging.getLogger ('hostapd_adapter')

class HostapdAdapter:

    cli_event_re = re.compile ('^.*<([0-9+])>(.+)$')
    cli_ready_re = re.compile ('Connection.*established|Interactive mode')

    def __init__ (self, hostapd_psk_path, hostapd_cli_path, hostapd_cli_args=()):
        self.event_handler_table = []
        self.hostapd_psk_path = Path(hostapd_psk_path) if hostapd_psk_path else None
        self.hostapd_cli_path = Path(hostapd_cli_path) if hostapd_cli_path else None
        self.hostapd_cli_args = hostapd_cli_args
        self.hostapd_cli_process = None
        self.process_reader_thread = None
        self.command_queue = None
        self.event_loop = None
        self.cli_connected = False
        self.cli_ready = False
        self.status_vars = None

    class HostapdCLIEventHandler:
        def __init__ (self, event_prefixes):
            self.hostapd_adapter = None
            self.event_prefixes = event_prefixes

        async def handle_hostapd_ready(self):
            pass

        async def handle_hostapd_cli_event(self, event):
            pass

    def register_cli_event_handler(self, handler):
        logger.info (f"HostapdAdapter: Registering event handler: {handler}")
        self.event_handler_table.append(handler)
        handler.hostapd_adapter = self

    def unregister_cli_event_handler(self, handler):
        del self.event_handler_table.remove[handler.type_prefix]
        handler.hostapd_adapter = None

    async def update (self, micronet_list, device_lists):
        logger.info (f"HostapdAdapter.update()")
        if not self.hostapd_psk_path:
            logger.info(f"HostapdAdapter.update: No PSK file configured, so nothing to do")

        with self.hostapd_psk_path.open ('w') as outfile:
            bss_list = list(self.get_status_var('bss').values())
            logger.info (f"HostapdAdapter.update: Writing PSKs to {self.hostapd_psk_path.absolute ()} "
                         f"for BSS {bss_list}")
            outfile.write ("# THIS WPA-PSK FILE IS MANAGED BY THE MICRONETS GATEWAY SERVICE\n\n")
            outfile.write ("# MODIFICATIONS TO THIS FILE WILL BE OVER-WRITTEN\n\n")
            for micronet_id, devices in device_lists.items ():
                micronet = micronet_list.get(micronet_id)
                vlan_id = micronet.get('vlan')
                interface_id = micronet.get('interface')

                if interface_id not in bss_list:
                    logger.info(f"HostapdAdapter.update: micronet {micronet_id} interface {interface_id} "
                                f"not in BSS list {bss_list} - skipping")
                    continue

                if not vlan_id:
                    logger.info(f"HostapdAdapter.update: no VLAN for micronet {micronet_id} - skipping")
                    outfile.write(f"# No VLAN for device {micronet_id}\n\n")
                    continue

                outfile.write (f"# DEVICES FOR MICRONET {micronet_id} (interface {interface_id}, vlan {vlan_id})\n")
                outfile.write ("###############################################################\n\n")
                for device_id, device in devices.items ():
                    psk = device.get('psk')
                    mac_addr = netaddr.EUI(device ['macAddress']['eui48'])
                    mac_addr.dialect = netaddr.mac_unix_expanded
                    ip_addr = IPv4Address (device ['networkAddress']['ipv4'])
                    if not psk:
                        logger.info(f"HostapdAdapter.update: no psk for device {device_id} in micronet {micronet_id} - skipping")
                        outfile.write(f"# No PSK for device {device_id} ({mac_addr})\n\n")
                        continue
                    outfile.write(f"# DEVICE {device_id} ({ip_addr})\n")

                    if vlan_id:
                        # vlanid=202 00:c0:ca:97:6d:16 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
                        outfile.write(f"vlanid={vlan_id} {mac_addr} {psk}\n\n")
                    else:
                        outfile.write(f"{mac_addr} {psk}\n\n")

        with self.hostapd_psk_path.open('r') as infile:
            infile.line_no = 0
            logger.info ("WROTE HOSTAPD WPA-PSK FILE:")
            logger.info ("------------------------------------------------------------------------")
            for line in infile:
                logger.info (line[0:-1])
            logger.info ("------------------------------------------------------------------------")

        if self.cli_ready:
            logger.info (f"HostapdAdapter.update: Issuing PSK reload command")
            psk_reload_command = await self.send_command(HostapdAdapter.ReloadPSKCLICommand())
            if await psk_reload_command.was_successful():
                logger.info(f"HostapdAdapter.update: PSK reload successful")
            else:
                response = await psk_reload_command.get_response()
                logger.warning(f"HostapdAdapter.update: PSK reload FAILED (received '{response}')")
        else:
            logger.warning(f"HostapdAdapter.update: Could not issue PSK reload (CLI not ready)")

    async def connect(self):
        logger.info(f"HostapdAdapter:connect()")
        if self.cli_connected:
            logger.info(f"HostapdAdapter:connect: Already connected - returning")
            return
        if not self.hostapd_cli_path:
            logger.info(f"HostapdAdapter:connect: hostapd_cli_path not set - returning")
            return
        self.event_loop = asyncio.get_event_loop ()
        self.command_queue = Queue()  # https://docs.python.org/3.6/library/queue.html
        logger.info(f"HostapdAdapter:connect: Running {self.hostapd_cli_path} {self.hostapd_cli_args}")

        self.hostapd_cli_process = Popen([self.hostapd_cli_path, *self.hostapd_cli_args],
                                         shell=False, bufsize=1,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.cli_connected = True
        self.process_reader_thread = threading.Thread(target=self.read_cli_output)
        self.process_reader_thread.start()
        logger.info(f"HostapdAdapter:connect: Reader thread started")

    def is_cli_connected(self):
        return self.cli_connected

    def is_cli_ready(self):
        return self.cli_ready

    def read_cli_output(self):
        response_data = None
        self.command_queue = Queue()
        logger.info(f"HostapdAdapter:read_cli_output: Started")
        command = None
        while True:
            try:
                # https://docs.python.org/3/library/io.html

                # logger.debug(f"HostapdAdapter:read_cli_output: Waiting on stdout.readline()...")
                data = self.hostapd_cli_process.stdout.readline()
                if not data:
                    logger.info(f"HostapdAdapter:read_cli_output: Got EOF from hostapd_cli - exiting")
                    break
                line = data.decode("utf-8")
                if len(line) == 0:
                    continue
                logger.debug(f"HostapdAdapter:read_cli_output: \"{line[:-1]}\"")
                if not self.cli_ready and self.cli_ready_re.match(line):
                    logger.info(f"HostapdAdapter:read_cli_output: hostapd CLI is now READY")
                    self.cli_ready = True
                    asyncio.run_coroutine_threadsafe(self.process_hostapd_ready(), self.event_loop)
                if not command:
                    response_data = None
                    try:
                        command = self.command_queue.get(block=False)
                    except Empty:
                        command = None

                if command:
                    if response_data is None:
                        # Don't store the first line - which contains the command (start aggregating on the next line)
                        response_data = ""
                        continue
                    response_data += line
                    pos = response_data.find("> ")
                    if pos >= 0:
                        # logger.debug (f"HostapdAdapter:read_cli_output: aggregate response_data: {response_data}")
                        command_type = type(command).__name__
                        complete_response = response_data[:pos].rstrip()
                        logger.debug (f"HostapdAdapter:read_cli_output: Found command response for {command}: {complete_response}")
                        asyncio.run_coroutine_threadsafe(command.process_response_data(complete_response), 
                                                         command.event_loop)
                        response_data = None
                        command = None
                else:
                    # This is assuming avents aren't delivered while a command response is being processed
                    cli_event_match = HostapdAdapter.cli_event_re.match(line)
                    if cli_event_match:
                        event_data = cli_event_match.group(2).strip()
                        asyncio.run_coroutine_threadsafe(self.process_event(event_data), self.event_loop)
            except Exception as ex:
                logger.warning(f"HostapdAdapter:read_cli_output: Error processing data: {ex}", exc_info=True)
        self.cli_connected = False
        self.cli_ready = False

    async def process_hostapd_ready(self):
        logger.info(f"HostapdAdapter:process_hostapd_ready()")
        status_cmd = await self.send_command(HostapdAdapter.StatusCLICommand())
        logger.info (f"HostapdAdapter:process_hostapd_ready: Retrieving status...")
        self.status_vars = await status_cmd.get_status_dict()
        for handler in self.event_handler_table:
            asyncio.ensure_future(handler.handle_hostapd_ready())

    async def process_event(self, event_data):
        logger.info(f"HostapdAdapter:process_event: EVENT: (\"{event_data}\")")
        if event_data.startswith("CTRL-EVENT-TERMINATING"):
            logger.info(f"HostapdAdapter:process_event: hostapd CLI is now NOT READY")
            self.cli_ready = False
        else:
            for handler in self.event_handler_table:
                if handler.event_prefixes is None or event_data.startswith(handler.event_prefixes):
                    asyncio.ensure_future(handler.handle_hostapd_cli_event(event_data))

    def get_status_var(self, var_name):
        if not self.status_vars:
            raise Exception("The Hostapd adapter status variables aren't initialized")
        return self.status_vars.get(var_name, None)

    class HostapdCLICommand:
        def __init__ (self, event_loop = asyncio.get_event_loop()):
            self.event_loop = event_loop
            self.response_future = asyncio.Future(loop=event_loop)

        def get_command_string(self):
            """ Over-ride this method to provide the string that compromise the hostapd_cli command (without newline)"""
            pass

        async def process_response_data(self, response):
            """This is where the response can be parsed for meaningful data, parsed, and have
            memvars set to any values that want to be retained."""
            self.response_future.set_result(response)

        async def get_response(self):
            """Return the raw response data. Subclasses may provide accessors for specific data elements."""
            return await self.response_future

        def __str__(self):
            return type(self).__name__ + ": " + self.get_command_string()

    async def send_command(self, command):
        if not isinstance(command, HostapdAdapter.HostapdCLICommand):
            raise TypeError
        if not self.cli_ready:
            raise Exception("hostapd adapter CLI is not ready")
        self.command_queue.put(command)
        command_string = command.get_command_string()
        logger.info (f"HostapdAdapter:send_command: issuing command: {command} (\"{command_string}\")")
        # Put 2 newlines on the end to force a newline on the output
        command_string = command_string + "\n\n"
        self.hostapd_cli_process.stdin.write(command_string.encode())
        self.hostapd_cli_process.stdin.flush()

        return command


    class PingCLICommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)

        def get_command_string(self):
            return "ping"

    class GenericHostapdCLIMessage(HostapdCLICommand):
        def __init__ (self, hostapd_command, hostapd_command_args=(), event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.hostapd_command = hostapd_command
            self.hostapd_command_args = hostapd_command_args

        def get_command_string(self):
            if isinstance (self.hostapdcommand, bytes):
                return self.hostapdcommand
            compound_command = self.hostapdcommand
            for arg in self.hostapd_command_args:
                compound_command = " " + compound_command
            return compound_command


    class HelpCLICommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)

        def get_command_string(self):
            return "help"


    class StatusCLICommand(HostapdCLICommand):
        index_re = re.compile("^([a-zA-Z0-9]+)\[([0-9]+)\]$")
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.status_vars = {}

        def get_command_string(self):
            return "status"

        async def process_response_data(self, response):
            try:
                for line in response.splitlines():
                    try:
                        (name,val) = line.split("=")
                        if not name or not val:
                            continue
                        index_match = HostapdAdapter.StatusCLICommand.index_re.match(name)
                        if index_match:
                            name = index_match.group(1)
                            index = int(index_match.group(2))
                            if name not in self.status_vars:
                                self.status_vars[name] = {}
                            self.status_vars[name][index] = val
                        else:
                            self.status_vars[name] = val
                        logger.debug(f"StatusCLICommand.process_response_data: {name} = \"{self.status_vars[name]}\"")
                    except Exception as ex:
                        logger.warning(f"StatusCLICommand.process_response_data: Error processing status line {line}: {ex}", exc_info=True)
            finally:
                await super().process_response_data(response)

        async def get_status_dict(self):
            await self.get_response()
            return self.status_vars

        async def get_status_var(self, name):
            await self.get_response()
            return self.status_vars.get(name)

    class ListStationsCLICommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.sta_macs = []

        def get_command_string(self):
            return "list_sta"

        async def process_response_data(self, response):
            self.sta_macs = response.splitlines()
            await super().process_response_data(response)

        async def get_sta_macs(self):
            await self.get_response()
            return self.sta_macs

    class SetCLICommand(HostapdCLICommand):
        def __init__ (self, setting_name, setting_value, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.setting_name = setting_name
            self.setting_value = setting_value
            self.success = False

        def get_command_string(self):
            return f"set {self.setting_name} {self.setting_value}"

        async def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                await super().process_response_data(response)

        async def was_successful(self):
            await self.get_response()
            return self.success

    class DPPAddConfiguratorCLICommand(HostapdCLICommand):
        def __init__ (self, curve=None, key=None, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.curve = curve
            self.key = key
            self.configurator_id = None
            self.success = False

        def get_command_string(self):
            cmd_string = "dpp_configurator_add"
            if self.curve:
                cmd_string += f" curve={self.curve}"
            if self.key:
                cmd_string += f" key={self.key}"
            return cmd_string

        async def process_response_data(self, response):
            try:
                self.configurator_id = int(response)
                self.success = True
            except Exception as ex:
                # If the response isn't an integer, the command failed
                self.success = False
            finally:
                await super().process_response_data(response)

        async def get_configurator_id(self):
            response = await self.get_response()
            if not self.success:
                raise Exception(f"Unexpected response: ({response})")
            return self.configurator_id

    class DPPAddQRCodeCLICommand(HostapdCLICommand):
        def __init__ (self, qrcode, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.qrcode = qrcode
            self.qrcode_id = None
            self.success = False

        def get_command_string(self):
            return f"dpp_qr_code {self.qrcode}"

        async def process_response_data(self, response):
            try:
                self.qrcode_id = int(response)
                self.success = True
            except Exception as ex:
                self.success = False
            finally:
                await super().process_response_data(response)

        def get_qrcode(self):
            return self.qrcode

        async def get_qrcode_id(self):
            response = await self.get_response()
            if not self.success:
                raise Exception(f"Unexpected response: ({response})")
            return self.qrcode_id

        async def was_successful(self):
            await self.get_response()
            return self.success

    class DPPAuthInitCommand(HostapdCLICommand):
        def __init__ (self, configurator_id, qrcode_id, ssid, akms, psk=None, passphrase=None, freq=None,
                      event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.configurator_id = configurator_id
            self.qrcode_id = qrcode_id
            self.ssid = ssid
            self.psk = psk
            self.passphrase = passphrase
            self.akms = akms
            self.freq = freq
            self.success = False
            self.passphrase_asciihex = None
            if self.passphrase:
                self.passphrase_asciihex = self.passphrase.encode("ascii").hex()

        def get_command_string(self):
            ssid_asciihex = self.ssid.encode("ascii").hex()
            cmd = f"dpp_auth_init peer={self.qrcode_id} ssid={ssid_asciihex} configurator={self.configurator_id}"

            # Currently allowed configs: psk, sae, dpp, psk+sae, dpp+sae, dpp+psk+sae
            # (see dpp_configuration_alloc in src/common/dpp.c of hostap sources)
            akm_str = ""
            if 'dpp' in self.akms:
                akm_str += "+dpp"
            if 'psk' in self.akms:
                if not (self.psk or self.passphrase):
                    raise Exception(f"'psk' included in AKMS but no PSK or passphrase provided")
                akm_str += "+psk"
            if 'sae' in self.akms:
                if not self.passphrase:
                    raise Exception(f"'sae' included in AKMS but no passphrase provided")
                akm_str += "+sae"
            if len(akm_str) == 0:
                raise Exception(f"No valid akms elements found (akms: {self.akms})")
            # Note: akm_str will have an extra "+" at the front
            cmd += f" conf=sta-{akm_str[1:]}"

            if self.psk:
                cmd += f" psk={self.psk}"
            if self.passphrase_asciihex:
                cmd += f" pass={self.passphrase_asciihex}"
            if self.freq:
                cmd += f" neg_freq={self.freq}"

            return cmd

        async def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                await super().process_response_data(response)

        async def was_successful(self):
            await self.get_response()
            return self.success

    class ReloadPSKCLICommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.success = False

        def get_command_string(self):
            return "reload_wpa_psk"

        async def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                await super().process_response_data(response)

        async def was_successful(self):
            await self.get_response()
            return self.success

    class DPPConfiguratorDPPSignCLICommand(HostapdCLICommand):
        def __init__ (self, configurator_id, ssid, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.configurator_id = configurator_id
            self.ssid = ssid
            self.success = False
            self.c_sign_key = None
            self.net_access_key = None
            self.dpp_connector = None

        def get_command_string(self):
            ssid_asciihex = self.ssid.encode("ascii").hex()
            return f"dpp_configurator_sign conf=ap-dpp ssid={ssid_asciihex} configurator={self.configurator_id}"

        sign_response_re = re.compile("^<3>([-A-Z0-9]+)(?: (.+))?$")

        async def process_response_data(self, response):
            try:
                for line in response.splitlines():
                    # TODO: REMOVE ME
                    logger.info(f"DPPConfiguratorDPPSignCLICommand.process_response_data: Looking at line: {line}")
                    try:
                        if line == "OK":
                            self.success = self.c_sign_key and self.net_access_key and self.dpp_connector
                            continue
                        sign_response_elem = HostapdAdapter.DPPConfiguratorDPPSignCLICommand.sign_response_re.match(line)
                        if sign_response_elem:
                            (param_name, param_val) = sign_response_elem.groups()
                            if param_name == "DPP-CONNECTOR":
                                self.dpp_connector = param_val
                            elif param_name == "DPP-C-SIGN-KEY":
                                self.c_sign_key = param_val
                            elif param_name == "DPP-NET-ACCESS-KEY":
                                self.net_access_key = param_val
                            else:
                                pass
                    except Exception as ex:
                        logger.warning(f"DPPConfiguratorDPPSignCLICommand.process_response_data: Error processing status line {line}: {ex}",
                                       exc_info=True)
            finally:
                await super().process_response_data(response)

        async def get_connector(self):
            response = await self.get_response()
            if not self.success:
                raise Exception(f"Unexpected response: ({response})")
            return self.dpp_connector

        async def get_c_sign_key(self):
            response = await self.get_response()
            if not self.success:
                raise Exception(f"Unexpected response: ({response})")
            return self.c_sign_key

        async def get_net_access_key(self):
            response = await self.get_response()
            if not self.success:
                raise Exception(f"Unexpected response: ({response})")
            return self.net_access_key

        async def was_successful(self):
            await self.get_response()
            return self.success

async def run_tests():
    hostapd_adapter = HostapdAdapter(None, "/opt/micronets-hostapd/bin/hostapd_cli", [])

    await hostapd_adapter.connect()
    logger.info (f"{__name__}: Connected.")

    # await asyncio.sleep(2)
    # logger.info (f"{__name__}: Issuing help command...")
    # help_cmd = await hostapd_adapter.send_command(HelpCLICommand())
    # response = await help_cmd.get_response()
    # logger.info (f"{__name__}: Help command response: {response}")

    await asyncio.sleep(2)
    logger.info (f"{__name__}: Issuing ping command...")
    ping_cmd = await hostapd_adapter.send_command(HostapdAdapter.PingCLICommand())
    response = await ping_cmd.get_response()
    logger.info (f"{__name__}: Ping response: {response}")

    await asyncio.sleep(2)
    logger.info (f"{__name__}: Issuing List Stations command...")
    list_sta_cmd = await hostapd_adapter.send_command(HostapdAdapter.ListStationsCLICommand())
    stas = await list_sta_cmd.get_sta_macs()
    logger.info (f"{__name__}: Station List: {stas}")

    await asyncio.sleep(2)
    logger.info (f"{__name__}: Issuing Status command...")
    status_cmd = await hostapd_adapter.send_command(HostapdAdapter.StatusCLICommand())
    # logger.info (f"{__name__}: Retrieving status dict...")
    # status_dict = await status_cmd.get_status_dict()
    # logger.info (f"{__name__}: Status dict: {status_dict}")
    logger.info (f"{__name__}: Retrieving ssid...")
    ssid = await status_cmd.get_status_var("ssid")
    logger.info (f"{__name__}: SSID: {ssid[0]}")

    await asyncio.sleep(2)
    logger.info (f"{__name__}: Issuing a flood of pings...")
    for x in range(1,10):
        logger.info (f"{__name__}: Issuing ping command #{x}...")
        ping_cmd = await hostapd_adapter.send_command(HostapdAdapter.PingCLICommand())
        response = await ping_cmd.get_response()
        logger.info (f"{__name__}: Ping response: {response}")
    logger.info (f"{__name__}: Tests complete.")


async def run_dpp_tests():
    # await asyncio.sleep(2)
    qrcode = "DPP:C:81/1;M:2c:d0:5a:6e:ca:3c;I:KYZRQ;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAC/nFQKV1+CErzr6QCUT0jFIno3CaTRr3BW2n0ThU4mAw=;;"
    logger.info (f"{__name__}: Issuing DPP Add QRCode command...")
    logger.info (f"{__name__}:   Code: {qrcode}")
    add_config_id_cmd = await hostapd_adapter.send_command(HostapdAdapter.DPPAddQRCodeCLICommand(qrcode))
    qrcode_id = await add_config_id_cmd.get_qrcode_id()
    logger.info (f"{__name__}: DPP QRCode ID: {qrcode_id}")

    # await asyncio.sleep(2)
    logger.info (f"{__name__}: Issuing DPP Auth Init command...")
    ssid="756e636c652d6a6f686e"
    psk="0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    logger.info (f"{__name__}:   SSID: {ssid}")
    logger.info (f"{__name__}:   PSK: {psk}")
    dpp_auth_init_cmd = await hostapd_adapter.send_command(HostapdAdapter.DPPAuthInitPSKCommand(configurator_id, qrcode_id, ssid, psk))
    result = await dpp_auth_init_cmd.get_response()
    logger.info (f"{__name__}: Auth Init result: {result}")

async def run_dpp_akm_tests():
    logger.info (f"{__name__}: Running dpp akm tests...")
    hostapd_adapter = HostapdAdapter(None, "/opt/micronets-hostapd/bin/hostapd_cli", [])
    await hostapd_adapter.connect()
    logger.info (f"{__name__}: CLI Connected.")

    await asyncio.sleep(2)

    status_cmd = await hostapd_adapter.send_command(HostapdAdapter.StatusCLICommand())
    logger.info (f"{__name__}: Retrieving ssid...")
    ssid_list = await status_cmd.get_status_var("ssid")
    ssid = ssid_list[0]
    logger.info(f"{__name__}: SSID: {ssid}")

    add_configurator_cmd = HostapdAdapter.DPPAddConfiguratorCLICommand(curve="prime256v1")
    await hostapd_adapter.send_command(add_configurator_cmd)
    dpp_configurator_id = await add_configurator_cmd.get_configurator_id()
    logger.info (f"{__name__}: Configurator ID: {dpp_configurator_id}")

    logger.info (f"{__name__}: Creating a DPP Connector for the AP")
    dpp_config_sign_cmd = HostapdAdapter.DPPConfiguratorDPPSignCLICommand(dpp_configurator_id, ssid)
    await hostapd_adapter.send_command(dpp_config_sign_cmd)
    dpp_connector = await dpp_config_sign_cmd.get_connector()
    logger.info (f"{__name__}:   Connector: {dpp_connector}")
    dpp_c_sign_key = await dpp_config_sign_cmd.get_c_sign_key()
    logger.info (f"{__name__}:   DPP c-sign-key: {dpp_c_sign_key}")
    dpp_net_access_key = await dpp_config_sign_cmd.get_net_access_key()
    logger.info (f"{__name__}:   Net access key: {dpp_net_access_key}")
    
    await hostapd_adapter.send_command(HostapdAdapter.SetCLICommand("dpp_connector", dpp_connector))
    await hostapd_adapter.send_command(HostapdAdapter.SetCLICommand("dpp_csign", dpp_c_sign_key))
    await hostapd_adapter.send_command(HostapdAdapter.SetCLICommand("dpp_netaccesskey", dpp_net_access_key))

if __name__ == '__main__':
    print (f"{__name__}: Starting\n")
    logging.basicConfig(level="DEBUG")
    logger = logging.getLogger ('hostapd_adapter')
    logger.info (f"{__name__}: Running hostapd_adapter tests")
    logger.info (f"{__name__}: Locale: {locale.getpreferredencoding(False)}")

    event_loop = asyncio.get_event_loop ()
    try:
        logger.info (f"{__name__}: Starting event loop...")
        event_loop.run_until_complete(run_dpp_akm_tests())
        event_loop.run_forever()
        logger.info (f"{__name__}: Event loop exited")
    except Exception as Ex:
        logger.warn (f"Caught an exception: {Ex}")
        traceback.print_exc()


