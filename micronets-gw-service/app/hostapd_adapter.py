import asyncio
import logging
import locale
import os
import traceback
import re
from asyncio import CancelledError

import netaddr
import socket
from queue import Queue, Empty
from ipaddress import IPv4Network, IPv4Address
from pathlib import Path

logger = logging.getLogger ('hostapd_adapter')


class HostapdAdapter:

    cli_event_re = re.compile ('^<([0-9]+)>(.+)$')

    def __init__ (self, hostapd_psk_path, hostapd_cli_path):
        self.event_loop = None
        self.event_handler_table = []
        self.hostapd_psk_path = Path(hostapd_psk_path) if hostapd_psk_path else None
        self.hostapd_cli_path = Path(hostapd_cli_path) if hostapd_cli_path else None
        self.hostapd_socket = None
        self.hostapd_reader_ready = None
        self.hostapd_control_connect_retry_s = 10
        self.hostapd_max_response = 4096
        self.hostapd_read_timeout_s = 5
        self.hostapd_ping_task = None
        self.hostapd_ping_interval_s = 10
        self.command_queue = None
        self.cli_connected = False
        self.cli_ready = False
        self.status_vars = None
        self.local_sock = f'/tmp/mn-wpactrl-{os.getpid()}'
        self.log_exception_backtraces = False

    class HostapdCLIEventHandler:
        def __init__ (self, event_prefixes):
            self.hostapd_adapter = None
            self.event_prefixes = event_prefixes

        async def handle_hostapd_ready(self):
            # Called when the connection to hostapd is made ready
            pass

        async def handle_hostapd_cli_event(self, event):
            # Called when a hostapd event is received
            pass

        async def handle_hostapd_status_var_change(self):
            # Called when a change to a status var is pushed to hostapd
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
            logger.info (f"HostapdAdapter.update: Writing PSKs to {self.hostapd_psk_path.absolute()}")
            outfile.write ("# THIS WPA-PSK FILE IS MANAGED BY THE MICRONETS GATEWAY SERVICE\n\n")
            outfile.write ("# MODIFICATIONS TO THIS FILE WILL BE OVER-WRITTEN\n\n")
            for micronet_id, devices in device_lists.items ():
                micronet = micronet_list.get(micronet_id)
                vlan_id = micronet.get('vlan')
                interface_id = micronet.get('interface')
                micronet_name = micronet.get('name')

                if not vlan_id:
                    logger.info(f"HostapdAdapter.update: no VLAN for micronet {micronet_id}/\"{micronet_name}\" - skipping")
                    outfile.write(f"# No VLAN for device {micronet_id}\n\n")
                    continue

                outfile.write (f"# DEVICES FOR MICRONET {micronet_id}/\"{micronet_name}\" (interface {interface_id}, vlan {vlan_id})\n")
                outfile.write ("###############################################################\n\n")
                for device_id, device in devices.items ():
                    mac_addr_str = device.get('macAddress')
                    if not mac_addr_str:
                        continue
                    mac_addr = netaddr.EUI(mac_addr_str)
                    mac_addr.dialect = netaddr.mac_unix_expanded
                    psk = device.get('psk')
                    device_name = device.get('name')
                    ip_addr = IPv4Address (device ['networkAddress']['ipv4'])
                    if not psk:
                        logger.info(f"HostapdAdapter.update: no psk for device {device_id}/\"{device_name}\" in micronet {micronet_id} - skipping")
                        outfile.write(f"# No PSK for device {device_id}/\"{device_name}\" ({mac_addr})\n\n")
                        continue
                    outfile.write(f"# DEVICE {device_id}/\"{device_name}\" ({ip_addr})\n")

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
        self.event_loop = asyncio.get_event_loop()
        if self.cli_connected:
            logger.info(f"HostapdAdapter:_connect_retry: Already connected - returning")
            return
        if not self.hostapd_cli_path:
            logger.info(f"HostapdAdapter:_connect_retry: hostapd_cli_path not set - returning")
            return

        self.hostapd_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.hostapd_socket.bind(self.local_sock)
        asyncio.create_task(self._connect_retry())

    async def _connect_retry(self):
        logger.info(f"HostapdAdapter:_connect_retry()")
        self.command_queue = Queue()  # https://docs.python.org/3.6/library/queue.html

        self.hostapd_read_task = None
        while True:
            try:
                logger.info(f"HostapdAdapter:connect: Connecting control socket to {self.hostapd_cli_path}...")
                # self.hostapd_socket.settimeout(self.hostapd_read_timeout_s)
                self.hostapd_socket.setblocking(False)
                self.hostapd_socket.connect(str(self.hostapd_cli_path))
                logger.info(f"HostapdAdapter:connect: Connected control socket to {self.hostapd_cli_path}")
                self.command_queue = Queue()
                self.hostapd_reader_ready = asyncio.Future(loop=self.event_loop)
                self.hostapd_read_task = asyncio.create_task(self._read_cli_output())
                await self.hostapd_reader_ready
                logger.info(f"HostapdAdapter:connect: Control interface reader task started and ready")
                self.cli_ready = True
                enable_command = await self.send_command(self.EnableEventsCommand())
                enable_success = await enable_command.get_response()
                if not enable_success:
                    logger.warning(f"FAILED to enable hostapd control events "
                                   f"({self.EnableEventsCommand.get_command_string()} failed)")
                self.hostapd_ping_task = asyncio.create_task(self._hostapd_ping_loop())
                await self.hostapd_read_task
                logger.info(f"HostapdAdapter:connect: Control interface read task exited.")
            except Exception as ex:
                self.cli_ready = False
                self.cli_connected = False
                if self.hostapd_read_task:
                    self.hostapd_read_task.cancel()
                    self.hostapd_read_task = None
                if self.hostapd_ping_task:
                    self.hostapd_ping_task.cancel()
                    self.hostapd_ping_task = None
                logger.info(f"HostapdAdapter:connect: Could not connect to hostapd control socket "
                            f"{self.hostapd_cli_path}: {ex}", exc_info=self.log_exception_backtraces)
                await asyncio.sleep(self.hostapd_control_connect_retry_s)

    async def _hostapd_ping_loop(self):
        try:
            while True:
                logger.info(f"HostapdAdapter: _hostapd_ping_loop: Issuing PING on command channel...")
                ping_command = await self.send_command(self.PingCLICommand())
                ping_result = await ping_command.get_response()
                logger.debug(f"HostapdAdapter: _hostapd_ping_loop: PING response: {ping_result}")
                if not ping_result:
                    logger.info(f"HostapdAdapter: _hostapd_ping_loop: PING command FAILED - exiting")
                    break
                await asyncio.sleep(self.hostapd_ping_interval_s)
        except Exception as ex:
            logger.info(f"HostapdAdapter: _hostapd_ping_loop: Caught exception during PING - exiting")

    def is_cli_connected(self):
        return self.cli_connected

    def is_cli_ready(self):
        return self.cli_ready

    async def _read_cli_output(self):
        response_data = None
        self.cli_ready = True
        logger.info(f"HostapdAdapter:read_cli_output: Started")
        command = None
        self.hostapd_reader_ready.set_result(True)
        while True:
            try:
                logger.debug(f"HostapdAdapter:read_cli_output: Waiting for data on {str(self.hostapd_cli_path)}...")
                data = await self.event_loop.sock_recv(self.hostapd_socket, self.hostapd_max_response)
                if not data:
                    logger.info(f"HostapdAdapter:read_cli_output: Got EOF from hostapd_cli - exiting read loop")
                    break
                response = data.decode("utf-8")
                if len(response) == 0:
                    continue
                logger.debug(f"HostapdAdapter:read_cli_output: \"{response[:-1]}\"")
                event_match = HostapdAdapter.cli_event_re.match(response)
                if event_match:
                    interface_index = int(event_match.group(1))
                    event_data = event_match.group(2).strip()
                    logger.debug(f"HostapdAdapter:read_cli_output: Found event on interface {interface_index}: {event_data}")
                    asyncio.create_task(self._process_hostapd_event(interface_index, event_data))
                    continue
                if not command:
                    try:
                        command = self.command_queue.get(block=False)
                    except Empty:
                        command = None
                if command:
                    logger.debug (f"HostapdAdapter:read_cli_output: Found command response for {command}: {response}")
                    done = command.process_response_data(response)
                    if done:
                        command = None
                    else:
                        logger.debug(f"HostapdAdapter:read_cli_output: Continuing multi-response command: {command}")
            except socket.timeout as to:
                logger.debug("HostapdAdapter:read_cli_output: Read timeout. Continuing...")
            except CancelledError as ce:
                logger.info("HostapdAdapter:read_cli_output: Socket read was cancelled - exiting")
                break
            except Exception as ex:
                logger.warning(f"HostapdAdapter:read_cli_output: Error processing data: {ex.__class__} - {ex}",
                               exc_info=self.log_exception_backtraces)
        self.command_queue = None
        self.cli_connected = False
        self.cli_ready = False

    async def _process_hostapd_ready(self):
        logger.info(f"HostapdAdapter:process_hostapd_ready()")
        await self._refresh_status_vars()
        for handler in self.event_handler_table:
            asyncio.ensure_future(handler.handle_hostapd_ready())

    async def _process_status_var_change(self):
        logger.info(f"HostapdAdapter:process_status_var_change()")
        for handler in self.event_handler_table:
            asyncio.ensure_future(handler.handle_hostapd_status_var_change())

    async def _process_hostapd_event(self, interface_index, event_data):
        logger.info(f"HostapdAdapter:process_event:")
        logger.info(f"HostapdAdapter:process_event: INTERFACE {interface_index} EVENT: (\"{event_data}\")")
        if event_data.startswith("CTRL-EVENT-TERMINATING"):
            logger.info(f"HostapdAdapter:process_event: hostapd CLI is now NOT READY")
            self.cli_ready = False
            self.hostapd_read_task.cancel()
        else:
            for handler in self.event_handler_table:
                if handler.event_prefixes is None or event_data.startswith(handler.event_prefixes):
                    asyncio.ensure_future(handler.handle_hostapd_cli_event(event_data))

    async def refresh_status_vars(self):
        logger.info(f"HostapdAdapter:refresh_status_vars()")
        await self._refresh_status_vars()
        await self._process_status_var_change()

    async def _refresh_status_vars(self):
        status_cmd = await self.send_command(HostapdAdapter.StatusCLICommand())
        self.status_vars = await status_cmd.get_status_dict()

    def get_status_var(self, var_name):
        if not self.status_vars:
            raise Exception("The Hostapd adapter status variables aren't initialized")
        return self.status_vars.get(var_name, None)

    class HostapdCLICommand:
        def __init__(self, host_adapter, event_loop = asyncio.get_event_loop()):
            self.event_loop = event_loop
            self.response_future = asyncio.Future(loop=event_loop)

        def get_command_string(self):
            """ Over-ride this method to provide the string that compromise the hostapd_cli command (without newline)"""
            pass

        async def run_command(self, hostapd_adapter):
            """ Run the command. For simple commands, the base class will use get_command_string() to determine
            the command to execute. For multi-part commands, this method can be over-ridden to perform multi-part
            commands. """
            command_string = self.get_command_string()
            logger.info(f"HostapdCLICommand:run_command: issuing command: {command_string}")
            hostapd_adapter.hostapd_socket.send(command_string.encode())

        def process_response_data(self, response):
            """This is where the response can be parsed for meaningful data, parsed, and have
            memvars set to any values that want to be retained."""
            self.response_future.set_result(response)
            return True

        async def get_response(self):
            """Return the raw response data. Subclasses may provide accessors for specific data elements."""
            return await self.response_future

        def __str__(self):
            return type(self).__name__ + ": " + self.get_command_string()

    async def send_command(self, command):
        if not isinstance(command, HostapdAdapter.HostapdCLICommand):
            raise TypeError
        self.command_queue.put(command)
        await command.run_command(self)
        return command

    class PingCLICommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.success = False

        def get_command_string(self):
            return "PING"

        def process_response_data(self, response):
            try:
                self.success = "PONG" in response
            finally:
                return super().process_response_data(response)

    class GenericHostapdCLIMessage(HostapdCLICommand):
        def __init__ (self, hostapd_command, hostapd_command_args=(), event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.hostapd_command = hostapd_command.upper()
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
            return "HELP"

    class EnableEventsCommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.success = False

        def get_command_string(self):
            return "ATTACH"

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

    class DisableEventsCommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)

        def get_command_string(self):
            return "DETACH"

    class StatusCLICommand(HostapdCLICommand):

        index_re = re.compile("^([a-zA-Z0-9]+)\[([0-9]+)\]$")

        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.status_vars = {}

        def get_command_string(self):
            return "STATUS"

        def process_response_data(self, response):
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
                        logger.warning(f"StatusCLICommand.process_response_data: Error processing status line {line}: {ex}",
                                       exc_info=self.log_exception_backtraces)
            finally:
                return super().process_response_data(response)

        async def get_status_dict(self):
            await self.get_response()
            return self.status_vars

        async def get_status_var(self, name):
            await self.get_response()
            return self.status_vars.get(name)

    class TrackStationsCLICommand(HostapdCLICommand):

        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            # Will be a dict indexed on MAC address with a duple (age(int), db(int))
            self.sta_stats = {}

        def get_command_string(self):
            return "TRACK_STA_LIST"

        def process_response_data(self, response):
            # Example output:
            # e4:f0:42:43:d8:5f 1 -88
            # ac:d5:64:20:eb:76 7 -92
            # 48:d6:d5:53:dc:3a 16 -44
            # 00:c0:ca:97:d9:b1 18 -33
            try:
                self.sta_stats = {}
                for line in response.splitlines():
                    try:
                        (mac,age,db) = line.split(" ")
                        if not mac or not age or not db:
                            continue
                        self.sta_stats[mac] = (int(age), int(db))
                        logger.debug(f"TrackStationsCLICommand.process_response_data: {mac} = \"{self.sta_stats[mac]}\"")
                    except Exception as ex:
                        logger.info(f"TrackStationsCLICommand.process_response_data: Error processing station stats line "
                                    f"{line}: {ex}", exc_info=self.log_exception_backtraces)
            finally:
                return super().process_response_data(response)

        async def get_sta_stats(self):
            await self.get_response()
            return self.sta_stats

    class ListStationsCLICommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.sta_macs = []

        # TODO: This will need to be changed to a macro to use STA-FIRST/STA-NEXT %s
        def get_command_string(self):
            return "LIST_STA"

        def process_response_data(self, response):
            self.sta_macs = response.splitlines()
            # TODO: Return False until the last STA is processed
            return super().process_response_data(response)

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
            return f"SET {self.setting_name} {self.setting_value}"

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

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
            cmd_string = "DPP_CONFIGURATOR_ADD"
            if self.curve:
                cmd_string += f" curve={self.curve}"
            if self.key:
                cmd_string += f" key={self.key}"
            return cmd_string

        def process_response_data(self, response):
            try:
                self.configurator_id = int(response)
                self.success = True
            except Exception as ex:
                # If the response isn't an integer, the command failed
                self.success = False
            finally:
                return super().process_response_data(response)

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
            return f"DPP_QR_CODE {self.qrcode}"

        def process_response_data(self, response):
            try:
                self.qrcode_id = int(response)
                self.success = True
            except Exception as ex:
                self.success = False
            finally:
                return super().process_response_data(response)

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

    class DPPBootstrapUriDeleteCommand(HostapdCLICommand):
        def __init__ (self, qrcode_id=None, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.qrcode_id = qrcode_id

        def get_command_string(self):
            cmd = f"DPP_BOOTSTRAP_REMOVE {self.qrcode_id if self.qrcode_id else '*'}"
            return cmd

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

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
            cmd = f"DPP_AUTH_INIT peer={self.qrcode_id} ssid={ssid_asciihex} configurator={self.configurator_id}"

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

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

        async def was_successful(self):
            await self.get_response()
            return self.success

    class DPPBootstrapSet(HostapdCLICommand):
        def __init__ (self, configurator_id, qrcode_id, ssid, akms, psk=None, passphrase=None,
                      event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.configurator_id = configurator_id
            self.qrcode_id = qrcode_id
            self.ssid = ssid
            self.psk = psk
            self.passphrase = passphrase
            self.akms = akms
            self.success = False
            self.passphrase_asciihex = None

        def get_command_string(self):
            ssid_asciihex = self.ssid.encode("ascii").hex()

            # dpp_bootstrap_set 1 conf=sta-psk ssid=<enc ssid> psk=<64 hex chars) configurator=1 conn_status=0 group_id=micronet-01
            cmd = f"DPP_BOOTSTRAP_SET {self.qrcode_id} ssid={ssid_asciihex} configurator={self.configurator_id}"

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
            if self.passphrase:
                passphrase_asciihex = self.passphrase.encode("ascii").hex()
                cmd += f" pass={passphrase_asciihex}"
            return cmd

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

        async def was_successful(self):
            await self.get_response()
            return self.success

        def __str__(self):
            return type(self).__name__ + ": " + self.get_command_string() + f" (SSID {self.ssid})"

    class DPPSetDPPConfigParamsCommand(HostapdCLICommand):
        def __init__ (self, configurator_id, ssid, akms, psk=None, passphrase=None,
                      event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.configurator_id = configurator_id
            self.ssid = ssid
            self.psk = psk
            self.passphrase = passphrase
            self.akms = akms
            self.success = False

        def get_command_string(self):
            ssid_asciihex = self.ssid.encode("ascii").hex()
            # set dpp_configurator_params "conf=sta-psk ssid=<encoded-ssid> pass=<hex-encoded pass> conn_status=0 group_id=micronet-01"
            cmd = f"SET dpp_configurator_params \"conn_status=0 ssid={ssid_asciihex}"

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
            if self.passphrase:
                passphrase_asciihex = self.passphrase.encode("ascii").hex()
                cmd += f" pass={passphrase_asciihex}"
            cmd += '"'
            return cmd

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

        async def was_successful(self):
            await self.get_response()
            return self.success

    class ReloadCLICommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.success = False

        def get_command_string(self):
            return "RELOAD"

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

        async def was_successful(self):
            await self.get_response()
            return self.success

    class ReloadPSKCLICommand(HostapdCLICommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.success = False

        def get_command_string(self):
            return "RELOAD_WPA_PSK"

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

        async def was_successful(self):
            await self.get_response()
            return self.success

    class DPPConfiguratorDPPSignCLICommand(HostapdCLICommand):
        def __init__ (self, configurator_id, ssid=None, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.configurator_id = configurator_id
            self.ssid = ssid
            self.success = False
            self.c_sign_key = None
            self.net_access_key = None
            self.dpp_connector = None

        def get_command_string(self):
            cmd = f"DPP_CONFIGURATOR_SIGN conf=ap-dpp configurator={self.configurator_id}"
            if self.ssid:
                ssid_asciihex = self.ssid.encode("ascii").hex()
                cmd += " ssid=" + ssid_asciihex
            return cmd

        sign_response_re = re.compile("^<3>([-A-Z0-9]+)(?: (.+))?$")

        def process_response_data(self, response):
            try:
                self.success = "OK" in response
            finally:
                return super().process_response_data(response)

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


