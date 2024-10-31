import asyncio
import logging
import locale
import os
import traceback
import re
import pprint
from asyncio import CancelledError

import netaddr
import socket
from queue import Queue, Empty
from ipaddress import IPv4Network, IPv4Address
from pathlib import Path

logger = logging.getLogger ('hostapd_adapter')


class HostapdAdapter:
    hostapd_event_re = re.compile ('^<([0-9]+)>(.+)$')

    def __init__ (self, hostapd_psk_path, hostapd_ctrl_path):
        self.event_loop = None
        self.event_handler_table = []
        self.hostapd_psk_path = Path(hostapd_psk_path) if hostapd_psk_path else None
        self.hostapd_ctrl_path = Path(hostapd_ctrl_path) if hostapd_ctrl_path else None
        self.hostapd_socket = None
        self.hostapd_reader_ready = None
        self.hostapd_control_connect_retry_s = 10
        self.hostapd_max_response = 4096
        self.hostapd_read_timeout_s = 5
        self.hostapd_ping_task = None
        self.hostapd_ping_interval_s = 10
        self.cur_command = None
        self.command_queue = Queue()
        self.ctrl_connected = False
        self.ctrl_ready = False
        self.status_vars = None
        self.local_sock = f'/tmp/mn-wpactrl-{os.getpid()}'
        self.log_exception_backtraces = False

    class HostapdEventHandler:
        def __init__ (self, event_prefixes):
            self.hostapd_adapter = None
            self.event_prefixes = event_prefixes

        async def handle_hostapd_ready(self):
            # Called when the connection to hostapd is made ready
            pass

        async def handle_hostapd_not_ready(self):
            # Called when the connection to hostapd is made ready
            pass

        async def handle_hostapd_event(self, event):
            # Called when a hostapd event is received
            pass

        async def handle_hostapd_status_var_change(self):
            # Called when a change to a status var is pushed to hostapd
            pass

    def register_event_handler(self, handler):
        logger.info (f"HostapdAdapter: Registering event handler: {handler}")
        self.event_handler_table.append(handler)
        handler.hostapd_adapter = self

    def unregister_event_handler(self, handler):
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

        if self.ctrl_ready:
            logger.info (f"HostapdAdapter.update: Issuing PSK reload command")
            psk_reload_command = await self.send_command(HostapdAdapter.ReloadPSKCommand())
            if await psk_reload_command.was_successful():
                logger.info(f"HostapdAdapter.update: PSK reload successful")
            else:
                response = await psk_reload_command.get_response()
                logger.warning(f"HostapdAdapter.update: PSK reload FAILED (received '{response}')")
        else:
            logger.warning(f"HostapdAdapter.update: Could not issue PSK reload (Control channel NOT READY)")

    async def connect(self):
        logger.info(f"HostapdAdapter:connect()")
        self.event_loop = asyncio.get_event_loop()
        if self.ctrl_connected:
            logger.info(f"HostapdAdapter:_connect_retry: Already connected - returning")
            return
        if not self.hostapd_ctrl_path:
            logger.info(f"HostapdAdapter:_connect_retry: hostapd_ctrl_path not set - returning")
            return

        self.hostapd_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.hostapd_socket.bind(self.local_sock)
        asyncio.create_task(self._connect_retry())

    async def _connect_retry(self):
        logger.info(f"HostapdAdapter:_connect_retry()")
        self.hostapd_read_task = None
        while True:
            try:
                logger.info(f"HostapdAdapter:connect: Connecting control socket to {self.hostapd_ctrl_path}...")
                # self.hostapd_socket.settimeout(self.hostapd_read_timeout_s)
                self.hostapd_socket.setblocking(False)
                self.hostapd_socket.connect(str(self.hostapd_ctrl_path))
                logger.info(f"HostapdAdapter:connect: Connected control socket to {self.hostapd_ctrl_path}")
                self.hostapd_reader_ready = asyncio.Future(loop=self.event_loop)
                self.hostapd_read_task = asyncio.create_task(self._read_ctrl_output())
                await self.hostapd_reader_ready

                logger.info(f"HostapdAdapter:connect: Control interface reader task started and READY")
                self.ctrl_ready = True
                enable_command = await self.send_command(self.EnableEventsCommand())
                enable_result = await enable_command.get_response()
                if not enable_result:
                    logger.warning(f"HostapdAdapter:connect: FAILED to enable hostapd control events "
                                   f"({self.EnableEventsCommand.get_command_string()} command failed)")
                await self._refresh_status_vars()
                self.hostapd_ping_task = asyncio.create_task(self._hostapd_ping_loop())

                await self._process_hostapd_ready()
                logger.info(f"HostapdAdapter:connect: Waiting for control interface read task to exit.")

                await self.hostapd_read_task
                logger.info(f"HostapdAdapter:connect: Control interface read task EXITED.")

                await self._process_hostapd_not_ready()
            except Exception as ex:
                self.ctrl_ready = False
                self.ctrl_connected = False
                if self.hostapd_read_task:
                    self.hostapd_read_task.cancel()
                    self.hostapd_read_task = None
                if self.hostapd_ping_task:
                    self.hostapd_ping_task.cancel()
                    self.hostapd_ping_task = None
                logger.info(f"HostapdAdapter:connect: Error setting up hostapd control connection "
                            f"{self.hostapd_ctrl_path}: {ex}", exc_info=self.log_exception_backtraces)
            await asyncio.sleep(self.hostapd_control_connect_retry_s)

    async def _hostapd_ping_loop(self):
        try:
            while True:
                logger.info(f"HostapdAdapter: _hostapd_ping_loop: Issuing PING on command channel...")
                ping_command = await self.send_command(self.PingCommand())
                ping_result = await ping_command.get_response()
                logger.debug(f"HostapdAdapter: _hostapd_ping_loop: PING response: {ping_result}")
                if not ping_result:
                    logger.info(f"HostapdAdapter: _hostapd_ping_loop: PING command FAILED - exiting")
                    break
                await asyncio.sleep(self.hostapd_ping_interval_s)
        except Exception as ex:
            logger.info(f"HostapdAdapter: _hostapd_ping_loop: Caught exception during PING - exiting")

    def is_hostapd_connected(self):
        return self.ctrl_connected

    def is_hostapd_ready(self):
        return self.ctrl_ready

    async def _read_ctrl_output(self):
        logger.debug(f"HostapdAdapter:_read_ctrl_output())")
        self.ctrl_ready = True
        self.hostapd_reader_ready.set_result(True)

        self.cur_command = None  # Set when we're waiting for a command response
        while True:
            try:
                logger.debug(f"HostapdAdapter:_read_ctrl_output: WAITING for data on {str(self.hostapd_ctrl_path)}...")
                data = await self.event_loop.sock_recv(self.hostapd_socket, self.hostapd_max_response)
                if data is None:
                    logger.info(f"HostapdAdapter:_read_ctrl_output: Got EOF from hostapd ctrl - BREAKING read loop")
                    break
                response = data.decode("utf-8")
                logger.debug(f"HostapdAdapter:_read_ctrl_output: read {len(response)} bytes: \"{response[:-1]}\"")
                event_match = HostapdAdapter.hostapd_event_re.match(response)
                if event_match:
                    interface_index = int(event_match.group(1))
                    event_data = event_match.group(2).strip()
                    asyncio.create_task(self._process_hostapd_event(interface_index, event_data))
                    continue
                if self.cur_command:
                    logger.debug(f"HostapdAdapter:_read_ctrl_output: FOUND command response for {self.cur_command}: {response}")
                    done = self.cur_command.process_response_data(response)
                    if done:
                        logger.debug(f"HostapdAdapter:_read_ctrl_output: COMPLETED command: {self.cur_command}")
                        if self.command_queue.empty():
                            self.cur_command = None
                        else:
                            self.cur_command = self.command_queue.get(block=False)
                            command_string = self.cur_command.get_command_string()
                            await self.event_loop.sock_sendall(self.hostapd_socket, command_string.encode())
                    else:
                        logger.debug(f"HostapdAdapter:_read_ctrl_output: CONTINUING multi-response command: {self.cur_command}")
            except socket.timeout as to:
                logger.debug("HostapdAdapter:_read_ctrl_output: Read TIMEOUT. Continuing...")
            except CancelledError as ce:
                logger.info("HostapdAdapter:_read_ctrl_output: Socket read was CANCELLED - exiting")
                break
            except Exception as ex:
                logger.warning(f"HostapdAdapter:_read_ctrl_output: Error processing data: {ex.__class__} - {ex}",
                               exc_info=self.log_exception_backtraces)
        # Terminate any pending commands
        if self.cur_command:
            self.cur_command.fail("Command channel closed")
            self.cur_command = None
        while not self.command_queue.empty():
            command = self.command_queue.get()
            command.fail("Command channel closed")
        self.ctrl_connected = False
        self.ctrl_ready = False
        logger.info(f"HostapdAdapter:_read_ctrl_output: EXITING")

    async def _process_hostapd_ready(self):
        logger.info(f"HostapdAdapter:process_hostapd_ready()")
        for handler in self.event_handler_table:
            asyncio.ensure_future(handler.handle_hostapd_ready())

    async def _process_hostapd_not_ready(self):
        logger.info(f"HostapdAdapter:process_hostapd_not_ready()")
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
            logger.info(f"HostapdAdapter:process_event: hostapd control channel is NOT READY")
            self.ctrl_ready = False
            self.hostapd_read_task.cancel()
        else:
            for handler in self.event_handler_table:
                if handler.event_prefixes is None or event_data.startswith(handler.event_prefixes):
                    asyncio.ensure_future(handler.handle_hostapd_event(event_data))

    async def refresh_status_vars(self):
        logger.info(f"HostapdAdapter:refresh_status_vars()")
        await self._refresh_status_vars()
        await self._process_status_var_change()

    async def _refresh_status_vars(self):
        status_cmd = await self.send_command(HostapdAdapter.StatusCommand())
        self.status_vars = await status_cmd.get_status_dict()

    def get_status_var(self, var_name):
        if not self.status_vars:
            raise Exception("The Hostapd adapter status variables aren't initialized")
        return self.status_vars.get(var_name, None)

    indexed_value_re = re.compile("^([a-zA-Z0-9]+)\[([0-9]+)\]$")

    @staticmethod
    def _convert_namevals_into_dict(nameval_lines):
        out_dict = {}
        for line in nameval_lines.splitlines():
            try:
                (name, val) = line.split("=")
                if not name or not val:
                    continue
                index_match = HostapdAdapter.indexed_value_re.match(name)
                if index_match:
                    name = index_match.group(1)
                    index = int(index_match.group(2))
                    if name not in out_dict:
                        out_dict[name] = {}
                    out_dict[name][index] = val
                else:
                    out_dict[name] = val
                logger.debug(f"HostapdAdapter._convert_namevals_into_dict: {name} = \"{out_dict[name]}\"")
            except Exception as ex:
                logger.warning(f"HostapdAdapter._convert_namevals_into_dict: Error processing MIB line {line}: {ex}",
                               exc_info=True)
        return out_dict

    class HostapdCommand:
        def __init__(self, event_loop = asyncio.get_event_loop()):
            self.event_loop = event_loop
            self.response_future = asyncio.Future(loop=event_loop)

        def get_command_string(self):
            """ Over-ride this method to provide the string that compromise the hostapd command (without newline)"""
            return ""

        def process_response_data(self, response):
            """This is where the response can be parsed for meaningful data, parsed, and have
            memvars set to any values that want to be retained."""
            self.response_future.set_result(response)
            return True

        async def get_response(self):
            """Return the raw response data. Subclasses may provide accessors for specific data elements."""
            return await self.response_future

        def fail(self, reason):
            self.response_future.cancel()

        def __str__(self):
            return type(self).__name__ + ": " + self.get_command_string()

    # TODO: Rename to run_command()
    async def send_command(self, command):
        if not isinstance(command, HostapdAdapter.HostapdCommand):
            raise TypeError
        command_string = command.get_command_string()
        if self.cur_command:
            self.command_queue.put(command)
            logger.info(f"HostapdCommand:run_command: QUEUED command: {command_string}")
        else:
            logger.info(f"HostapdCommand:run_command: SENDING command: {command_string}")
            self.cur_command = command
            await self.event_loop.sock_sendall(self.hostapd_socket, command_string.encode())
        return command

    class PingCommand(HostapdCommand):
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

    class GenericHostapdCommand(HostapdCommand):
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

    class EnableEventsCommand(HostapdCommand):
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

    class DisableEventsCommand(HostapdCommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)

        def get_command_string(self):
            return "DETACH"

    class StatusCommand(HostapdCommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.status_vars = {}

        def get_command_string(self):
            return "STATUS"

        def process_response_data(self, response):
            self.status_vars = HostapdAdapter._convert_namevals_into_dict(response)
            return super().process_response_data(response)

        async def get_status_dict(self):
            await self.get_response()
            return self.status_vars

        async def get_status_var(self, name):
            await self.get_response()
            return self.status_vars.get(name)

    class TrackStationsCommand(HostapdCommand):
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
                        logger.debug(f"TrackStationsCommand.process_response_data: {mac} = \"{self.sta_stats[mac]}\"")
                    except Exception as ex:
                        logger.info(f"TrackStationsCommand.process_response_data: Error processing station stats line "
                                    f"{line}: {ex}", exc_info=self.log_exception_backtraces)
            finally:
                return super().process_response_data(response)

        async def get_sta_stats(self):
            await self.get_response()
            return self.sta_stats

    class SetCommand(HostapdCommand):
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

    class DPPAddConfiguratorCommand(HostapdCommand):
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

    class DPPAddQRCodeCommand(HostapdCommand):
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

    class DPPBootstrapUriDeleteCommand(HostapdCommand):
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

    class DPPAuthInitCommand(HostapdCommand):
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

    class DPPBootstrapSet(HostapdCommand):
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

    class DPPSetDPPConfigParamsCommand(HostapdCommand):
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

    class ReloadCommand(HostapdCommand):
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

    class ReloadPSKCommand(HostapdCommand):
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

    class DPPConfiguratorDPPSignCommand(HostapdCommand):
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

    class FirstStaCommand(HostapdCommand):
        def __init__ (self, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.mac_address = None
            self.response_data = None

        def get_command_string(self):
            return "STA-FIRST"

        def process_response_data(self, response):
            try:
                if len(response) < 18:
                    self.mac_address = None
                else:
                    self.mac_address = response[0:17]
                    self.response_data = response
            finally:
                return super().process_response_data(response)

        async def get_mac(self):
            await self.get_response()
            return self.mac_address

        async def get_sta_mibs(self):
            await self.get_response()
            return HostapdAdapter._convert_namevals_into_dict(self.response_data[18:])

    class NextStaCommand(HostapdCommand):
        def __init__ (self, prev_mac_address, event_loop=asyncio.get_event_loop()):
            super().__init__(event_loop)
            self.prev_mac_address = prev_mac_address
            self.mac_address = None
            self.response_data = None

        def get_command_string(self):
            return f"STA-NEXT {self.prev_mac_address}"

        def process_response_data(self, response):
            try:
                if response == "FAIL":
                    self.mac_address = None
                elif len(response) < 18:
                    self.mac_address = None
                else:
                    self.mac_address = response[0:17]
                    self.response_data = response
            finally:
                return super().process_response_data(response)

        async def get_mac(self):
            await self.get_response()
            return self.mac_address

        async def get_sta_mibs(self):
            await self.get_response()
            return HostapdAdapter._convert_namevals_into_dict(self.response_data[18:])

    async def get_connected_sta_macs(self):
        logger.debug(f"HostapdAdapter:get_connected_stas()")
        mac_list = []
        first_sta_command = await self.send_command(self.FirstStaCommand())
        mac_addr = await first_sta_command.get_mac()
        while mac_addr:
            mac_list.append(mac_addr)
            next_sta_command = await self.send_command(self.NextStaCommand(mac_addr))
            mac_addr = await next_sta_command.get_mac()
        return mac_list

    async def get_connected_sta_mibs(self):
        logger.debug(f"HostapdAdapter:get_connected_stas()")
        mac_mibs = {}
        sta_command = await self.send_command(self.FirstStaCommand())
        mac_addr = await sta_command.get_mac()
        while mac_addr:
            mac_mibs[mac_addr] = await sta_command.get_sta_mibs()
            sta_command = await self.send_command(self.NextStaCommand(mac_addr))
            mac_addr = await sta_command.get_mac()
        return mac_mibs


async def run_tests():
    hostapd_adapter = HostapdAdapter(None, '/var/run/hostapd/wlan0', [])

    await hostapd_adapter.connect()
    logger.info (f"{__name__}: Connected.")

    # await asyncio.sleep(2)
    # logger.info (f"{__name__}: Issuing help command...")
    # help_cmd = await hostapd_adapter.send_command(HelpCommand())
    # response = await help_cmd.get_response()
    # logger.info (f"{__name__}: Help command response: {response}")

    await asyncio.sleep(2)
    logger.info (f"{__name__}: Issuing ping command...")
    ping_cmd = await hostapd_adapter.send_command(HostapdAdapter.PingCommand())
    response = await ping_cmd.get_response()
    logger.info (f"{__name__}: Ping response: {response}")

    await asyncio.sleep(2)
    logger.info (f"{__name__}: Getting active stations...")
    stas = await hostapd_adapter.get_connected_stas()
    logger.info (f"{__name__}: Station List: {stas}")

    await asyncio.sleep(2)
    logger.info (f"{__name__}: Getting active station MIBs...")
    sta_mibs = await hostapd_adapter.get_connected_sta_mibs()
    logger.info (f"{__name__}: Station MIBs: {pprint.pformat(sta_mibs)}")

    await asyncio.sleep(2)
    logger.info (f"{__name__}: Issuing Status command...")
    status_cmd = await hostapd_adapter.send_command(HostapdAdapter.StatusCommand())
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
        ping_cmd = await hostapd_adapter.send_command(HostapdAdapter.PingCommand())
        response = await ping_cmd.get_response()
        logger.info (f"{__name__}: Ping response: {response}")
    logger.info (f"{__name__}: Tests complete.")


async def run_dpp_tests():
    # await asyncio.sleep(2)
    qrcode = "DPP:C:81/1;M:2c:d0:5a:6e:ca:3c;I:KYZRQ;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAC/nFQKV1+CErzr6QCUT0jFIno3CaTRr3BW2n0ThU4mAw=;;"
    logger.info (f"{__name__}: Issuing DPP Add QRCode command...")
    logger.info (f"{__name__}:   Code: {qrcode}")
    add_config_id_cmd = await hostapd_adapter.send_command(HostapdAdapter.DPPAddQRCodeCommand(qrcode))
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
    hostapd_adapter = HostapdAdapter(None, '/var/run/hostapd/wlan0', [])
    await hostapd_adapter.connect()
    logger.info (f"{__name__}: hostapd control channel CONNECTED.")

    await asyncio.sleep(2)

    status_cmd = await hostapd_adapter.send_command(HostapdAdapter.StatusCommand())
    logger.info (f"{__name__}: Retrieving ssid...")
    ssid_list = await status_cmd.get_status_var("ssid")
    ssid = ssid_list[0]
    logger.info(f"{__name__}: SSID: {ssid}")

    add_configurator_cmd = HostapdAdapter.DPPAddConfiguratorCommand(curve="prime256v1")
    await hostapd_adapter.send_command(add_configurator_cmd)
    dpp_configurator_id = await add_configurator_cmd.get_configurator_id()
    logger.info (f"{__name__}: Configurator ID: {dpp_configurator_id}")

    logger.info (f"{__name__}: Creating a DPP Connector for the AP")
    dpp_config_sign_cmd = HostapdAdapter.DPPConfiguratorDPPSignCommand(dpp_configurator_id, ssid)
    await hostapd_adapter.send_command(dpp_config_sign_cmd)
    dpp_connector = await dpp_config_sign_cmd.get_connector()
    logger.info (f"{__name__}:   Connector: {dpp_connector}")
    dpp_c_sign_key = await dpp_config_sign_cmd.get_c_sign_key()
    logger.info (f"{__name__}:   DPP c-sign-key: {dpp_c_sign_key}")
    dpp_net_access_key = await dpp_config_sign_cmd.get_net_access_key()
    logger.info (f"{__name__}:   Net access key: {dpp_net_access_key}")
    
    await hostapd_adapter.send_command(HostapdAdapter.SetCommand("dpp_connector", dpp_connector))
    await hostapd_adapter.send_command(HostapdAdapter.SetCommand("dpp_csign", dpp_c_sign_key))
    await hostapd_adapter.send_command(HostapdAdapter.SetCommand("dpp_netaccesskey", dpp_net_access_key))

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


