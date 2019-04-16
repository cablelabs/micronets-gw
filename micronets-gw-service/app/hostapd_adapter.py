import asyncio
import logging
import locale
import subprocess
import threading
import traceback
import re
from queue import Queue, Empty
from subprocess import Popen, PIPE

logger = logging.getLogger ('hostapd_adapter')


class HostapdAdapter:

    cli_event_re = re.compile ('^.*<([0-9+])>(.+)$')

    def __init__ (self, hostapd_cli_path, hostapd_cli_args=()):
        self.hostapd_cli_path = hostapd_cli_path
        self.hostapd_cli_args = hostapd_cli_args
        self.hostapd_cli_process = None
        self.process_reader_thread = None
        self.command_queue = None
        self.event_loop = None

    async def connect(self):
        logger.info(f"HostapdAdapter:connect()")
        self.event_loop = asyncio.get_event_loop ()
        self.command_queue = Queue()  # https://docs.python.org/3.6/library/queue.html
        logger.info(f"HostapdAdapter:connect: Running {self.hostapd_cli_path} {self.hostapd_cli_args}")

        self.hostapd_cli_process = Popen([self.hostapd_cli_path, *self.hostapd_cli_args],
                                         shell=False, bufsize=1,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.process_reader_thread = threading.Thread(target=self.read_process_data)
        self.process_reader_thread.start()

    def read_process_data(self):
        response_data = None
        self.command_queue = Queue()
        logger.info(f"HostapdAdapter:read_process_data: Started")
        command = None
        while True:
            try:
                # https://docs.python.org/3/library/io.html

                # logger.debug(f"HostapdAdapter:read_process_data: Waiting on stdout.readline()...")
                data = self.hostapd_cli_process.stdout.readline()
                if not data:
                    logger.info(f"HostapdAdapter:read_process_data: Got EOF from hostapd_cli - exiting")
                    break
                line = data.decode("utf-8")
                if len(line) == 0:
                    continue
                logger.debug(f"HostapdAdapter:read_process_data: \"{line[:-1]}\"")
                cli_event_match = HostapdAdapter.cli_event_re.match(line)
                if cli_event_match:
                    event_data = cli_event_match.group(2)
                    asyncio.run_coroutine_threadsafe(self.process_event(event_data), self.event_loop)
                    continue
                if not command:
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
                    if pos > 0:
                        # logger.debug (f"HostapdAdapter:read_process_data: aggregate response_data: {response_data}")
                        command_type = type(command).__name__
                        complete_response = response_data[:pos].rstrip()
                        logger.debug (f"HostapdAdapter:read_process_data: Found command response for {command}: {complete_response}")
                        # logger.debug (f"HostapdAdapter:read_process_data: Calling process_response_data()...")
                        asyncio.run_coroutine_threadsafe(command.process_response_data(complete_response), 
                                                         command.event_loop)
                        # logger.debug (f"HostapdAdapter:read_process_data: process_response_data() returned.")
                        response_data = None
                        command = None
            except Exception as ex:
                logger.warning(f"HostapdAdapter:read_process_data: Error processing data: {ex}", exc_info=True)


    async def process_event(self, event_data):
        logger.info(f"HostapdAdapter:process_event: EVENT: (\"{event_data}\")")


    async def send_command(self, command):
        if not isinstance(command, HostapdCommand):
            raise TypeError
        self.command_queue.put(command)
        command_string = command.get_command_string()
        logger.info (f"HostapdAdapter:send_command: issuing command: {command} (\"{command_string}\")")
        # Put 2 newlines on the end to force a newline on the output
        command_string = command_string + "\n\n"
        self.hostapd_cli_process.stdin.write(command_string.encode())
        self.hostapd_cli_process.stdin.flush()

        return command


class HostapdCommand:
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


class GenericHostapdMessage(HostapdCommand):
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


class PingCommand(HostapdCommand):
    def __init__ (self, event_loop=asyncio.get_event_loop()):
        super().__init__(event_loop)

    def get_command_string(self):
        return "ping"


class HelpCommand(HostapdCommand):
    def __init__ (self, event_loop=asyncio.get_event_loop()):
        super().__init__(event_loop)

    def get_command_string(self):
        return "help"


class ListStationsCommand(HostapdCommand):
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


class DPPAddConfiguratorCommand(HostapdCommand):
    def __init__ (self, event_loop=asyncio.get_event_loop()):
        super().__init__(event_loop)
        self.configurator_id = None

    def get_command_string(self):
        return "dpp_configurator_add"

    async def process_response_data(self, response):
        try:
            self.configurator_id = int(response)
        finally:
            await super().process_response_data(response)

    async def get_configurator_id(self):
        await self.get_response()
        return self.configurator_id

class DPPAddQRCodeCommand(HostapdCommand):
    def __init__ (self, qrcode, event_loop=asyncio.get_event_loop()):
        super().__init__(event_loop)
        self.qrcode = qrcode
        self.qrcode_id = None

    def get_command_string(self):
        return f"dpp_qr_code {self.qrcode}"

    async def process_response_data(self, response):
        try:
            self.qrcode_id = int(response)
        finally:
            await super().process_response_data(response)

    def get_qrcode(self):
        return self.qrcode

    async def get_qrcode_id(self):
        await self.get_response()
        return self.qrcode_id


class DPPAuthInitPSK(HostapdCommand):
    def __init__ (self, configurator_id, qrcode_id, ssid, psk, event_loop=asyncio.get_event_loop()):
        super().__init__(event_loop)
        self.configurator_id = configurator_id
        self.qrcode_id = qrcode_id
        self.ssid = ssid
        self.psk = psk

    def get_command_string(self):
        return f"dpp_auth_init peer={self.qrcode_id} conf=sta-psk ssid={self.ssid} psk={self.psk} configurator={self.configurator_id}"

    async def process_response_data(self, response):
        await super().process_response_data(response)


async def run_tests():
#        hostapd_adapter = HostapdAdapter("/usr/bin/tail", ["-f", "-n", "1", "/var/log/syslog"])
        hostapd_adapter = HostapdAdapter("/opt/micronets-hostapd/bin/hostapd_cli", [])

        await hostapd_adapter.connect()
        logger.info (f"{__name__}: Connected.")

        # await asyncio.sleep(2)
        # logger.info (f"{__name__}: Issuing help command...")
        # help_cmd = await hostapd_adapter.send_command(HelpCommand())
        # response = await help_cmd.get_response()
        # logger.info (f"{__name__}: Help command response: {response}")

        await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing ping command...")
        ping_cmd = await hostapd_adapter.send_command(PingCommand())
        response = await ping_cmd.get_response()
        logger.info (f"{__name__}: Ping response: {response}")

        await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing List Stations command...")
        list_sta_cmd = await hostapd_adapter.send_command(ListStationsCommand())
        stas = await list_sta_cmd.get_sta_macs()
        logger.info (f"{__name__}: Station List: {stas}")

        await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing DPP Add Configurator command...")
        add_config_id_cmd = await hostapd_adapter.send_command(DPPAddConfiguratorCommand())
        configurator_id = await add_config_id_cmd.get_configurator_id()
        logger.info (f"{__name__}: DPP Configurator ID: {configurator_id}")

        # await asyncio.sleep(2)
        qrcode = "DPP:C:81/1;M:2c:d0:5a:6e:ca:3c;I:KYZRQ;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAC/nFQKV1+CErzr6QCUT0jFIno3CaTRr3BW2n0ThU4mAw=;;"
        logger.info (f"{__name__}: Issuing DPP Add QRCode command...")
        logger.info (f"{__name__}:   Code: {qrcode}")
        add_config_id_cmd = await hostapd_adapter.send_command(DPPAddQRCodeCommand(qrcode))
        qrcode_id = await add_config_id_cmd.get_qrcode_id()
        logger.info (f"{__name__}: DPP QRCode ID: {qrcode_id}")

        # await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing DPP Auth Init command...")
        ssid="756e636c652d6a6f686e"
        psk="0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        logger.info (f"{__name__}:   SSID: {ssid}")
        logger.info (f"{__name__}:   PSK: {psk}")
        dpp_auth_init_cmd = await hostapd_adapter.send_command(DPPAuthInitPSK(configurator_id, qrcode_id, ssid, psk))
        result = await dpp_auth_init_cmd.get_response()
        logger.info (f"{__name__}: Auth Init result: {result}")

        await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing a flood of pings...")
        for x in range(1,10):
            logger.info (f"{__name__}: Issuing ping command #{x}...")
            ping_cmd = await hostapd_adapter.send_command(PingCommand())
            response = await ping_cmd.get_response()
            logger.info (f"{__name__}: Ping response: {response}")
        logger.info (f"{__name__}: Tests complete.")


if __name__ == '__main__':
    print (f"{__name__}: Starting\n")
    logging.basicConfig(level="DEBUG")
    logger = logging.getLogger ('hostapd_adapter')
    logger.info (f"{__name__}: Running hostapd_adapter tests")
    logger.info (f"{__name__}: Locale: {locale.getpreferredencoding(False)}")

    event_loop = asyncio.get_event_loop ()
    try:
        logger.info (f"{__name__}: Starting event loop...")
        event_loop.run_until_complete(run_tests())
        event_loop.run_forever()
        logger.info (f"{__name__}: Event loop exited")
    except Exception as Ex:
        logger.warn (f"Caught an exception: {Ex}")
        traceback.print_exc()


