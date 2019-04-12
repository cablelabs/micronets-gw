import asyncio
import logging
import locale
import subprocess
import threading
import traceback
from queue import Queue, Empty
from subprocess import Popen, PIPE

logger = logging.getLogger ('hostapd_adapter')

class HostapdAdapter:

    def __init__ (self, hostapd_cli_path, hostapd_cli_args=()):
        self.hostapd_cli_path = hostapd_cli_path
        self.hostapd_cli_args = hostapd_cli_args
        self.hostapd_cli_process = None
        self.process_reader_thread = None
        self.command_queue = None

    async def connect(self):
        logger.info(f"HostapdAdapter:connect()")
        event_loop = asyncio.get_event_loop ()
        self.command_queue = Queue()  # https://docs.python.org/3.6/library/queue.html
        logger.info(f"HostapdAdapter:connect: Running {self.hostapd_cli_path} {self.hostapd_cli_args}")
        
        self.hostapd_cli_process = Popen([self.hostapd_cli_path, *self.hostapd_cli_args],
                                         shell=False, bufsize=1,
                                         stdin=PIPE, stdout=PIPE, stderr=subprocess.STDOUT)

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
                data = self.hostapd_cli_process.stdout.readline().decode("utf-8")
                if not data:
                    logger.info(f"HostapdAdapter:read_process_data: Got EOF from hostapd_cli - exiting")
                    break
                # logger.debug(f"HostapdAdapter:read_process_data: Read data: {data.rstrip()}")
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
                    response_data = response_data + data
                    pos = response_data.find("\n> ")
                    if pos > 0:
                        # logger.debug (f"HostapdAdapter:read_process_data: aggregate response_data: {response_data}")
                        command_type = type(command).__name__
                        complete_response = response_data[:pos]
                        logger.debug (f"HostapdAdapter:read_process_data: Found command response for {command}: {complete_response}")
                        asyncio.run_coroutine_threadsafe(command.process_response_data(complete_response), 
                                                         command.event_loop)
                        response_data = None
                        command = None
            except Exception as ex:
                logger.warning(f"HostapdAdapter:read_process_data: Error processing data: {ex}")

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
        self.response_future.set_result(response)

    async def get_sta_macs(self):
        await self.get_response()
        return self.sta_macs


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
        logger.info (f"{__name__}: Ping response: \"{response}\"")

        await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing List Stations command...")
        ping_cmd = await hostapd_adapter.send_command(ListStationsCommand())
        stas = await ping_cmd.get_sta_macs()
        logger.info (f"{__name__}: Station List: \"{stas}\"")

        logger.info (f"{__name__}: Issuing a flood of pings...")
        for x in range(1,10):
            logger.info (f"{__name__}: Issuing ping command #{x}...")
            ping_cmd = await hostapd_adapter.send_command(PingCommand())
            response = await ping_cmd.get_response()
            logger.info (f"{__name__}: Ping response: \"{response}\"")


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


