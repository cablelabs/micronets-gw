import asyncio
import logging
import sys
import locale
import inspect
import time
import fcntl
import os
import subprocess
import threading
from asyncio import BaseTransport, ReadTransport, WriteTransport, SubprocessTransport
from subprocess import Popen, PIPE

logger = logging.getLogger ('hostapd_adapter')

class HostapdAdapter:

    def __init__ (self, hostapd_cli_path, hostapd_cli_args=()):
        self.hostapd_cli_path = hostapd_cli_path
        self.hostapd_cli_args = hostapd_cli_args
        self.hostapd_cli_process = None
        self.process_reader_thread = None
        self.current_command = None

    async def connect(self):
        logger.info(f"HostapdAdapter:connect()")
        event_loop = asyncio.get_event_loop ()
        logger.info(f"HostapdAdapter:connect: Running {self.hostapd_cli_path} {self.hostapd_cli_args}")
        
        self.hostapd_cli_process = Popen([self.hostapd_cli_path, *self.hostapd_cli_args],
                                         shell=False, bufsize=1,
                                         stdin=PIPE, stdout=PIPE, stderr=subprocess.STDOUT)

        self.process_reader_thread = threading.Thread(target=self.read_process_data)
        self.process_reader_thread.start()

    def read_process_data(self):
        response_data = None
        logger.info(f"HostapdAdapter:read_process_data: Started")
        while True:
            try:
                # https://docs.python.org/3/library/io.html
                data = self.hostapd_cli_process.stdout.readline().decode("utf-8")
                if not data:
                    break
                logger.info(f"HostapdAdapter:read_process_data: Read data: {data.rstrip()}")
                if self.current_command:
                    if response_data is None:
                        # Don't store the first line (start aggregating on the next line)
                        response_data = ""
                        continue
                    response_data = response_data + data
                    pos = response_data.find("\n> ")
                    if pos > 0:
                        command = self.current_command
                        logger.info (f"HostapdAdapter:read_process_data: aggregate response_data: {response_data}")
                        command_type = type(command).__name__
                        complete_response = response_data[:pos]
                        logger.info (f"HostapdAdapter:read_process_data: Found command response for {command_type}: {complete_response}")
                        response_future = asyncio.run_coroutine_threadsafe (command.process_response(complete_response), 
                                                                            command.event_loop)
                        logger.info (f"HostapdAdapter:read_process_data: Waiting for {command_type}.process_response() to complete...")
                        response_future.result ()
                        logger.info (f"HostapdAdapter:read_process_data: {command_type}.process_response() completed.")
                        response_data = None
                        self.current_command = None
                else:
                    response_data = ""
            except Exception as ex:
                logger.warning(f"HostapdAdapter:read_process_data: Error processing data: {ex}")

    async def send_command(self, command):
        if not isinstance(command, HostapdCommand):
            raise TypeError
        if self.current_command:
            # TODO: Queue the command
            raise Exception(f"send_command already processing {type(self.current_command).__name__} command")
        self.current_command = command
        command_string = command.get_command_string()
        logger.info (f"HostapdAdapter:send_command: issuing command: \"{command_string}\"")
        # Put 2 newlines on the end to force a newline on the output
        command_string = command_string + "\n\n"
        self.hostapd_cli_process.stdin.write(command_string.encode())
        self.hostapd_cli_process.stdin.flush()


class HostapdCommand:
    def __init__ (self, event_loop = asyncio.get_event_loop()):
        self.event_loop = event_loop

    def get_command_string(self):
        """ Over-ride this method to provide the string that compromise the hostapd_cli command (without newline)"""
        pass

    async def process_response(self, response):
        """This is where the response can be parsed for meaningful data, parsed, and have
        memvars set to any values that want to be retained."""
        pass

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

    async def process_response(self, response):
        self.response = response


class PingCommand(HostapdCommand):
    def __init__ (self, event_loop=asyncio.get_event_loop()):
        super().__init__(event_loop)
        self.ping_response = None

    def get_command_string(self):
        return "ping"

    async def process_response(self, response):
        logger.info (f"{__name__}: Got ping response: {response.rstrip()}")
        self.ping_response = response
    
    def get_response(self):
        return self.ping_response


class HelpCommand(HostapdCommand):
    def __init__ (self, event_loop=asyncio.get_event_loop()):
        super().__init__(event_loop)

    def get_command_string(self):
        return "help"

    async def process_response(self, response):
        logger.info (f"{__name__}: Got help response: {response.rstrip()}")


async def run_tests():
#        hostapd_adapter = HostapdAdapter("/usr/bin/tail", ["-f", "-n", "1", "/var/log/syslog"])
        hostapd_adapter = HostapdAdapter("/opt/micronets-hostapd/bin/hostapd_cli", [])
        await hostapd_adapter.connect()
        logger.info (f"{__name__}: Connected.")

        await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing help command...")
        await hostapd_adapter.send_command(HelpCommand())

        await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing ping command...")
        ping_cmd = PingCommand()
        await hostapd_adapter.send_command(PingCommand())
        logger.info (f"{__name__}: Ping response: \"{ping_cmd.get_response()}\"")

        await asyncio.sleep(2)
        logger.info (f"{__name__}: Issuing ping command...")
        await hostapd_adapter.send_command(PingCommand())

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


