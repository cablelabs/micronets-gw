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
        while True:
            try:
                data = self.hostapd_cli_process.stdout.readline().decode("utf-8")
                if not data:
                    break
                logger.info(f"HostapdAdapter:read_process_data: Read data: {data.rstrip()}")
            except Exception as ex:
                logger.warning(f"HostapdAdapter:read_process_data: Error processing data: {ex}")

    def send_command(self, message):
        self.hostapd_cli_process.stdin.write((message + '\n').encode())	
        self.hostapd_cli_process.stdin.flush()

if __name__ == '__main__':
    print (f"{__name__}: Starting\n")
    logging.basicConfig(level="DEBUG")
    logger = logging.getLogger ('hostapd_adapter')
    logger.info (f"{__name__}: Running hostapd_adapter tests")
    logger.info (f"{__name__}: Locale: {locale.getpreferredencoding(False)}")

    event_loop = asyncio.get_event_loop ()
    try:
        logger.info (f"{__name__}: Starting event loop...")
#        hostapd_adapter = HostapdAdapter("/usr/bin/tail", ["-f", "-n", "1", "/var/log/syslog"])
        hostapd_adapter = HostapdAdapter("/opt/micronets-hostapd/bin/hostapd_cli", [])
        event_loop.run_until_complete(hostapd_adapter.connect())
        logger.info (f"{__name__}: Connected.")
        time.sleep(2)
        logger.info (f"{__name__}: Issuing help command...")
        hostapd_adapter.send_command("help")
#        event_loop.run_until_complete(hostapd_adapter.relay_messages())
        event_loop.run_forever()
    except Exception as Ex:
        logger.warn (f"Caught an exception: {Ex}")


