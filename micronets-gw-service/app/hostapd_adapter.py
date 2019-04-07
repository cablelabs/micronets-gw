import asyncio
import logging
import sys
import locale
import inspect
import time
import fcntl
import os
from asyncio import BaseTransport, ReadTransport, WriteTransport, SubprocessTransport

logger = logging.getLogger ('hostapd_adapter')

class HostapdAdapter:

    def __init__ (self, hostapd_cli_path, hostapd_cli_args=()):
        self.hostapd_cli_path = hostapd_cli_path
        self.hostapd_cli_args = hostapd_cli_args
        self.hostapd_proc = None
        self.transport = None
        self.protocol = None


    async def connect(self):
        logger.info(f"HostapdAdapter:connect()")
        event_loop = asyncio.get_event_loop ()
        logger.info(f"HostapdAdapter:connect: Running {self.hostapd_cli_path} {self.hostapd_cli_args}")
#        code = "import time,datetime; print(datetime.datetime.now());time.sleep(4);print(datetime.datetime.now());time.sleep(4);print(datetime.datetime.now());"
#        code = 'import time,datetime; \nwhile True: \n\tprint(datetime.datetime.now())\n\ttime.sleep(1)\n'
        transport, protocol = await event_loop.subprocess_exec(HostapdConnection, 
                                                               self.hostapd_cli_path, *self.hostapd_cli_args,
                                                               stdout=asyncio.subprocess.PIPE, 
                                                               stderr=asyncio.subprocess.STDOUT, 
                                                               stdin=asyncio.subprocess.PIPE,
                                                               encoding="utf-8")
        logger.info(f"HostapdAdapter:connect: subprocess_exec returned: transport {transport}, protocol {protocol}")
        self.transport = transport
        self.protocol = protocol
        protocol.stdin.writelines([b"help()\n   "])
        # protocol.stdin_pipe.flush()
        # protocol.stdout_pipe.flush()
        # time.sleep(1)
        # protocol.stdin.writelines([b"topics\n"])
        # time.sleep(1)
        # protocol.stdin.writelines([b"modules\n"])
        # time.sleep(1)
        # protocol.stdin.write_eof()
        logger.info(f"HostapdAdapter:connect done")

#async def relay_messages(self):
#        logger.info(f"HostapdAdapter:relay_messages()")
#        done, pending = await asyncio.wait ([self.read_stdout(), self.read_stderr(), self.write_stdin()],
#                                            return_when=asyncio.FIRST_COMPLETED)
#        logger.info(f"HostapdAdapter:relay_messages done")


class HostapdConnection (asyncio.Protocol):
    def __init__(self):
        logger.info(f"HostapdConnection constructed")
        self.transport = None
        self.stdin = None
        self.stdin_pipe = None
        self.stdout = None

    def connection_made(self, transport):
        logger.info(f"HostapdConnection:connection_made(transport: {transport})")
        if transport:
            self.transport = transport
            self.protocol = transport.get_protocol()
            logger.info(f"HostapdConnection:connection_made:   protocol: {self.protocol}")
            logger.info(f"HostapdConnection:connection_made:   transport type: {type(transport)}")
            
            if isinstance(transport, asyncio.ReadTransport):
                logger.info(f"HostapdConnection:connection_made:   transport is a ReadTransport")
            if isinstance(transport, asyncio.WriteTransport):
                logger.info(f"HostapdConnection:connection_made:   transport is a WriteTransport")
            if isinstance(transport, asyncio.SubprocessTransport):
                logger.info(f"HostapdConnection:connection_made:   transport is a SubprocessTransport")
                self.stdin = transport.get_pipe_transport(0)
                logger.info(f"HostapdConnection:connection_made:     stdin: {self.stdin}")
                logger.info(f"HostapdConnection:connection_made:     stdin: write_buffer_limit: {self.stdin.get_write_buffer_limits()}")
                # self.stdin.set_write_buffer_limits(10, 1)
                logger.info(f"HostapdConnection:connection_made:     stdin: adjusted write_buffer_limit: {self.stdin.get_write_buffer_limits()}")
                logger.info(f"HostapdConnection:connection_made:     stdin: write_buffer_size: {self.stdin.get_write_buffer_size()}")
                self.stdin_pipe = self.stdin.get_extra_info("pipe", None)
                logger.info(f"HostapdConnection:connection_made:     stdin: pipe: {self.stdin_pipe}")
                logger.info(f"HostapdConnection:connection_made:     stdin: fileno: {self.stdin_pipe.fileno()}")
                # logger.info(f"HostapdConnection:connection_made:     stdin members: {inspect.getmembers (self.stdin_pipe)}")
                # make stdin non-blocking 
                fl = fcntl.fcntl(self.stdin_pipe, fcntl.F_GETFL)
                fcntl.fcntl(self.stdin_pipe, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                self.stdout = transport.get_pipe_transport(1)
                logger.info(f"HostapdConnection:connection_made:     stdout: {self.stdout}")
                self.stdout_pipe = self.stdout.get_extra_info("pipe", None)
                logger.info(f"HostapdConnection:connection_made:     stdout: pipe: {self.stdout_pipe}")
                logger.info(f"HostapdConnection:connection_made:     stdout: resuming reading")

                fd = self.stdout_pipe.fileno()
                fl = fcntl.fcntl(fd, fcntl.F_GETFL)
                fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
                # logger.info(f"HostapdConnection:connection_made:     stdin members: {inspect.getmembers (self.stdin)}")

    def pipe_data_received(self, fd, data):
        logger.info(f"HostapdConnection:pipe_data_received(fd: {fd}, data: {data})")
    
    def pipe_connection_lost(self, fd, exc):
        logger.info(f"HostapdConnection:pipe_connection_lost(fd: {fd}, exc: {exc})")
    
    def process_exited(self):
        logger.info(f"HostapdConnection:process_exited()")
    
    def error_received(self, exc):
        logger.info(f"HostapdConnection:error_received(exc: {exc})")

    def connection_lost(self, exc):
        logger.info(f"HostapdConnection:connection_lost(exc: {exc})")

if __name__ == '__main__':
    print (f"{__name__}: Starting\n")
    logging.basicConfig(level="DEBUG")
    logger = logging.getLogger ('hostapd_adapter')
    logger.info (f"{__name__}: Running hostapd_adapter tests")
    logger.info (f"{__name__}: Locale: {locale.getpreferredencoding(False)}")

    event_loop = asyncio.get_event_loop ()
    try:
        logger.info (f"Starting event loop...")
#        hostapd_adapter = HostapdAdapter("/usr/bin/tail", ["-f", "-n", "1", "/var/log/syslog"])
        hostapd_adapter = HostapdAdapter("/usr/bin/python", ["-u"])
        event_loop.run_until_complete(hostapd_adapter.connect())
        event_loop.run_forever()
#        event_loop.run_until_complete(hostapd_adapter.relay_messages())
        event_loop.run_forever()
    except Exception as Ex:
        logger.warn (f"Caught an exception: {Ex}")
        traceback.print_exc (file=sys.stdout)
    

