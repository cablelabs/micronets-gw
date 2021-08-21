#!/opt/micronets-gw/virtualenv/bin/python

import sys, pathlib, logging
import asyncio
import aiohttp
import json

# PSK Lookup Server config
LOOKUP_URL_BASE = "https://staging.api.controller.netreach.in"
LOOKUP_URL_PATH = "/v1/psks/psk-lookup"


# Some basic config
SERVER_BIN_DIR = pathlib.Path(__file__).parent
SERVER_BASE_DIR = SERVER_BIN_DIR.parent
LOGFILE_PATH = SERVER_BASE_DIR.joinpath("psk-delegate.log")
LOGFILE_MODE = 'a'

# Setup the logging
logger = logging.getLogger('psk-lookup-delegate')
logging_format = '%(asctime)s %(name)s: %(levelname)s %(message)s'
logging_level = logging.DEBUG
logging.basicConfig(level=logging_level, filename=LOGFILE_PATH,
                    filemode=LOGFILE_MODE, format=logging_format)

logger.info(f"Logging to logfile {LOGFILE_PATH} (level {logging_level})")

# Actual psk lookup starts below

def m2tojson(in_args):
  logger.debug(in_args)
  m2data = { "anonce": in_args[1],
             "snonce": in_args[2],
             "sta_mac": in_args[3],
             "ap_mac": in_args[4],
             "ssid": in_args[5],
             "akmp": in_args[6],
             "pairwise": in_args[7],
             "sta_m2": in_args[8]
            }
  return json.dumps(m2data, 2)


async def main():
  # Start with checking incoming arguments
  # This line should be disabled in production
  #logger.debug(f"Argument List: {str(sys.argv)}")
  if len(sys.argv) == 9:
    # Right number of arguments, format them
    psk_data = m2tojson(sys.argv)
    
    #async with aiohttp.ClientSession() as session:
    #  async with session.get() as resp:
    #    logger.debug(resp.status)
    #    logger.debug(await resp.text())
    
    print('0065', '221f7c59f10c217409ab1c35404fc512c8fdad646e197c269daafd5935b7303a')
    sys.exit(0)
  
  else:
    logger.error('Incorrect number of arguments')
    # hostap expects delegate to print some user friendly message
    # print('Incorrect number of arguments')
    exit(1)
    

if __name__ == '__main__':
  loop = asyncio.get_event_loop()
  try:
    loop.run_until_complete(main())
  finally:
    loop.run_until_complete(loop.shutdown_asyncgens())
    loop.close()
  