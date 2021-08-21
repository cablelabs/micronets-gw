#!/opt/micronets-gw/virtualenv/bin/python

import sys, pathlib, logging
import asyncio
import aiohttp
import json

# PSK Lookup Server config
LOOKUP_URL_BASE = "https://staging.api.controller.netreach.in"
LOOKUP_URL_PATH = "/v1/psks/psk-lookup"
LOOKUP_URL = LOOKUP_URL_BASE + LOOKUP_URL_PATH

# Some basic config
DELEGATE_BIN_DIR = pathlib.Path(__file__).parent
DELEGATE_BASE_DIR = DELEGATE_BIN_DIR.parent
DELEGATE_LIB_DIR = DELEGATE_BASE_DIR.joinpath("lib")
API_TOKEN_FILE = DELEGATE_LIB_DIR.joinpath("netreach-api-token.txt")

LOGFILE_PATH = DELEGATE_BASE_DIR.joinpath("psk-delegate.log")
LOGFILE_MODE = 'a'

# Setup the logging
logger = logging.getLogger('psk-lookup-delegate')
logging_level = logging.DEBUG
logging_format = '%(asctime)s %(name)s: %(levelname)s %(message)s'
logging.basicConfig(level=logging_level, filename=LOGFILE_PATH,
                    filemode=LOGFILE_MODE, format=logging_format)
try:
  logger.info(f"Logging to logfile {LOGFILE_PATH} (level {logging_level})")
except PermissionError as pe:
  print(f"Permissions Error opening logfile: {LOGFILE_PATH}... exiting")
  sys.exit(2)

# Read the API token or die
try:
  with open(API_TOKEN_FILE) as token_file:
    api_token = token_file.read()
except EnvironmentError:
  logger.error(f"Problem reading api token file: {API_TOKEN_FILE}... exiting")
  sys.exit(3)
  
# Actual psk lookup starts below

# Create json body from handshake params
def m2tojson(in_args):
  #logger.debug(in_args)
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

def json2vlanpsk(body):
  logger.debug(f"Formatting vlan and PSK for hostap consumption")
  vlan_psk = json.loads(body)
  vlan = '{:04x}'.format(vlan_psk["vlan"])
  psk = vlan_psk["psk"]
  retval = vlan + " " + psk
  return retval
  
  
async def main():
  # Start with checking incoming arguments
  
  # The line below should be disabled in production
  #logger.debug(f"Argument List: {str(sys.argv)}")
  if len(sys.argv) == 9:
    # Right number of arguments, format them
    psk_data = m2tojson(sys.argv)
    
    headers = { "x-api-token": api_token }
    async with aiohttp.ClientSession(headers=headers) as session:
      async with session.post(LOOKUP_URL, json=psk_data) as resp:
        json_body = await resp.json()
        logger.debug(f"Response code of psk lookup: {resp.status}")
        if resp.status == 200:
          # Success, we got a match
          logger.debug(f"PSK Matched for STA: {str(sys.argv[3])}")
          # Send the formatted output to stdout
          print(json2vlanpsk(json_body))
        else:
          # No match, reject device auth
          logger.debug(f"Rejected authentication for STA: {str(sys.argv[3])}")
          sys.exit(1)
        
    
    #print('0065', '22fe3217153bec6dbd1413bf02adce374e6a5be87252db0dbd4dba9eeb588ec2')
    sys.exit(0)
  
  else:
    logger.error('Incorrect number of arguments....exiting')
    logger.debug(f'Arguments List: {str(sys.argv)}')
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
  