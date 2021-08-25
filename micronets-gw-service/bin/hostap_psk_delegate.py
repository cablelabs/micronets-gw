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
DELEGATE_BIN_DIR = pathlib.Path(__file__).parent.resolve()
#print(f"DELEGATE_BIN_DIR: {DELEGATE_BIN_DIR}")
DELEGATE_BASE_DIR = DELEGATE_BIN_DIR.parent.resolve()
#print(f"DELEGATE_BASE_DIR: {DELEGATE_BASE_DIR}")
DELEGATE_LIB_DIR = DELEGATE_BASE_DIR.joinpath("lib").resolve()
#print(f"DELEGATE_LIB_DIR: {DELEGATE_LIB_DIR}")

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
  with open(API_TOKEN_FILE, "r") as token_file:
    api_token = token_file.read()
except EnvironmentError:
  logger.error(f"Problem reading api token file: {API_TOKEN_FILE}... exiting")
  sys.exit(3)

# Check to see if the delegate is set to operate in fake mode, this is to be used only for dev/debug reasons
# Fake mode operates by checking if there is a "force-fake-delegate.txt file next to the delegate and if
# it is there, it reads the vlan id and psk from that file and returns that value if the psk-lookup DOES NOT
# return a SUCCESS. If the psk-lookup is successful, its value will be returned even in fake mode
# Note that the "force-fake-delegate.txt file needs to have the vlan and psk in valid format, otherwise
# you can potentially hang up hostap so BE VERY CAREFUL when using fake mode
# YOU should IMMEDIATELY delete the "force-fake-delegate.txt file as soon as you are done testing
FORCE_FAKE_DELEGATE = DELEGATE_BIN_DIR.joinpath("force-fake-delegate.txt")
FORCE_FAKE_ACTIVE = False
fake_values = ""
try:
  with open(FORCE_FAKE_DELEGATE, "r") as fake_psk:
    fake_values = fake_psk.read()
    if len(fake_values) > 0:
      FORCE_FAKE_ACTIVE = True
      logger.debug(f"Delegate fake mode activated with values: {fake_values}")
    else:
      logger.debug(f"Delegate gake mode activated but no valid vlan/psk provided")
except  EnvironmentError:
  logger.debug(f"Delegate set to use psk-lookup at: {LOOKUP_URL}")

  
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
  return m2data

def json2vlanpsk(body_json):
  logger.debug(f"Formatting vlan and PSK for hostap consumption")
  vlan_psk = body_json
  vlan = '{:04x}'.format(vlan_psk["vlan"])
  psk = vlan_psk["psk"]
  retval = vlan + " " + psk
  return retval

def handle_failure():
  # IF fake mode active, use fake values
  if FORCE_FAKE_ACTIVE:
    logger.debug(f"Sending fake vlan/psk values: {fake_values}")
    print(fake_values)
    sys.exit(0)
  else:
    # No match, reject device auth
    logger.debug(f"Rejected authentication for STA: {str(sys.argv[3])}")
    sys.exit(1)
  
async def main():
  # Start with checking incoming arguments
  
  # The line below should be disabled in production
  logger.debug(f"Argument List: {str(sys.argv)}")
  if len(sys.argv) == 9:
    # Right number of arguments, format them
    psk_data = m2tojson(sys.argv)
    logger.debug(f"psk_data: {json.dumps(psk_data, indent=4)}")

    headers = { "x-api-token": api_token}
    logger.debug(f"headers: {headers}")
    async with aiohttp.ClientSession(headers=headers) as session:
      async with session.post(LOOKUP_URL, json=psk_data) as resp:
        json_body = await resp.json()
        logger.debug(f"Response code of psk lookup: {resp.status}")
        logger.debug(f"Response body of psk lookup: {json.dumps(json_body,indent=4)}")
        if resp.status == 200:
          # Success, we got a match
          logger.debug(f"PSK Matched for STA: {str(sys.argv[3])}")
          # Send the formatted output to stdout
          print(json2vlanpsk(json_body))
        else:
          # send back auth failure or fake values
          handle_failure()
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
  