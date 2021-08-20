

import sys, pathlib, logging

# Setup the logging
SERVER_BIN_DIR = pathlib.Path(__file__).parent
SERVER_BASE_DIR = SERVER_BIN_DIR.parent
LOGFILE_PATH = SERVER_BASE_DIR.joinpath("psk-delegate.log")
LOGFILE_MODE = 'a'
logger = logging.getLogger('psk-lookup-delegate')

logging_format = '%(asctime)s %(name)s: %(levelname)s %(message)s'
logging_level = logging.DEBUG
logging.basicConfig(level=logging_level, filename=LOGFILE_PATH,
                    filemode=LOGFILE_MODE, format=logging_format)

logger.info(f"Logging to logfile {LOGFILE_PATH} (level {logging_level})")


# Real psk lookup starts below

# Start with logging incoming arguments
# This line should be disabled in production
logger.debug(f"Argument List: {str(sys.argv)}")

print('0065', '221f7c59f10c217409ab1c35404fc512c8fdad646e197c269daafd5935b7303a')

sys.exit(0)
