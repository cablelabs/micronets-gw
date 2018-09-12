from gevent import monkey
monkey.patch_all ()

from quart import Quart, request
import os, argparse, config, sys, traceback, asyncio, websockets, logging

# create application instance
app = Quart (__name__)

arg_parser = argparse.ArgumentParser(description='The Micronets Gateway Service')

arg_parser.add_argument ('--config', "-c", required=False, action='store', type=str,
                         help="The service configuration to use (e.g. config.MockDevelopmentConfig, config.DnsmasqTestingConfig)")
args = arg_parser.parse_args ()

flask_env = os.environ.get ('FLASK_ENV')

if (args.config):
    config = args.config
elif (flask_env):
    config = flask_env
else:
    config = 'config.MockDevelopmentConfig'

app.config.from_object (config)

logging_filename = app.config ['LOGFILE_PATH']
logging_filemode = app.config ['LOGFILE_MODE']
logging_level = app.config ['LOGGING_LEVEL']
logging.basicConfig (level=logging_level, filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')

logger = logging.getLogger ('micronets-gw-service')

logger.info (f"Loading app module using {config}")

dhcp_conf_model = None
dhcp_adapter = None

def get_dhcp_conf_model ():
    return dhcp_conf_model

if not 'DHCP_ADAPTER' in app.config:
    exit (f"A DHCP_ADAPTER must be defined in the selected configuration ({app.config})")

adapter = app.config ['DHCP_ADAPTER'].upper ()
if adapter == "MOCK":
    from .mock_adapter import MockAdapter
    logger.info ("Using MOCK adapter")
    dhcp_adapter = MockAdapter ()
elif adapter == "ISCDHCP":
    from .isc_dhcpd_adapter import IscDhcpdAdapter
    logger.info ("Using ISC DHCP adapter")
    dhcp_adapter = IscDhcpdAdapter (app.config)
elif adapter == "DNSMASQ":
    from .dnsmasq_adapter import DnsMasqAdapter
    logger.info ("Using DNSMASQ adapter")
    dhcp_adapter = DnsMasqAdapter (app.config)
else:
    exit ("Unrecognized adapter type ({})".format (adapter))

from .dhcp_conf import DHCPConf

try:
    min_dhcp_conf_update_int_s = app.config ['MIN_DHCP_UPDATE_INTERVAL_S']
    logger.info (f"Minimum DHCP update interval (seconds): {min_dhcp_conf_update_int_s}")
    dhcp_conf_model = DHCPConf (dhcp_adapter, min_dhcp_conf_update_int_s)
except Exception as ex:
    logger.info ("Error starting with adapter:", exc_info=True)
    exit (1)

from .ws_connection import WSConnector

try:
    ws_server_address = app.config ['WEBSOCKET_SERVER_ADDRESS']
    ws_server_port = app.config ['WEBSOCKET_SERVER_PORT']
    ws_server_path = app.config ['WEBSOCKET_SERVER_PATH']
    ws_tls_certkey_file = app.config ['WEBSOCKET_TLS_CERTKEY_FILE']
    ws_tls_ca_cert_file = app.config ['WEBSOCKET_TLS_CA_CERT_FILE']
    ws_connection = WSConnector (ws_server_address, ws_server_port, ws_server_path,
                                 tls_certkey_file = ws_tls_certkey_file,
                                 tls_ca_file = ws_tls_ca_cert_file)
    ws_connection.connect ()
except Exception as ex:
    logger.info ("Error starting websocket connector:", exc_info=True)
    exit (1)

# Initialize the API
from . import dhcp_api

