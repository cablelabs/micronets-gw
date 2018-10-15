from gevent import monkey
monkey.patch_all ()

from quart import Quart, Request, request

import os, argparse, config, sys, traceback, asyncio, websockets, logging

from .utils import InvalidUsage

# override the quart Request.on_json_loading_failed() to produce a more useful error
class MyRequest (Request):
    def on_json_loading_failed(self, error: Exception) -> None:
        """Handle a JSON parsing error.

        Arguments:
            error: The exception raised during parsing.
        """
        raise InvalidUsage (400, message=f"JSON parsing error: {error}")

class MyQuart (Quart):
    request_class = MyRequest

# create application instance
app = MyQuart (__name__)

arg_parser = argparse.ArgumentParser(description='The Micronets Gateway Service')

arg_parser.add_argument ('--config', "-c", required=False, action='store', type=str,
                         help="The service configuration to use (e.g. config.MockDevelopmentConfig, config.DnsmasqTestingConfig)")
args = arg_parser.parse_args ()

dhcp_config_env = os.environ.get ('MICRONETS_DHCP_CONFIG')

if (args.config):
    config = args.config
elif (dhcp_config_env):
    config = dhcp_config_env
else:
    config = 'config.MockDevelopmentConfig'

app.config.from_object (config)

logging_filename = app.config ['LOGFILE_PATH']
logging_filemode = app.config ['LOGFILE_MODE']
logging_level = app.config ['LOGGING_LEVEL']
logging.basicConfig (level=logging_level, filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')
print (f"Logging to logfile {logging_filename} (level {logging_level})")

logger = logging.getLogger ('micronets-gw-service')

logger.info (f"Loading app module using {config}")

dhcp_conf_model = None
dhcp_adapter = None
ws_connection = None

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

from .ws_connection import WSConnector

try:
    ws_connection_enabled = app.config['WEBSOCKET_CONNECTION_ENABLED']
    ws_server_address = app.config ['WEBSOCKET_SERVER_ADDRESS']
    ws_server_port = app.config ['WEBSOCKET_SERVER_PORT']
    ws_server_path = app.config ['WEBSOCKET_SERVER_PATH']
    ws_tls_certkey_file = app.config['WEBSOCKET_TLS_CERTKEY_FILE']
    ws_tls_ca_cert_file = app.config['WEBSOCKET_TLS_CA_CERT_FILE']
    ws_connection = WSConnector (ws_server_address, ws_server_port, ws_server_path,
                                 tls_certkey_file=ws_tls_certkey_file,
                                 tls_ca_file=ws_tls_ca_cert_file)
    if ws_connection_enabled:
        ws_connection.connect ()
    else:
        logger.info("Not initiating websocket connection (Websocket connection disabled)")
except Exception as ex:
    logger.info ("Error starting websocket connector:", exc_info=True)
    exit (1)

from .dhcp_conf import DHCPConf

flow_adapter = None
try:
    if app.config['FLOW_ADAPTER_ENABLED']:
        from .open_flow_adapter import OpenFlowAdapter

        flow_adapter = OpenFlowAdapter (app.config)
    else:
        logger.info("Not starting OpenFlowAdapter (adapter disabled in config)")
except Exception as ex:
    logger.warning ("Error staring flow adapter:", exc_info=True)

try:
    min_dhcp_conf_update_int_s = app.config ['MIN_DHCP_UPDATE_INTERVAL_S']
    logger.info (f"Minimum DHCP update interval (seconds): {min_dhcp_conf_update_int_s}")
    dhcp_conf_model = DHCPConf (ws_connection, dhcp_adapter, flow_adapter, min_dhcp_conf_update_int_s)
except Exception as ex:
    logger.info ("Error starting with adapter:", exc_info=True)
    exit (1)

# Initialize the API
from . import dhcp_api

