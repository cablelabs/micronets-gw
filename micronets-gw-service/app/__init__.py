from quart import Quart, Request, request

import os, argparse, config, sys, traceback, asyncio, socket, websockets, logging

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

logger = logging.getLogger ('micronets-gw-service')

# create application instance
app = MyQuart (__name__)

arg_parser = argparse.ArgumentParser(description='The Micronets Gateway Service')

arg_parser.add_argument ('--config', "-c", required=False, action='store', type=str,
                         help="The service configuration to use (e.g. config.MockDevelopmentConfig, config.DnsmasqTestingConfig)")
args = arg_parser.parse_args ()

config_env = os.environ.get ('MICRONETS_GW_SERVICE_CONFIG')

if (args.config):
    config = args.config
elif (config_env):
    config = config_env
else:
    config = 'config.MockDevelopmentConfig'

print (f"Running with config {config}")

app.config.from_object (config)

logging_filename = app.config.get('LOGFILE_PATH')
logging_filemode = app.config.get('LOGFILE_MODE')
logging_level = app.config.get('LOGGING_LEVEL')
logging.basicConfig (level=logging_level, filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')
print (f"Logging to logfile {logging_filename} (level {logging_level})")

logger.info (f"Loading app module using {config}")

def get_logger():
    return logger

def get_conf_model ():
    return conf_model

def get_ws_connector():
    return ws_connector

def get_dpp_handler():
    return dpp_handler

if not 'DHCP_ADAPTER' in app.config:
    exit (f"A DHCP_ADAPTER must be defined in the selected configuration ({app.config})")

subscriber_id = app.config.get('SUBSCRIBER_ID')

gateway_id = app.config.get('GATEWAY_ID')
if not gateway_id:
    gateway_id = socket.gethostname().split(".")[0]

logger.info (f"Starting gateway \"{gateway_id}\"")

if subscriber_id:
    logger.info(f"Subscriber ID override: \"{subscriber_id}\"")

dhcp_adapter = None
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

from .ws_connector import WSConnector

ws_connector = None
try:
    ws_connector_enabled = app.config.get('WEBSOCKET_CONNECTION_ENABLED')
    ws_url = app.config.get('WEBSOCKET_URL')
    ws_lookup_url = app.config.get('WEBSOCKET_LOOKUP_URL')
    ws_tls_certkey_file = app.config.get('WEBSOCKET_TLS_CERTKEY_FILE')
    ws_tls_ca_cert_file = app.config.get('WEBSOCKET_TLS_CA_CERT_FILE')

    ws_connector = WSConnector (ws_url, ws_lookup_url, gateway_id,
                                tls_certkey_file=ws_tls_certkey_file,
                                tls_ca_file=ws_tls_ca_cert_file)
    if ws_connector_enabled:
        ws_connector.connect ()
    else:
        logger.info("Not initiating websocket connection (Websocket connection disabled)")
except Exception as ex:
    logger.info ("Error starting websocket connector:", exc_info=True)
    exit (1)

from .hostapd_adapter import HostapdAdapter

hostapd_adapter = None
try:
    hostapd_adapter_enabled = app.config['HOSTAPD_ADAPTER_ENABLED']
    if hostapd_adapter_enabled:
        hostapd_cli_path = app.config.get('HOSTAPD_CLI_PATH')
        hostapd_psk_file_path = app.config.get('HOSTAPD_PSK_FILE_PATH')
        logger.info(f"hostapd adapter enabled (hostapd_psk_file_path {hostapd_psk_file_path}"
                                             f",hostapd cli path {hostapd_cli_path})")
        hostapd_adapter = HostapdAdapter(hostapd_psk_file_path, hostapd_cli_path)
        asyncio.ensure_future(hostapd_adapter.connect())
    else:
        logger.info("Not initiating hostapd adapter (disabled via config)")
except Exception as ex:
    logger.info ("Error starting hostapd adapter:", exc_info=True)
    exit (1)

from .dpp_handler import DPPHandler

dpp_handler = None
try:
    dpp_handler_enabled = app.config['DPP_HANDLER_ENABLED']
    if dpp_handler_enabled:
        dpp_handler = DPPHandler(app.config, hostapd_adapter)
        ws_connector.register_handler (dpp_handler)
        if hostapd_adapter:
            hostapd_adapter.register_cli_event_handler(dpp_handler)
    else:
        logger.info("Not initiating dpp handler (DPP handler disabled)")
except Exception as ex:
    logger.info ("Error registering DPP handler:", exc_info=True)
    exit (1)

flow_adapter = None
try:
    if app.config['FLOW_ADAPTER_ENABLED']:
        from .open_flow_adapter import OpenFlowAdapter

        flow_adapter = OpenFlowAdapter (app.config)
        if hostapd_adapter:
            hostapd_adapter.register_cli_event_handler(flow_adapter)
    else:
        logger.info("Not starting OpenFlowAdapter (adapter disabled in config)")
except Exception as ex:
    logger.warning ("Error starting flow adapter:", exc_info=True)

from .gateway_service_conf import GatewayServiceConf

conf_model = None
try:
    min_dhcp_conf_update_int_s = app.config ['MIN_DHCP_UPDATE_INTERVAL_S']
    logger.info (f"Minimum DHCP update interval (seconds): {min_dhcp_conf_update_int_s}")
    conf_model = GatewayServiceConf (ws_connector, dhcp_adapter, flow_adapter, hostapd_adapter,
                                     min_dhcp_conf_update_int_s)
except Exception as ex:
    logger.info ("Error starting with adapter:", exc_info=True)
    exit (1)

asyncio.ensure_future(conf_model.queue_conf_update())

# Initialize the API
from . import gateway_service_api

