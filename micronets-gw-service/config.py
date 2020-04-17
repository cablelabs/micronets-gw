import os, sys, pathlib, logging

app_dir = os.path.abspath (os.path.dirname (__file__))

class BaseConfig:
    LOGGING_LEVEL = logging.DEBUG
    SECRET_KEY = os.environ.get ('SECRET_KEY') or 'A SECRET KEY'
    LISTEN_HOST = "0.0.0.0"
    LISTEN_PORT = 5000
    MIN_DHCP_UPDATE_INTERVAL_S = 2
    DEFAULT_LEASE_PERIOD = '2m'
    SERVER_BASE_DIR = pathlib.Path (__file__).parent
    SERVER_BIN_DIR = SERVER_BASE_DIR.joinpath ("bin")
    WEBSOCKET_CONNECTION_ENABLED = False
    WEBSOCKET_LOOKUP_URL = 'https://dev.mso-portal-api.micronets.in/api/portal/v1/socket?gatewayId={gateway_id}'
    WEBSOCKET_TLS_CERTKEY_FILE = pathlib.Path (__file__).parent.joinpath ('lib/micronets-gw-service.pkeycert.pem')
    WEBSOCKET_TLS_CA_CERT_FILE = pathlib.Path (__file__).parent.joinpath ('lib/micronets-ws-root.cert.pem')
    FLOW_ADAPTER_NETWORK_INTERFACES_PATH = "/etc/network/interfaces"
    # For this command, the first parameter will be the bridge name and the second the flow filename
    FLOW_ADAPTER_ENABLED = False
    DPP_HANDLER_ENABLED = False
    DPP_CONFIG_KEY_FILE = pathlib.Path (__file__).parent.joinpath ("lib/hostapd-dpp-configurator.key")
    DPP_AP_CONNECTOR_FILE = pathlib.Path (__file__).parent.joinpath ("lib/hostapd-dpp-ap-connector.json")
    HOSTAPD_ADAPTER_ENABLED = False
    SIMULATE_ONBOARD_RESPONSE_EVENTS = False

class BaseGatewayConfig:
    LOGFILE_PATH = pathlib.Path (__file__).parent.joinpath ("micronets-gw.log")
    FLOW_ADAPTER_APPLY_FLOWS_COMMAND = '/usr/bin/ovs-ofctl add-flows {ovs_bridge} {flow_file}'
    HOSTAPD_PSK_FILE_PATH = '/opt/micronets-hostapd/lib/hostapd.wpa_psk'
    HOSTAPD_CLI_PATH = '/opt/micronets-hostapd/bin/hostapd_cli'
    # Set this iff you want to disable websocket URL lookup using MSO Portal (MSO_PORTAL_WEBSOCKET_LOOKUP_ENDPOINT)
    #    WEBSOCKET_URL = "wss://ws-proxy-api.micronets.in:5050/micronets/v1/ws-proxy/gw-test/{gateway_id}"

#
# Mock Adapter Configurations
#

class BaseMockConfig (BaseConfig):
    DHCP_ADAPTER = "Mock"
    GATEWAY_ID = "mock-gw"

class MockDevelopmentConfig (BaseMockConfig):
    LISTEN_HOST = "127.0.0.1"
    LOGFILE_PATH = None
    LOGFILE_MODE = None
    DEBUG = True

class MockDevelopmentConfigWithWebsocket (MockDevelopmentConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    WEBSOCKET_URL = "wss://localhost:5050/micronets/v1/ws-proxy/gw/mock-gw"
    DPP_HANDLER_ENABLED = True
    SIMULATE_ONBOARD_RESPONSE_EVENTS = "with success"

#
# ISC DHCP Adapter Configurations
#

class BaseIscDhcpConfig (BaseConfig):
    DHCP_ADAPTER = "IscDhcp"
    ISC_DHCPD_CONF_FILE = '/etc/dhcp/dhcpd.conf'
    ISC_DHCPD_RESTART_COMMAND = ['sudo','/etc/init.d/isc-dhcp-server','restart']

class IscDevelopmentConfig (BaseIscDhcpConfig):
    LISTEN_HOST = "127.0.0.1"
    LOGFILE_PATH = None
    LOGFILE_MODE = None
    ISC_DHCPD_CONF_FILE = 'doc/dhcpd-sample.conf'
    ISC_DHCPD_RESTART_COMMAND = None
    DEBUG = True

class IscTestingConfig (BaseIscDhcpConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    DEBUG = True

class IscProductionConfig (BaseIscDhcpConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    DPP_HANDLER_ENABLED = True
    DEBUG = False
    LOGGING_LEVEL = logging.INFO
    LOGFILE_MODE = 'a'

#
# DNSMASQ DHCP Adapter Configurations
#

class BaseDnsmasqConfig (BaseConfig):
    DHCP_ADAPTER = "DnsMasq"
    DNSMASQ_CONF_FILE = '/etc/dnsmasq.d/micronets'
    DNSMASQ_RESTART_COMMAND = ['sudo','/etc/init.d/dnsmasq','restart']
    DNSMASQ_LEASE_SCRIPT = BaseConfig.SERVER_BIN_DIR.joinpath ("dnsmasq_lease_notify.py")

class DnsmasqDevelopmentConfig (BaseDnsmasqConfig):
    DEBUG = True
    LISTEN_HOST = "127.0.0.1"
    DNSMASQ_CONF_FILE = 'doc/dnsmasq-config.sample'
    DNSMASQ_RESTART_COMMAND = []
    FLOW_ADAPTER_NETWORK_INTERFACES_PATH = BaseConfig.SERVER_BASE_DIR.parent\
                                           .joinpath("filesystem/opt/micronets-gw/doc/interfaces.sample")
    HOSTAPD_ADAPTER_ENABLED = True
    HOSTAPD_PSK_FILE_PATH = 'doc/hostapd.wpa_psk.sample'

class DnsmasqDevelopmentConfigWithLocalWebsocket (DnsmasqDevelopmentConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    WEBSOCKET_URL = "wss://localhost:5050/micronets/v1/ws-proxy/gw/mock-gw"
    DPP_HANDLER_ENABLED = True
    SIMULATE_ONBOARD_RESPONSE_EVENTS = "with success"

class DnsmasqDevelopmentConfigWithFlowRules (DnsmasqDevelopmentConfig):
    FLOW_ADAPTER_APPLY_FLOWS_COMMAND = '/usr/bin/sort -t= -k 2n -k 3rn {flow_file}'
    FLOW_ADAPTER_ENABLED = True

class DnsmasqDebugConfig (BaseDnsmasqConfig, BaseGatewayConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    DPP_HANDLER_ENABLED = True
    FLOW_ADAPTER_ENABLED = True
    HOSTAPD_ADAPTER_ENABLED = True
    LOGFILE_PATH = None
    DEBUG = True

class DnsmasqTestingConfig (BaseDnsmasqConfig, BaseGatewayConfig):
    DEBUG = True
    LOGFILE_MODE = 'w'  # 'w' clears the log at startup, 'a' appends to the existing log file
    WEBSOCKET_CONNECTION_ENABLED = True
    DPP_HANDLER_ENABLED = True
    FLOW_ADAPTER_ENABLED = True
    HOSTAPD_ADAPTER_ENABLED = True

class DnsmasqProductionConfig (DnsmasqTestingConfig):
    DEBUG = False
    LOGGING_LEVEL = logging.INFO
    LOGFILE_MODE = 'a'

