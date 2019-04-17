import os, sys, pathlib, logging

app_dir = os.path.abspath (os.path.dirname (__file__))

class BaseConfig:
    LOGFILE_PATH = pathlib.Path (__file__).parent.joinpath ("micronets-gw.log")
    LOGFILE_MODE = 'w'  # 'w' clears the log at startup, 'a' appends to the existing log file
    LOGGING_LEVEL = logging.DEBUG
    SECRET_KEY = os.environ.get ('SECRET_KEY') or 'A SECRET KEY'
    LISTEN_HOST = "0.0.0.0"
    LISTEN_PORT = 5000
    MIN_DHCP_UPDATE_INTERVAL_S = 5
    DEFAULT_LEASE_PERIOD = '10m'
    SERVER_BASE_DIR = pathlib.Path (__file__).parent
    SERVER_BIN_DIR = SERVER_BASE_DIR.joinpath ("bin")
    WEBSOCKET_CONNECTION_ENABLED = False
    WEBSOCKET_SERVER_ADDRESS = "ws-proxy-api.micronets.in"
    WEBSOCKET_SERVER_PORT = 5050
    # NOTE: The WEBSOCKET_SERVER_PATH should be unique to the gateway/subscriber if using the proxy
    WEBSOCKET_SERVER_PATH = '/micronets/v1/ws-proxy/micronets-gw-0001'
    WEBSOCKET_TLS_CERTKEY_FILE = pathlib.Path (__file__).parent.joinpath ('lib/micronets-gw-service.pkeycert.pem')
    WEBSOCKET_TLS_CA_CERT_FILE = pathlib.Path (__file__).parent.joinpath ('lib/micronets-ws-root.cert.pem')
    FLOW_ADAPTER_NETWORK_INTERFACES_PATH = "/etc/network/interfaces"
    # For this command, the first parameter will be the bridge name and the second the flow filename
    FLOW_ADAPTER_APPLY_FLOWS_COMMAND = '/usr/bin/ovs-ofctl add-flows {} {}'
    FLOW_ADAPTER_ENABLED = False
    DPP_HANDLER_ENABLED = False
    HOSTAPD_ADAPTER_ENABLED = False
#
# Mock Adapter Configurations
#

class BaseMockConfig (BaseConfig):
    DHCP_ADAPTER = "Mock"

class MockDevelopmentConfig (BaseMockConfig):
    LISTEN_HOST = "127.0.0.1"
    LOGFILE_PATH = None
    LOGFILE_MODE = None
    DEBUG = True

class MockDevelopmentConfigWithWebsocket (MockDevelopmentConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    DPP_HANDLER_ENABLED = True
    WEBSOCKET_SERVER_ADDRESS = "localhost"

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
    LOGFILE_PATH = None
    LOGFILE_MODE = None
    DNSMASQ_CONF_FILE = 'doc/dnsmasq-config.sample'
    DNSMASQ_RESTART_COMMAND = []
    FLOW_ADAPTER_NETWORK_INTERFACES_PATH = BaseConfig.SERVER_BASE_DIR.parent\
                                           .joinpath("filesystem/opt/micronets-gw/doc/interfaces.sample")
    HOSTAPD_ADAPTER_ENABLED = True
    HOSTAPD_CLI_PATH = '/opt/micronets-hostapd/bin/hostapd_cli'

class DnsmasqDevelopmentConfigWithWebsocket (DnsmasqDevelopmentConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    WEBSOCKET_SERVER_ADDRESS = "localhost"
    DPP_HANDLER_ENABLED = True

class DnsmasqDevelopmentConfigWithFlowAdapter (DnsmasqDevelopmentConfig):
    FLOW_ADAPTER_APPLY_FLOWS_COMMAND = '/bin/echo This is where I would add flows to bridge {} from {}'
    FLOW_ADAPTER_ENABLED = True

class DnsmasqTestingConfig (BaseDnsmasqConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    DPP_HANDLER_ENABLED = True
    FLOW_ADAPTER_ENABLED = True
    DEBUG = True

class DnsmasqProductionConfig (BaseDnsmasqConfig):
    WEBSOCKET_CONNECTION_ENABLED = True
    DPP_HANDLER_ENABLED = True
    DEBUG = False
    LOGGING_LEVEL = logging.INFO
    LOGFILE_MODE = 'a'
