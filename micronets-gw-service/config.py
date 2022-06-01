import os, pathlib, logging

class BaseConfigSettings:
    SECRET_KEY = os.environ.get ('SECRET_KEY') or 'A SECRET KEY'
    LISTEN_PORT = 5000
    SERVER_BASE_DIR = pathlib.Path (__file__).parent.resolve()
    SERVER_BIN_DIR = SERVER_BASE_DIR.joinpath ("bin")
    SERVER_LIB_DIR = SERVER_BASE_DIR.joinpath ("lib")
    DB_ADAPTER = "JsonDBFileAdapter"
    JSONFILEDB_DIR_PATH = SERVER_LIB_DIR
    ADAPTER_UPDATE_INTERVAL_S = 2
    DHCP_ADAPTER = "dnsmasq"
    DHCP_ADAPTER_DEFAULT_LEASE_PERIOD = '2m'
    DNSMASQ_ADAPTER_LEASE_SCRIPT = SERVER_BIN_DIR.joinpath ("dnsmasq_lease_notify.py")
    FLOW_ADAPTER_ENABLED = False
    HOSTAPD_ADAPTER_ENABLED = False
    DPP_HANDLER_ENABLED = False
    MICRONETS_OVS_BRIDGE = os.environ.get('MICRONETS_OVS_BRIDGE') or 'brmn001'
    MICRONETS_GATEWAY_NETMASK = "10.0.0.1/255.0.0.255"
    # If not set, the MAC of the MICRONETS_OVS_BRIDGE host interface will be used
    # MICRONETS_GATEWAY_MAC_ADDR = "00:10:00:21:12:42"
    MICRONETS_OVS_BRIDGE_TRUNK_PORT = int(os.environ.get('MICRONETS_OVS_BRIDGE_TRUNK_PORT', '1'))
    MICRONETS_OVS_BRIDGE_DROP_PORT = int(os.environ.get('MICRONETS_OVS_BRIDGE_DROP_PORT', '42'))
    DPP_CONFIG_KEY_FILE = SERVER_LIB_DIR.joinpath("hostapd-dpp-configurator.key")
    DPP_AP_CONNECTOR_FILE = SERVER_LIB_DIR.joinpath("hostapd-dpp-ap-connector.json")
    DPP_HANDLER_SIMULATE_ONBOARD_RESPONSE_EVENTS = False
    WEBSOCKET_CONNECTION_ENABLED = False
    WEBSOCKET_LOOKUP_URL = 'https://dev.mso-portal-api.micronets.in/portal/v1/socket?gatewayId={gateway_id}'
    WEBSOCKET_TLS_CERTKEY_FILE = SERVER_LIB_DIR.joinpath ('micronets-gw-service.pkeycert.pem')
    WEBSOCKET_TLS_CA_CERT_FILE = SERVER_LIB_DIR.joinpath ('micronets-ws-root.cert.pem')

#
# Configure settings for reference gateway (system configured with dependent packages)
#
class ReferenceGatewaySettings (BaseConfigSettings):
    # Note: This is dangerous - don't listen on 0.0.0.0 in production
    # TODO: Define a way to provide an interface name for listen
    LISTEN_HOST = "0.0.0.0"
    LOGFILE_PATH = BaseConfigSettings.SERVER_BASE_DIR.joinpath ("micronets-gw.log")
    LOGFILE_MODE = 'a'
    DNSMASQ_ADAPTER_CONF_FILE = '/etc/dnsmasq.d/micronets'
    DNSMASQ_ADAPTER_RESTART_COMMAND = ['sudo', 'systemctl', 'restart', 'dnsmasq.service']
    FLOW_ADAPTER_APPLY_FLOWS_COMMAND = '/usr/bin/ovs-ofctl add-flows {ovs_bridge} {command_file}'
    FLOW_ADAPTER_APPLY_RULES_COMMAND = '/usr/bin/ovs-ofctl add-groups {ovs_bridge} {command_file}'
    HOSTAPD_CLI_PATH = '/opt/micronets-hostapd/bin/hostapd_cli'
    HOSTAPD_PSK_FILE_PATH = '/opt/micronets-hostapd/lib/hostapd.wpa_psk'

class NetreachDefaultSettings():
    libpath = BaseConfigSettings.SERVER_LIB_DIR
    NETREACH_ADAPTER_ENABLED = True
    NETREACH_ADAPTER_SERIAL_NUM_FILE = libpath.joinpath('netreach-serialnum.txt')
    NETREACH_ADAPTER_REG_TOKEN_FILE = libpath.joinpath('netreach-reg-token.txt')
    NETREACH_ADAPTER_PUBLIC_KEY_FILE = libpath.joinpath('netreach-pubkey.pem')
    NETREACH_ADAPTER_PRIVATE_KEY_FILE = libpath.joinpath('netreach-privkey.pem')
    NETREACH_ADAPTER_WIFI_INTERFACE = "wlan0"
    NETREACH_ADAPTER_MAN_INTERFACE = "eth0"
    # NETREACH_ADAPTER_MAN_ADDRESS = "1.2.3.4"
    # NETREACH_ADAPTER_GEOLOCATION = {"latitude": "0.0", "longitude": "0.0"}
    NETREACH_ADAPTER_SSID_OVERRIDE_FILE = libpath.joinpath('netreach-ssid-override.txt')
    NETREACH_ADAPTER_UNASSIGNED_SSID = "netreach-inactive"
    NETREACH_ADAPTER_CONTROLLER_BASE_URL = "https://staging.api.controller.netreach.in"
    # NETREACH_ADAPTER_CONTROLLER_BASE_URL = "https://api.controller.netreach.in"
    NETREACH_ADAPTER_API_KEY_FILE = libpath.joinpath('netreach-api-token.txt')
    NETREACH_ADAPTER_API_KEY_REFRESH_DAYS = 500
    # NETREACH_ADAPTER_MQTT_BROKER_URL = "mqtts://staging.broker.controller.netreach.in:8885" # for overriding
    NETREACH_ADAPTER_MQTT_CA_CERTS = libpath.joinpath('netreach-mqtt-ca.crt')
    NETREACH_ADAPTER_CONN_START_DELAY_S = 2
    NETREACH_ADAPTER_CONN_RETRY_S = 10
    NETREACH_ADAPTER_USE_DEVICE_PASS = True
    NETREACH_ADAPTER_PSK_CACHE_ENABLED = True
    NETREACH_ADAPTER_PSK_CACHE_EXPIRE_S = 60
    NETREACH_ADAPTER_VXLAN_PEER_INAME_PREFIX = "nap."
    NETREACH_ADAPTER_VXLAN_PEER_INAME_FORMAT = "nap.{short_ap_id}.{vlan:x}"
    NETREACH_ADAPTER_VXLAN_NET_BRIDGE = "brhapd"
    NETREACH_ADAPTER_VXLAN_NET_MICRONETS_PORT = "hapd-tr-patch"
    NETREACH_ADAPTER_VXLAN_NET_HOSTAPD_PORT = "haport-sw"
    NETREACH_ADAPTER_VXLAN_LIST_PORTS = "/usr/bin/ovs-vsctl list-ports {vxlan_net_bridge}"
    NETREACH_ADAPTER_VXLAN_CONNECT_CMD = "/usr/bin/ovs-vsctl add-port {vxlan_net_bridge} {vxlan_port_name} -- " \
                                       "set interface {vxlan_port_name} type=vxlan " \
                                       "options:remote_ip={remote_vxlan_host} " \
                                       "options:key={vxlan_conn_key}"
    NETREACH_ADAPTER_VXLAN_DISCONNECT_CMD = "/usr/bin/ovs-vsctl del-port {vxlan_port_name}"
    NETREACH_ADAPTER_DEVICE_MTU = 1430
    # Set this to False when using a DHCP server that signals DHCP renew (e.g. dnsmask 2.81 script-on-renewal option)
    NETREACH_ADAPTER_SET_CONN_ON_ASSOC = True

#
# Configure settings for local/development testing
#
class LocalDevelopmentSettings (BaseConfigSettings):
    # Anything here should be an alternate local setting to what's set in ReferenceGatewayConfig
    # Anything that's common to local development config and the gateway config should be in BaseConfig
    LOGFILE_PATH = None
    LOGFILE_MODE = None
    LISTEN_HOST = "127.0.0.1"
    DNSMASQ_ADAPTER_CONF_FILE = BaseConfigSettings.SERVER_LIB_DIR.joinpath("dnsmasq-config.sample")
    DNSMASQ_ADAPTER_RESTART_COMMAND = []
    FLOW_ADAPTER_APPLY_FLOWS_COMMAND = '/usr/bin/sort -t= -k 2n -k 3rn {flow_file}'
    HOSTAPD_CLI_PATH = None
    HOSTAPD_PSK_FILE_PATH = BaseConfigSettings.SERVER_LIB_DIR.joinpath("hostapd.wpa_psk")

#
# Configurations to enable various combinations of adapters and control debug/log levels
# General settings should NOT go here
#

#
# Local Development Configs
#
class LocalDevelopmentConfig (LocalDevelopmentSettings):
    GATEWAY_ID = "mock-gw"
    DEBUG = True
    LOGGING_LEVEL = logging.DEBUG
    FLOW_ADAPTER_ENABLED = True

class LocalDevelopmentConfigWithWebsocket (LocalDevelopmentConfig):
    # Websocket URL will be looked up using the gateway ID
    WEBSOCKET_CONNECTION_ENABLED = True

class LocalDevelopmentConfigWithSimDPPWebsocketEvents (LocalDevelopmentConfig):
    # Websocket URL will be looked up using the gateway ID
    DPP_HANDLER_ENABLED = True
    DPP_HANDLER_SIMULATE_ONBOARD_RESPONSE_EVENTS = "with success"

class LocalDevelopmentConfigWithLocalWebsocket (LocalDevelopmentConfig):
    WEBSOCKET_URL = "wss://localhost:5050/micronets/v1/ws-proxy/gw/mock-gw"
    WEBSOCKET_CONNECTION_ENABLED = True

class LocalDevelopmentConfigWithSimDPPLocalWebsocketEvents (LocalDevelopmentConfigWithLocalWebsocket,
                                                            LocalDevelopmentConfigWithSimDPPWebsocketEvents):
    # Just a mix of the two
    pass

#
# Wired-only Configs (Note: Wired and wireless are not mutually exclusive. These just don't enable wireless.)
#

class WiredGatewayConfig (ReferenceGatewaySettings):
    # Note: No websocket connection is setup and hostapd control is disabled. Just DHCP and flow adapter control
    DEBUG = False
    LOGGING_LEVEL = logging.INFO
    LOGFILE_MODE = 'a'
    FLOW_ADAPTER_ENABLED = True

class WiredGatewayDebugConfig (WiredGatewayConfig):
    DEBUG = True
    LOGGING_LEVEL = logging.DEBUG
    LOGFILE_MODE = 'w'  # 'w' clears the log at startup, 'a' appends to the existing log file

class WiredGatewayConfigWithWebsocketLookup (WiredGatewayConfig):
    WEBSOCKET_CONNECTION_ENABLED = True

#
# Wireless Configs
#

class WirelessGatewayConfig (ReferenceGatewaySettings):
    # Note: No websocket connection is setup
    DPP_HANDLER_ENABLED = True
    FLOW_ADAPTER_ENABLED = True
    HOSTAPD_ADAPTER_ENABLED = True
    DEBUG = False
    LOGGING_LEVEL = logging.INFO
    LOGFILE_MODE = 'a'  # append to the existing log file

class WirelessGatewayConfigWithWebsocket (WirelessGatewayConfig):
    WEBSOCKET_CONNECTION_ENABLED = True

class WirelessGatewayDebugConfig (WirelessGatewayConfig):
    DEBUG = True
    LOGGING_LEVEL = logging.DEBUG
    LOGFILE_MODE = 'w'  # clears the log at startup

class WirelessGatewayDebugConfigNoLogfile (WirelessGatewayDebugConfig):
    LOGFILE_PATH = None

class WirelessGatewayDebugConfigWithWebsocket (WirelessGatewayDebugConfig, WirelessGatewayConfigWithWebsocket):
    pass

class NetreachDevelopmentConfig (LocalDevelopmentConfig, NetreachDefaultSettings):
    DEBUG = True
    LOGGING_LEVEL = logging.DEBUG
    LOGFILE_MODE = 'w'  # clears the log at startup

class NetreachDebugConfig (WirelessGatewayDebugConfig, NetreachDefaultSettings):
    pass

class NetreachDebugConfigNoLogFile (WirelessGatewayDebugConfig, NetreachDefaultSettings):
    LOGFILE_PATH = None
    DPP_HANDLER_ENABLED = False

#
# The default configuration (default for the /lib/systemd/system/micronets-gw.service file)
#
class DefaultConfig (NetreachDebugConfig):
    pass

