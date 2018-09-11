import os, sys, pathlib, logging

app_dir = os.path.abspath (os.path.dirname (__file__))

class BaseConfig:
    LOGFILE_PATH = "micronets-dhcp.log"
    LOGFILE_MODE = 'w'  # 'w' clears the log at startup, 'a' appends to the existing log file
    LOGGING_LEVEL = logging.DEBUG
    SECRET_KEY = os.environ.get ('SECRET_KEY') or 'A SECRET KEY'
    LISTEN_HOST = "0.0.0.0"
    LISTEN_PORT = 5000
    MIN_DHCP_UPDATE_INTERVAL_S = 5
    DEFAULT_LEASE_PERIOD = '10m'
    SERVER_BIN_DIR = os.path.dirname (os.path.abspath (sys.argv [0]))
    WEBSOCKET_SERVER_ADDRESS = "localhost"
    WEBSOCKET_SERVER_PORT = 5050
    WEBSOCKET_SERVER_PATH = '/micronets/v1/ws-proxy/micronets-gw-0001'
    WEBSOCKET_TLS_CERTKEY_FILE = pathlib.Path (__file__).parent.joinpath ('lib/micronets-gw-service.pkeycert.pem')
    WEBSOCKET_TLS_CA_CERT_FILE = pathlib.Path (__file__).parent.joinpath ('lib/micronets-ws-root.cert.pem')

    ##### Flask-Mail configurations #####
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get ('MAIL_USERNAME') or 'xyz@gmail.com'
    MAIL_PASSWORD = os.environ.get ('MAIL_PASSWORD') or 'password'
    MAIL_DEFAULT_SENDER = MAIL_USERNAME

class BaseMockConfig (BaseConfig):
    DHCP_ADAPTER = "Mock"

class MockDevelopmentConfig (BaseMockConfig):
    LISTEN_HOST = "127.0.0.1"
    LOGFILE_PATH = None
    LOGFILE_MODE = None
    DEBUG = True

class MockTestingConfig (BaseMockConfig):
    """For testing with the mock adapter on all interfaces"""
    WEBSOCKET_SERVER_ADDRESS = "74.207.229.106"
    USE_MOCK_DHCP_CONFIG = True
    DEBUG = True

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
    DEBUG = True

class IscProductionConfig (BaseIscDhcpConfig):
    DEBUG = False
    LOGGING_LEVEL = logging.INFO

class BaseDnsmasqConfig (BaseConfig):
    DHCP_ADAPTER = "DnsMasq"
    DNSMASQ_CONF_FILE = '/etc/dnsmasq.d/micronets'
    DNSMASQ_RESTART_COMMAND = ['sudo','/etc/init.d/dnsmasq','restart']

class DnsmasqDevelopmentConfig (BaseDnsmasqConfig):
    LISTEN_HOST = "127.0.0.1"
    LOGFILE_PATH = None
    LOGFILE_MODE = None
    DNSMASQ_CONF_FILE = 'doc/dnsmasq-config.sample'
    DNSMASQ_RESTART_COMMAND = []
    DEBUG = True

class DnsmasqTestingConfig (BaseDnsmasqConfig):
    WEBSOCKET_SERVER_ADDRESS = "74.207.229.106"
    DEBUG = True

class DnsmasqProductionConfig (BaseDnsmasqConfig):
    WEBSOCKET_SERVER_ADDRESS = "74.207.229.106"
    DEBUG = False
    LOGGING_LEVEL = logging.INFO
