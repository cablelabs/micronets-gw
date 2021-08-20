import re, logging, asyncio, subprocess

from pathlib import Path
from .utils import get_ipv4_hostports_for_hostportspec, parse_portspec, \
                   parse_hostportspec, mac_addr_re, parse_macportspec

from .hostapd_adapter import HostapdAdapter

logger = logging.getLogger ('micronets-gw-service-netreach')


class NetreachAdapter(HostapdAdapter.HostapdCLIEventHandler):

    def __init__ (self, config):
        self.serial_number_file = config['NETREACH_ADAPTER_SERIAL_NUM_FILE']
        self.pub_key_file = config['NETREACH_ADAPTER_PUBLIC_KEY_FILE']
        self.priv_key_file = config['NETREACH_ADAPTER_PRIVATE_KEY_FILE']
        with open(self.serial_number_file, 'rt') as f:
            self.serial_number = f.read().strip()
        with open(self.pub_key_file, 'rt') as f:
            self.pub_key = f.read()
        with open(self.priv_key_file, 'rt') as f:
            self.priv_key = f.read()
        logger.info (f"NetreachAdapter: Serial number: {self.serial_number}")
        logger.info (f"NetreachAdapter: public key: \n{self.pub_key}")
        logger.info (f"NetreachAdapter: private key: \n{self.priv_key}")

    async def handle_hostapd_ready(self):
        logger.info(f"NetreachAdapter.handle_hostapd_ready()")

    async def update (self, micronet_list, device_lists):
        logger.info (f"NetreachAdapter.update ()")
        logger.info (f"NetreachAdapter.update: device_lists: {device_lists}")

