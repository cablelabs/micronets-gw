import re, logging, base64, json, httpx

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization



from .hostapd_adapter import HostapdAdapter

logger = logging.getLogger ('micronets-gw-service-netreach')


class NetreachAdapter(HostapdAdapter.HostapdCLIEventHandler):

    def __init__ (self, config):
        self.serial_number_file = config['NETREACH_ADAPTER_SERIAL_NUM_FILE']
        self.pub_key_file = config['NETREACH_ADAPTER_PUBLIC_KEY_FILE']
        self.priv_key_file = config['NETREACH_ADAPTER_PRIVATE_KEY_FILE']
        self.base_url = config['NETREACH_ADAPTER_CONTROLLER_BASE_URL']
        self.api_token_file = config['NETREACH_ADAPTER_API_KEY_FILE']
        self.token_request_time = 500
        self.api_token = None
        with open(self.serial_number_file, 'rt') as f:
            self.serial_number = f.read().strip()
        with open(self.pub_key_file, 'rb') as f:
            self.pub_key = f.read()
        with open(self.priv_key_file, 'rb') as f:
            self.priv_key = f.read()
        logger.info(f"NetreachAdapter: Base url: {self.base_url}")
        logger.info(f"NetreachAdapter: Serial number: {self.serial_number}")
        logger.info(f"NetreachAdapter: public key: \n{self.pub_key}")
        logger.info(f"NetreachAdapter: private key: \n{self.priv_key}")
        self.login_to_controller()

    def login_to_controller(self):
        logger.info(f"NetreachAdapter: Logging into controller at {self.base_url}")
        data = {
            "serial": self.serial_number,
            "token_expiration_request": self.token_request_time
        }
        data_json = json.dumps(data)

        signature_algorithm = ec.ECDSA(hashes.SHA256())

        key = serialization.load_pem_private_key(self.priv_key, password=None)
        signature = key.sign(data_json.encode(), signature_algorithm)
        enc_signature = base64.b64encode(signature).decode()
        result = httpx.post(f"{self.base_url}/v1/access-points/token",
                            headers={"x-ap-signature": enc_signature},
                            json=data)
        res_json = result.json()
        if result.status_code >= 400:
            raise ValueError(res_json)
        logger.info(f"AP SUCCESSFULLY logged into NetReach Controller ({result})")
        self.api_token = result.json()['token']
        with open(self.api_token_file, 'wt') as f:
            self.priv_key = f.write(self.api_token)
        logger.info(f"Saved NetReach Controller API token to {self.api_token_file}")

    async def handle_hostapd_ready(self):
        logger.info(f"NetreachAdapter.handle_hostapd_ready()")

    async def update (self, micronet_list, device_lists):
        logger.info (f"NetreachAdapter.update ()")
        logger.info (f"NetreachAdapter.update: device_lists: {device_lists}")

