# Copyright (c) 2022 Cable Television Laboratories, Inc. ("CableLabs")
#                    and others.  All rights reserved.
#
# Licensed in accordance of the accompanied LICENSE.txt or LICENSE.md
# file in the base directory for this project. If none is supplied contact
# CableLabs for licensing terms of this software.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging, base64, json, httpx, re, asyncio, time, random, uuid

from app import get_conf_model
from ipaddress import IPv4Network, IPv4Address, AddressValueError, NetmaskValueError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import paho.mqtt.client as mqtt
from urllib import parse as urllib_dot_parse
from quart import jsonify
from pathlib import Path
from .utils import short_uuid, ip_for_interface, mac_for_interface
from .netreach_ap_net_manager import NetreachApNetworkManager
from .hostapd_adapter import HostapdAdapter

logger = logging.getLogger ('netreach-adapter')


class NetreachAdapter(HostapdAdapter.HostapdCLIEventHandler):

    def __init__ (self, config):
        HostapdAdapter.HostapdCLIEventHandler.__init__(self, ("AP-STA"))
        self.debug = config.get('DEBUG')
        self.serial_number_file = config['NETREACH_ADAPTER_SERIAL_NUM_FILE']
        self.reg_token_file = config['NETREACH_ADAPTER_REG_TOKEN_FILE']
        self.pub_key_file = config['NETREACH_ADAPTER_PUBLIC_KEY_FILE']
        self.priv_key_file = config['NETREACH_ADAPTER_PRIVATE_KEY_FILE']
        self.wifi_interface = config['NETREACH_ADAPTER_WIFI_INTERFACE']
        self.ssid_override_file = config['NETREACH_ADAPTER_SSID_OVERRIDE_FILE']
        self.geolocation = config.get('NETREACH_ADAPTER_GEOLOCATION')
        self.management_address = config.get('NETREACH_ADAPTER_MAN_ADDRESS')
        self.management_interface = config.get('NETREACH_ADAPTER_MAN_INTERFACE')
        self.controller_base_url = config['NETREACH_ADAPTER_CONTROLLER_BASE_URL']
        self.api_token_file = config['NETREACH_ADAPTER_API_KEY_FILE']
        self.token_request_time = config['NETREACH_ADAPTER_API_KEY_REFRESH_DAYS']
        self.mqtt_broker_url = config.get('NETREACH_ADAPTER_MQTT_BROKER_URL') # Optional
        self.mqtt_ca_certs = config.get('NETREACH_ADAPTER_MQTT_CA_CERTS')
        self.connection_startup_delay_s = config.get('NETREACH_ADAPTER_CONN_START_DELAY_S')
        self.connection_retry_s = config.get('NETREACH_ADAPTER_CONN_RETRY_S')
        self.use_device_pass = bool(config.get('NETREACH_ADAPTER_USE_DEVICE_PASS', "False"))
        self.psk_cache_enabled = bool(config.get('NETREACH_ADAPTER_PSK_CACHE_ENABLED', "True"))
        self.psk_cache_expire_s = config.get('NETREACH_ADAPTER_PSK_CACHE_EXPIRE_S', 120)
        self.device_mtu = config.get('NETREACH_ADAPTER_DEVICE_MTU', 0)
        self.set_connected_on_associated = config['NETREACH_ADAPTER_SET_CONN_ON_ASSOC']
        self.tunnel_man = NetreachApNetworkManager(config, self)
        self.api_token = None
        self.api_token_refresh = None
        self.ap_uuid = None
        self.ap_name = None
        self.ap_group = None
        self.ssid_list = []
        self.api_token_expiration = None
        self.ap_name = None
        self.ap_enabled = None
        self.logged_in = False
        # Cache PSK lookup results (to avoid DOSing the controller and for local lookups)
        self.psk_lookup_cache = {}
        # Caching device MACs to map hostapd notifications
        self.device_mac_cache = {}
        self.associated_devices = {}
        self.micronets_api_prefix = f"http://{config['LISTEN_HOST']}:{config['LISTEN_PORT']}/gateway/v1"
        self.serial_number = self.serial_number_file.read_text().strip() if self.serial_number_file.exists() else None
        self.reg_token = self.reg_token_file.read_text().strip() if self.reg_token_file.exists() else None
        if not self.management_address and self.management_interface:
            logger.info(f"NetreachAdapter: Setting management address to {self.management_interface} address")
            self.management_address = ip_for_interface(self.management_interface)
        self.ssid_override = self.ssid_override_file.read_text().strip() if self.ssid_override_file.exists() else None
        if not self.geolocation:
            self.geolocation = self._get_geolocation()
        self.pub_key = None
        self.priv_key = None
        self.mqtt_client = None
        self.mqtt_connection_state = "DISCONNECTED"
        self.async_event_loop = asyncio.get_event_loop()
        for (name, val) in vars(self).items():
            if val is not None:
                logger.info(f"NetreachAdapter: {name} = {val}")

    def _get_geolocation(self):
        # TODO: Implement this to retrieve physical location coords
        return {"latitude": "0.0", "longitude": "0.0"}

    async def update (self, micronet_list, device_lists):
        logger.info (f"NetreachAdapter.update ()")
        logger.info (f"NetreachAdapter.update: device_lists: {device_lists}")

    def enqueue_connect(self):
        logger.info(f"NetreachAdapter:enqueue_connect()")
        asyncio.ensure_future(self._kickoff_cloud_connection())

    def set_mqtt_connection_state(self, new_state):
        logger.info(f"NetreachAdapter:set_mqtt_connection_state: Changing state from {self.mqtt_connection_state} to {new_state}")
        self.mqtt_connection_state = new_state

    async def _kickoff_cloud_connection(self):
        logger.info(f"NetreachAdapter:_kickoff_cloud_connection()")

        if not self.serial_number:
            logger.warning(f"NetreachAdapter:_kickoff_cloud_connection: Cannot register with controller - "
                           f"no serial number defined ({self.serial_number_file} does not exist?)")
            raise Exception("No serial number defined - cannot continue")

        if not self.pub_key_file.exists() and not self.reg_token_file.exists():
            logger.warning(f"NetreachAdapter:_kickoff_cloud_connection: Cannot register with controller - "
                           "no keypair or registration token")
            raise Exception("No keypair or registration token configured - cannot continue")

        if self.pub_key_file.exists():
            self.pub_key = self.pub_key_file.read_text()
            self.priv_key = self.priv_key_file.read_text()
            logger.info(f"NetreachAdapter: Found public key file {self.pub_key_file}:\n{self.pub_key}")
        else:
            self.pub_key, self.priv_key = self._generate_ecc_keypair()
            logger.info(f"NetreachAdapter: Generated new key pair. Public key saved to {self.pub_key_file}:\n"
                        f"{self.pub_key}")

        if self.connection_startup_delay_s:
            logger.info(f"NetreachAdapter:_kickoff_cloud_connection: Waiting {self.connection_startup_delay_s} "
                        "seconds to start...")
            await asyncio.sleep(self.connection_startup_delay_s)
        await self._cloud_login_and_setup()
        await self._connect_mqtt_listener_loop()

    def _generate_ecc_keypair(self):
        logger.info(f"NetreachAdapter:_generate_ecc_keypair()")
        curve = ec.SECP256R1()
        private_value = int(random.random()*pow(10, 50))
        priv_key = ec.derive_private_key(private_value, curve, default_backend())
        pub_key = priv_key.public_key()

        private_pem = priv_key.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.TraditionalOpenSSL,
                                             serialization.NoEncryption()).decode()
        public_pem = pub_key.public_bytes(serialization.Encoding.PEM,
                                          format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        with open(self.priv_key_file, 'wt') as f:
            f.write(private_pem)
            logger.info(f"NetreachAdapter:_generate_ecc_keypair: Wrote private key to {self.priv_key_file}")

        with open(self.pub_key_file, 'wt') as f:
            f.write(public_pem)
            logger.info(f"NetreachAdapter:_generate_ecc_keypair: Wrote public key to {self.pub_key_file}")

        return public_pem, private_pem

    async def _register_ap(self):
        async with httpx.AsyncClient() as httpx_client:
            logger.info(f"NetreachAdapter._register_ap: Attempting to register AP using registration token "
                        f"{self.reg_token[0:6]}...{self.reg_token[-6:]}")

            registration_request = {"publicKey": self.pub_key,
                                    "managementAddress": self.management_address,
                                    "geolocation": self.geolocation}

            logger.info(f"NetreachAdapter._register_ap: Registration request: {registration_request}")
            headers = {"x-registration-token": self.reg_token,
                       "content-type": "application/json"}
            response = await httpx_client.post(f"{self.controller_base_url}/v1/access-points/register",
                                               headers=headers,
                                               json=registration_request)
            logger.info(f"NetreachAdapter._register_ap: Registration response: {response.status_code}: {response.text}")
            if response.status_code != 200:
                raise Exception(f"Failed to register AP with reg token {self.reg_token[0:8]}...{self.reg_token[-8:]}")
            res_json = response.json()
            resp_serial = res_json['serial']
            if resp_serial != self.serial_number:
                logger.warning(f"NetreachAdapter._register_ap: Registration serial number mismatch: "
                               f"Found {resp_serial}, expecting {self.serial_number}")

        logger.info(f"NetreachAdapter._register_ap: Successfully registered AP with pubkey \n{self.pub_key}")

    async def _cloud_login_and_setup(self):
        logger.info(f"NetreachAdapter:_cloud_login_and_setup()")

        while not self.logged_in:
            try:
                if self.reg_token:
                    logger.info(f"NetreachAdapter: _cloud_login_and_setup: Found registration token "
                                f"{self.reg_token[0:6]}...{self.reg_token[-6:]}")
                    await self._register_ap()
                    self.reg_token = None
                    self.reg_token_file.unlink()

                await self._login_to_controller()
                self.logged_in = True
                cur_ap_info = await self._get_ap_info()
                await self._update_ap_info(cur_ap_info)
                (ap_group, ap_services, ap_service_devices) = await self._get_services_for_ap()
                self.ap_group = ap_group
                await self._setup_micronets_for_ap(ap_services, ap_service_devices)
                if self.tunnel_man:
                    await self.tunnel_man.init_ap_online(str(self.ap_uuid), self.ap_group,
                                                         ap_services, ap_service_devices)
                await self._configure_hostapd(ap_group)
            except Exception as ex:
                logger.info(f"NetreachAdapter:_cloud_login_and_setup: Error performing controller login/setup: {ex}",
                            exc_info=self.debug)
                logger.info(f"NetreachAdapter:_cloud_login_and_setup: Sleeping {self.connection_retry_s} seconds...")
                await asyncio.sleep(self.connection_retry_s)
                logger.info(f"NetreachAdapter:_cloud_login_and_setup: Retrying controller login/setup")

    async def _connect_mqtt_listener_loop(self, wait_for_s=0):
        logger.info(f"NetreachAdapter:_connect_mqtt_listener_loop(wait_for_s={wait_for_s})")
        while self.mqtt_connection_state == "DISCONNECTED":
            try:
                if wait_for_s:
                    logger.info(f"NetreachAdapter:_connect_mqtt_listener_loop: Waiting {wait_for_s} seconds to connect")
                    await asyncio.sleep(wait_for_s)
                self._connect_mqtt_listener()
                # Note: A lot of errors can happen async. So getting through here doesn't guarantee connect.
                #       But it should ensure we at least get CONNECT/DISCONNECT notifications that can drive
                #       retry logic.
            except Exception as ex:
                logger.info(f"NetreachAdapter:_connect_mqtt_listener_loop: Error while connecting MQTT: {ex}")
                logger.info(f"NetreachAdapter:_connect_mqtt_listener_loop: Sleeping {self.connection_retry_s}...")
                await asyncio.sleep(self.connection_retry_s)
                logger.info(f"NetreachAdapter:_connect_mqtt_listener_loop: Retrying MQTT connection establishment")

    async def _login_to_controller(self):
        logger.info(f"NetreachAdapter:_login_to_controller: Logging into controller at {self.controller_base_url}")

        data = {
            "serial": self.serial_number,
            "token_expiration_request": self.token_request_time
        }
        data_json = json.dumps(data)

        signature = self._sign_data(data_json.encode())
        enc_signature = base64.b64encode(signature).decode()
        async with httpx.AsyncClient() as httpx_client:
            response = await httpx_client.post(f"{self.controller_base_url}/v1/access-points/token",
                                               headers={"x-ap-signature": enc_signature,
                                                        "content-type": "application/json"},
                                               data=data_json)
            res_json = response.json()
            if response.status_code >= 400:
                logger.warning(f"NetreachAdapter:_login_to_controller: FAILED login to NetReach Controller: "
                               f"{response.status_code}: {response.text}")
                raise ValueError(res_json)
            logger.info(f"NetreachAdapter:_login_to_controller: AP SUCCESSFULLY logged into NetReach Controller")
            self.ap_uuid = uuid.UUID(res_json['uuid'])
            self.api_token = res_json['token']
            self.api_token_refresh = res_json['refresh_token']
            # TODO: Implement logoff/login to refresh API token
            self.api_token_expiration = res_json['expires']
            if not self.mqtt_broker_url:
                self.mqtt_broker_url = res_json['mqttProxyUrl']

            with open(self.api_token_file, 'wt') as f:
                f.write(self.api_token)
            logger.info(f"NetreachAdapter:_login_to_controller: Saved NetReach Controller API token to {self.api_token_file}")

    def _sign_data(self, data):
        key = serialization.load_pem_private_key(self.priv_key.encode(), password=None)
        signature_algorithm = ec.ECDSA(hashes.SHA256())
        return key.sign(data, signature_algorithm)

    def _connect_mqtt_listener(self):
        logger.debug(f"NetreachAdapter:_connect_mqtt_listener()")
        logger.info(f"NetreachAdapter:_connect_mqtt_listener: Connecting with MQTT broker at {self.mqtt_broker_url}")

        # Instantiate mqtt broker.  This is a sync implementation.  Async implementations are available
        mqtt_client = mqtt.Client(str(self.ap_uuid))
        mqtt_client.username_pw_set(str(self.ap_uuid), self.api_token)

        mqtt_client.on_connect = self._on_mqtt_connect
        mqtt_client.on_message = self._on_mqtt_message
        mqtt_client.on_disconnect = self._on_mqtt_disconnect
        mqtt_client.on_log = self._on_mqtt_log

        url_parts = urllib_dot_parse.urlparse(self.mqtt_broker_url)
        if url_parts.scheme == "mqtt" or url_parts.scheme == "mqtts":
            if url_parts.scheme == "mqtts":
                mqtt_client.tls_set(ca_certs=self.mqtt_ca_certs)
                # mqtt_client.tls_insecure_set(True)
            logger.info(f"NetreachAdapter:_connect_mqtt_listener: Connecting to MQTT broker at {url_parts.hostname}:{url_parts.port}")
            mqtt_client.connect(url_parts.hostname, url_parts.port, keepalive=60)
        else:
            raise Exception(f"Unrecognized mqtt url scheme {self.mqtt_broker_url}")

        self.set_mqtt_connection_state("CONNECTING")
        self.mqtt_client = mqtt_client
        self.mqtt_client.loop_start()

    async def _get_ap_info(self):
        # Retrieve info on myself
        async with httpx.AsyncClient() as httpx_client:
            response = await httpx_client.get(f"{self.controller_base_url}/v1/access-points/{self.ap_uuid}",
                                              headers={"x-api-token": self.api_token})
            ap_info = response.json()
            logger.info(f"NetreachAdapter:_login_to_controller: Got AP Info: {ap_info}")
            self.ap_name = ap_info['name']
            self.ap_enabled = ap_info['enabled']
            self.ap_serial = ap_info['serial']
            return ap_info

    async def _get_services_for_ap(self):
        # Return the AP Group, a list of all the services currently configured on the AP
        # and a dict keyed off the Service uuid mapped to an array of Device entries

        async with httpx.AsyncClient() as httpx_client:
            # Get the AP Group(s)
            response = await httpx_client.get(f"{self.controller_base_url}/v1/ap-groups?apUuid={self.ap_uuid}",
                                              headers={"x-api-token": self.api_token})
            if response.status_code != 200:
                logger.warning(f"NetreachAdapter._get_services_for_ap: FAILED retrieving AP list for "
                               f"AP {self.ap_uuid} ({response.status_code}): {response.text}")
                raise ValueError(response.status_code)
            ap_groups = response.json()['results']
            if len(ap_groups) == 0:
                logger.info(f"NetreachAdapter:_get_services_for_ap {self.ap_name} ({self.ap_uuid}) is not assigned to an AP Group. Nothing to setup.")
            else:
                ap_group = ap_groups[0]
            logger.info(f"NetreachAdapter:_get_services_for_ap: AP Group \"{ap_group['name']}\" ({ap_group['uuid']})")

            # Get the Services for the AP Group
            ap_group_uuid = ap_group['uuid']
            response = await httpx_client.get(f"{self.controller_base_url}/v1/services?apGroupUuid={ap_group_uuid}",
                                              headers={"x-api-token": self.api_token})
            if response.status_code != 200:
                logger.warning(f"NetreachTunnelManager.get_aps_for_group: FAILED retrieving Service list for "
                               f"AP Group \"{ap_group['name']}\" ({ap_group['uuid']}). "
                               f"Returned status {response.status_code} ({response.text})")
                raise ValueError(response.status_code)
            service_list = response.json()['results']
            logger.info(f"NetreachAdapter:_get_services_for_ap: Found {len(service_list)} services in AP Group "
                        f"\"{ap_group['name']}\" ({ap_group['uuid']})")

            # Get the Devices for each Service
            service_device_list = {}
            for service in service_list:
                service_uuid = service['uuid']
                service_name = service['name']
                response = await httpx_client.get(f"{self.controller_base_url}/v1/services/{service_uuid}/devices",
                                                  headers={"x-api-token": self.api_token})
                if response.status_code != 200:
                    logger.warning(f"Could not retrieve devices for service {service_name} ({service_uuid}) - "
                                   f"Result was {response.status_code} ({response.reason_phrase})")
                    continue
                device_list = response.json()['results']
                logger.info(f"NetreachAdapter:_get_services_for_ap: Found {len(device_list)} devices for service "
                            f"\"{service_name}\" ({service_uuid})")
                service_device_list[service_uuid] = device_list

        return ap_group, service_list, service_device_list

    async def _update_ap_info(self, cur_ap_info):
        # Currently this will check/update the management address and geolocation
        cur_man_address = cur_ap_info.get('managementAddress')
        cur_geo_location = cur_ap_info.get('geolocation')

        actual_geolocation = self._get_geolocation()

        if cur_man_address == self.management_address and cur_geo_location == actual_geolocation:
            return

        async with httpx.AsyncClient() as httpx_client:
            logger.info(f"NetreachAdapter._update_ap_info: Updating management address from "
                        f"{cur_man_address} to {self.management_address}")
            logger.info(f"NetreachAdapter._update_ap_info: Updating geolocation from "
                        f"{cur_geo_location} to {actual_geolocation}")

            update_request = {
                "managementAddress": self.management_address,
                "geolocation": self.geolocation,
                "status": "ONLINE"
            }
            response = await httpx_client.patch(f"{self.controller_base_url}/v1/access-points/{self.ap_uuid}",
                                                headers={"x-api-token": self.api_token},
                                                json=update_request)
            if response.status_code != 200:
                raise Exception(f"Failed to update AP with {update_request}")

            ap_info = response.json()
            logger.info(f"NetreachAdapter:_update_ap_info: Got updated AP Info: {ap_info}")
            self.ap_name = ap_info['name']
            self.ap_enabled = ap_info['enabled']
            resp_serial = ap_info['serial']
            if resp_serial != self.serial_number:
                logger.warning(f"NetreachAdapter._update_ap_info: Registration serial number mismatch: "
                               f"Found {resp_serial}, expecting {self.serial_number}")

        logger.info(f"NetreachAdapter._register_ap: Successfully updated AP management address/geolocation")

    async def _refresh_all_services(self):
        logger.info(f"NetreachAdapter:_refresh_all_services()")
        (ap_group, ap_services, ap_service_devices) = await self._get_services_for_ap()
        self.ap_group = ap_group
        self.psk_lookup_cache.clear()
        await self._setup_micronets_for_ap(ap_services, ap_service_devices)
        await self._configure_hostapd(ap_group)
        if self.tunnel_man:
            await self.tunnel_man.update_ap_network(ap_services, ap_service_devices)

    async def _setup_micronets_for_ap(self, service_list, service_device_list):
        logger.info(f"NetreachAdapter:_setup_micronets_for_ap {self.ap_name} ({self.ap_uuid})")

        async with httpx.AsyncClient() as micronets_api:
            # Clear out all the micronets - we're going to rebuild them
            result = await micronets_api.delete(f"{self.micronets_api_prefix}/micronets")

            logger.info(f"NetreachAdapter:_setup_micronets_for_ap:  Configuring {len(service_list)} services "
                        f"for AP Group \"{self.ap_group['name']}\" ({self.ap_group['uuid']})")

            for service in service_list:
                service_enabled = service['enabled']
                service_uuid = service['uuid']
                service_name = service['name']
                micronet_subnet = IPv4Network(service['micronetSubnet'], strict=True)
                micronet_vlan = int(service['vlan'])
                # TODO: Replace this with gateway reference from Service object (see issue #15)
                micronet_gateway = service['micronetGateway']
                logger.info(f"NetreachAdapter:_setup_micronets_for_ap: Service \"{service_name}\" ({service_uuid})")
                logger.info(f"NetreachAdapter:_setup_micronets_for_ap:  micronet id {service_uuid} vlan {micronet_vlan}")
                if not (micronet_subnet and micronet_vlan):
                    logger.info(f"NetreachAdapter:_setup_micronets_for_ap: netreach Service {service_name} "
                                f"({service_uuid}) does not have a micronet ID/vlan - SKIPPING")
                    pass
                micronet_subnet_addr = micronet_subnet.network_address
                micronet_subnet_netmask = micronet_subnet.netmask
                logger.info(f"NetreachAdapter:_setup_micronets_for_ap:    subnet {micronet_subnet} "
                            f"({micronet_subnet_addr}/{micronet_subnet_netmask})")
                logger.info(f"NetreachAdapter:_setup_micronets_for_ap:    micronet gateway {micronet_gateway}")

                micronet_to_add = {
                    "micronet": {
                        "micronetId": service_uuid,
                        "name": service_name,
                        "ipv4Network": {"network": str(micronet_subnet_addr), "mask": str(micronet_subnet_netmask),
                                        "gateway": micronet_gateway},
                        "interface": self.wifi_interface,
                        "vlan": micronet_vlan,
                        "nameservers": [micronet_gateway]
                    }
                }

                if self.device_mtu:
                    micronet_to_add['micronet']['mtu'] = self.device_mtu
                logger.info(f"NetreachAdapter:_setup_micronets_for_ap: micronet: {json.dumps(micronet_to_add, indent=4)}")
                result = await micronets_api.post(f"{self.micronets_api_prefix}/micronets",
                                                  json=micronet_to_add)
                if result.is_error:
                    logger.warning(f"Could not add micronet for service \"{service_name}\" ({service_uuid}) - "
                                   f"Result was {result.status_code} ({result.reason_phrase})")
                    continue

                nr_device_list = service_device_list[service_uuid]
                micronet_devices = []

                for device in nr_device_list:
                    device_id = device['uuid']
                    device_name = device['name']
                    logger.info(f"NetreachAdapter:_setup_micronets_for_ap:   device \"{device_name}\" ({device_id})")
                    device_enabled = device['enabled']
                    device_mac = device.get('macAddress')
                    device_ip = device['ipAddress']
                    device_bootstrapping_info = device.get('bootstrappingInfo')
                    device_psk_or_pass = device['passphrase'] if self.use_device_pass else device['psks'][0]
                    logger.info(f"NetreachAdapter:_setup_micronets_for_ap:   device \"{device_name}\" "
                                f"mac {device_mac} ip {device_ip}")
                    device_to_add = {
                        "deviceId": device_id,
                        "name": device_name,
                        "networkAddress": {"ipv4": device_ip}
                    }
                    if device_mac:
                        device_mac = device_mac.lower()
                        device_to_add['macAddress'] = device_mac
                        mac_cache_entry = {"updated": int(time.time()), "serviceUuid": service_uuid,
                                           "deviceUuid": device_id}
                        self.device_mac_cache[device_mac] = mac_cache_entry
                        logger.info(f"NetreachAdapter._setup_micronets_for_ap:   Adding mac cache entry for {device_mac}: "
                                    + str(mac_cache_entry))
                    if not device_psk_or_pass:
                        logger.info(f"NetreachAdapter:_setup_micronets_for_ap:   Device {device_id} (\"{device_name}\") "
                                    f" does not have a PSK ({device_id})")
                        continue
                    if device_bootstrapping_info:
                        device_to_add['dppBootstrapUri'] = device_bootstrapping_info
                    if not device_enabled or not service_enabled:
                        # Poison the PSK
                        device_psk_or_pass = "DISABLED-" + str(random.getrandbits(24)) + "-" + device_psk_or_pass
                    device_to_add['psk'] = device_psk_or_pass
                    micronet_devices.append(device_to_add)

                micronet_device_list = {"devices": micronet_devices}
                logger.info(f"NetreachAdapter:_setup_micronets_for_ap: Micronet devices for service {service_name}: \n"
                            f"{json.dumps(micronet_device_list, indent=4)}")
                result = await micronets_api.post(f"{self.micronets_api_prefix}/micronets/{service_uuid}/devices",
                                                  json=micronet_device_list)
                if result.is_error:
                    logger.warning(f"NetreachAdapter:_setup_micronets_for_ap: Could not add micronet devices "
                                   f"for service {service_name} ({service_uuid}) - Result was {result.reason_phrase}")
                    continue

    async def _configure_hostapd(self, ap_group):
        logger.info(f"NetreachAdapter:_configure_hostapd({ap_group})")
        if not ap_group:
            ssid_list = None
        else:
            ssid_list = ap_group['ssid'] if not self.ssid_override else [self.ssid_override]

        if ssid_list:
            # Note: This only deals with one SSID currently
            ssid = ssid_list[0]

            cur_ssids = self.hostapd_adapter.get_status_var("ssid")
            if cur_ssids[0] == ssid:
                logger.info(f"NetreachAdapter:_configure_hostapd: AP SSID already set to \"{ssid}\" "
                            f"- nothing to do")
                return

            logger.info(f"NetreachAdapter:_configure_hostapd): Changing AP SSID from \"{cur_ssids[0]}\" "
                        f"to \"{ssid}\"")
            set_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.SetCLICommand("ssid", ssid))
            if not await set_cmd.was_successful():
                response = await set_cmd.get_response()
                raise Exception(f"Could not set ssid to {ssid}: {response}")

            reload_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.ReloadCLICommand())
            if not await reload_cmd.was_successful():
                raise Exception(f"Error issuing hostapd reload after setting SSID to {ssid}")
            await self.hostapd_adapter.refresh_status_vars()

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        # handles the connecting event of the mqtt broker
        logger.info(f"NetreachAdapter:_on_mqtt_connect(client:{client},userdata:{userdata},flags:{flags},rc:{rc})")
        asyncio.set_event_loop(self.async_event_loop)
        # subscribe to the event topic
        ap_topic = f'access-points/{self.ap_uuid}/events'
        client.subscribe(f'access-points/{self.ap_uuid}/events', qos=1)
        client.subscribe(f'access-points/{self.ap_uuid}/data', qos=1)
        self.set_mqtt_connection_state("CONNECTED")

    def _on_mqtt_disconnect(self, client, userdata, rc):
        # Notifies the controller of broker disconnection
        logger.info(f"NetreachAdapter:_on_disconnect(client:{client},userdata:{userdata},rc:{rc})")
        self.set_mqtt_connection_state("DISCONNECTED")
        # Note: The MQTT client is supposed to attempt reconnect on its own. So considering this
        #       handler a no-op
        # asyncio.ensure_future(self._connect_mqtt_listener_loop(wait_for_s=self.connection_retry_s),
        #                       loop=self.async_event_loop)

    def _on_mqtt_message(self, client, userdata, message):
        # handles all incoming mqtt messages
        logger.info(f"NetreachAdapter:_on_mqtt_message(client:{client},userdata:{userdata},message:{message})")
        try:
            msg = json.loads(message.payload.decode("utf-8"))

            if not type(msg) is dict:
                logger.info(f"NetreachAdapter:_on_mqtt_message: Received MQTT message without JSON payload")
                return

            # parse out topic uuids
            topic_parts = self._parse_mqtt_topic(message.topic)

            if "events" in topic_parts:
                self._handle_event_topic(client, userdata, msg)
        except Exception as e:
            print(message.topic)
            print(e)
            raise e

    def _on_mqtt_log(self, client, userdata, message):
        # handles all incoming mqtt messages
        logger.info(f"NetreachAdapter:_on_mqtt_log(client:{client},userdata:{userdata},message:{message})")

    def _report_event_success(self, message):
        logger.info(f"NetreachAdapter:_report_event_success: message={message}, uuid={message['eventUuid']})")

    def _report_event_failure(self, message, payload):
        logger.info(f"NetreachAdapter:_report_event_failure: message={message}, uuid={message['eventUuid']}, payload={payload})")

    def _parse_mqtt_topic(self, topic):
        logger.info(f"NetreachAdapter:_parse_mqtt_topic({topic})")
        out = {}
        topic_split = topic.split("/")

        for idx, part in enumerate(topic_split):
            # handle uuid case

            if self._validate_uuid(part):
                out[topic_split[idx-1]] = part

            # handle event special case
            if part == "events" and idx+1 < len(topic_split):
                out[part] = topic_split[idx+1]

            # handle last topic part
            if idx == len(topic_split)-1:
                out[part] = None

        return out

    def _handle_data_topic(self, client, userdata, msg):
        pass

    def _handle_event_topic(self, client, userdata, msg):
        event_dict = {
            "AP_PARAMETER_UPDATE": self._handle_ap_update,
            "AP_INCLUDED_IN_AP_GROUP": self._handle_ap_included_in_ap_group,
            "AP_EXCLUDED_FROM_AP_GROUP": self._handle_ap_excluded_from_ap_group,
            "AP_PROVISON_SERVICE": self._handle_ap_provision_service,
            "AP_UPDATE_SERVICE": self._handle_ap_update_service,
            "AP_REMOVE_SERVICE": self._handle_ap_remove_service,
            "AP_PROVISION_DEVICE": self._handle_ap_provision_device,
            "AP_UPDATE_DEVICE": self._handle_ap_update_device,
            "AP_REMOVE_DEVICE": self._handle_ap_remove_device,
        }

        if not msg["event"] in event_dict:
            raise Exception(f"No Event: {msg['event']}")

        # handle the event async
        asyncio.run_coroutine_threadsafe(event_dict[msg["event"]](client, msg), self.async_event_loop)

    def _send_status(self, status):
        pass
        # http.patch(f'/access-points/{access_point.get_attribute("uuid")}', data={
        #     "status": status
        # })

    def _validate_uuid(self, uuid_str):
        try:
            return int(uuid.UUID(uuid_str).version) > 0
        except ValueError:
            return False

    async def _handle_ap_update(self, client, message):
        logger.info(f"NetreachAdapter:_handle_ap_update()")
        self._report_event_success(message)
        await self._refresh_all_services()

    async def _handle_ap_included_in_ap_group(self, client, message):
        logger.info(f"NetreachAdapter: handle_ap_included_in_ap_group()")
        try:
            await self._refresh_all_services()
            # TODO: Move failure/success reporting
            # Report Success
            self._report_event_success(message)
        except ValueError as e:
            self._report_event_failure(message, {
                "uuidList": ["uuid_of_failed_link"],
                "reasonList": [str(e)]
            })

    async def _handle_ap_excluded_from_ap_group(self, client, message):
        logger.info(f"NetreachAdapter: handle_ap_excluded_from_ap_group()")
        try:
            await self._refresh_all_services()
            # TODO: Move failure/success reporting
            # Report Success
            self._report_event_success(message)
        except ValueError as e:
            self._report_event_failure(message, {
                "uuidList": ["uuid_of_failed_link"],
                "reasonList": [str(e)]
            })

    async def _handle_ap_provision_service(self, client, message):
        logger.info(f"NetreachAdapter:_handle_ap_provision_service()")
        try:
            await self._refresh_all_services()
            # TODO: Move failure/success reporting
            # Report Success
            self._report_event_success(message)
        except ValueError as e:
            self._report_event_failure(message, {
                "uuidList": ["uuid_of_failed_link"],
                "reasonList": [str(e)]
            })

    async def _handle_ap_update_service(self, client, message):
        logger.info(f"NetreachAdapter:_handle_ap_update_service()")
        try:
            await self._refresh_all_services()
            # TODO: Move failure/success reporting
            # Report Success
            self._report_event_success(message)
        except ValueError as e:
            self._report_event_failure(message, {
                "uuidList": ["uuid_of_failed_link"],
                "reasonList": [str(e)]
            })

    async def _handle_ap_remove_service(self, client, message):
        logger.info(f"NetreachAdapter:_handle_ap_remove_service()")
        try:
            await self._refresh_all_services()
            # TODO: Move failure/success reporting
            # Report Success
            self._report_event_success(message)
        except ValueError as e:
            self._report_event_failure(message, {
                "uuidList": ["uuid_of_failed_link"],
                "reasonList": [str(e)]
            })

    async def _handle_ap_provision_device(self, client, message):
        logger.info(f"NetreachAdapter:_handle_ap_provision_device({message})")
        try:
            await self._refresh_all_services()
            # Report Success
            # Clear the PSK lookup cache (in case the device being added has a cache fail)
            logger.info(f"NetreachAdapter:_handle_ap_provision_device: Clearing the PSK lookup cache")
            self.psk_lookup_cache = {}
            # TODO: Just clear failures?
            self._report_event_success(message)
        except ValueError as e:
            self._report_event_failure(message, {
                "uuidList": ["uuid_of_failed_link"],
                "reasonList": [str(e)]
            })

    async def _handle_ap_update_device(self, client, message):
        logger.info(f"NetreachAdapter:_handle_ap_update_device({client},{message})")
        try:
            href_components = message['href'].split('/')
            service_id = href_components[2]
            device_id = href_components[4]
            payload = message['payload']
            connected = payload.get("connected") if payload else None
            associated_ap_id = payload.get("associatedApUuid")
            if connected is not None:
                logger.info(f"NetreachAdapter:_handle_ap_update_device: Device status updated for Device {device_id} "
                            f"(Service {service_id})")
                await self._refresh_all_services()
                # await self.tunnel_man.update_ap_network_for_device(device_id, service_id, connected, associated_ap_id)
            else:
                logger.info(f"NetreachAdapter:_handle_ap_update_device: Device record updated for Device {device_id} "
                            f" (Service {service_id})")
                await self._refresh_all_services()
            # TODO: Move failure/success reporting
            # Report Success
            self._report_event_success(message)
        except Exception as e:
            logger.warning(f"NetreachAdapter:_handle_ap_update_device: Caught exception: {e}", exc_info=True)
            self._report_event_failure(message, {
                # TODO
                "uuidList": ["uuid_of_failed_link"],
                "reasonList": [str(e)]
            })

    async def _handle_ap_remove_device(self, client, message):
        logger.info(f"NetreachAdapter:_handle_ap_remove_device({message})")
        try:
            await self._refresh_all_services()
            # TODO: Move failure/success reporting
            async with httpx.AsyncClient() as httpx_client:
                logger.info(f"NetreachAdapter._handle_ap_remove_device: Looking up client object at {message['href']}")
                result = await httpx_client.get(f"{self.controller_base_url}{message['href']}",
                                                headers={"x-api-token": self.api_token})
                response_json = await result.json()
                mac_addr = response_json.get('macAddress')
                if not mac_addr:
                    logger.info(f"NetreachAdapter._handle_ap_remove_device: Could not find mac addr for device {message['href']}")
                else:
                    logger.info(f"NetreachAdapter._handle_ap_remove_device: Removing PSK result cache entry for MAC {mac_addr}")
                    del self.psk_lookup_cache[mac_addr.lower()]
            # Report Success
            self._report_event_success(message)
        except ValueError as e:
            self._report_event_failure(message, {
                "uuidList": ["uuid_of_failed_link"],
                "reasonList": [str(e)]
            })

    async def process_dhcp_lease_event(self, micronet_id, device_id, action, mac_addr, ip_addr):
        logger.info(f"NetreachAdapter.process_dhcp_lease_event({micronet_id}, {device_id}, {action}, {mac_addr}, {ip_addr})")
        if not self.api_token:
            logger.info (f"NetreachAdapter.process_dhcp_lease_event: Cannot process {action} event - the API key has not been established")
            return f"The NetReach API key is not set", 500

        if action == "leaseAcquired":
            await self._update_device_status_and_cache(mac_addr, True, True)
        else:
            logger.info(f"NetreachAdapter.process_dhcp_lease_event: Ignoring action '{action}' for MAC {mac_addr}")

    async def lookup_psk_for_device(self, psk_lookup_fields):
        logger.info(f"NetreachAdapter.lookup_psk_for_device({psk_lookup_fields})")
        # psk_lookup_fields: anonce, snonce, sta_mac, ap_mac, ssid, akmp, pairwise, sta_m2

        sta_mac = psk_lookup_fields['sta_mac'].lower()
        if not self.api_token:
            logger.info(f"NetreachAdapter.lookup_psk_for_device: Internal error "
                        f"looking up device {sta_mac}: the controller API key has not been established")
            return {"detail": "The controller API key is not set"}, 500

        if self.psk_cache_enabled:
            psk_entry = self.psk_lookup_cache.get(sta_mac)
            if psk_entry:
                entry_age_s = int(time.time()) - psk_entry['createTime']
                logger.info(f"NetreachAdapter.lookup_psk_for_device: Found cached PSK lookup entry for MAC {sta_mac}: {psk_entry}")
                logger.info(f"NetreachAdapter.lookup_psk_for_device: Cached PSK lookup entry for MAC {sta_mac} is {entry_age_s}s old")
                if entry_age_s > self.psk_cache_expire_s:
                    # Don't use the entry - it's too old - purge it
                    logger.info(f"NetreachAdapter.lookup_psk_for_device: Removing PSK lookup cache entry due to old age ({self.psk_cache_expire_s}s)")
                    del self.psk_lookup_cache[sta_mac]
                    psk_entry = None
                    # Drop into lookup logic
                else:
                    logger.info(f"NetreachAdapter.lookup_psk_for_device: Using cached PSK lookup entry for MAC {sta_mac}")
                    psk_entry['count'] += 1
                    return (psk_entry['lookupResult'], psk_entry['lookupResultCode'], psk_entry['headers'])

        try:
            # Perform the actual lookup of the PSK with the cloud
            result = httpx.post(f"{self.controller_base_url}/v1/psks/psk-lookup",
                                headers={"x-api-token": self.api_token},
                                json=psk_lookup_fields)
            logger.info(f"NetreachAdapter.lookup_psk_for_device: PSK lookup {'FAILED' if result.is_error else 'SUCCEEDED'}")
            logger.info(f"NetreachAdapter.lookup_psk_for_device: PSK lookup response: {result.text}")
            headers_to_pass = {k: result.headers[k] for k in result.headers.keys() & {"content-type"}}
        except Exception as e:
            return {"detail": f"Unexpected error performing PSK lookup on controller: {str(e)}"}, 500

        if self.psk_cache_enabled:
            # If result is 200, response will have "psk', "vlan", "deviceUuid", and "serviceUuid"
            psk_entry = {"count": 1, "createTime": int(time.time()), "pskFound": not result.is_error,
                         "lookupResultCode": result.status_code, "lookupResult": result.text,
                         "headers": headers_to_pass}
            self.psk_lookup_cache[sta_mac] = psk_entry
        logger.info(f"NetreachAdapter.lookup_psk_for_device: Passing headers: {headers_to_pass}")

        if not result.is_error:
            response_json = result.json()
            cache_entry = {"updated": int(time.time()),
                           "serviceUuid": response_json['serviceUuid'],
                           "deviceUuid": response_json['deviceUuid']}
            self.device_mac_cache[sta_mac] = cache_entry
            logger.info(f"NetreachAdapter.lookup_psk_for_device: Adding mac cache entry for {sta_mac}: {cache_entry}")

        return (result.text, result.status_code, headers_to_pass)

    def register_hostapd_event_handler(self, hostapd_adapter):
        if hostapd_adapter:
            hostapd_adapter.register_cli_event_handler(self)

    async def handle_hostapd_ready(self):
        logger.info(f"NetreachAdapter.handle_hostapd_ready()")
        await self._configure_hostapd(self.ap_group)
        await self._add_connected_stas_to_device_mac_cache()

    async def _add_connected_stas_to_device_mac_cache(self):
        list_sta_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.ListStationsCLICommand())
        sta_macs = await list_sta_cmd.get_sta_macs()
        for sta_mac in sta_macs:
            logger.info(f"NetreachAdapter:_add_connected_stas_to_device_mac_cache: Processing STA MAC {sta_mac}")
            await self._update_device_status_and_cache(sta_mac, True, self.set_connected_on_associated)

    async def handle_hostapd_cli_event(self, event_msg):
        # Note: Handler is registered to receive "AP-STA" events only
        logger.info(f"NetreachAdapter.handle_hostapd_cli_event({event_msg})")
        if not self.api_token:
            logger.info(f"NetreachAdapter.handle_hostapd_cli_event: Cannot process {event_msg} "
                        "event - the API key has not been established")
            return

        event, mac = event_msg.split(' ')
        mac = mac.lower()

        if event == "AP-STA-CONNECTED":
            await self._update_device_status_and_cache(mac, True, self.set_connected_on_associated)
        elif event == "AP-STA-DISCONNECTED":
            await self._update_device_status_and_cache(mac, False, False)
        else:
            logger.warning(f"NetreachAdapter.handle_hostapd_cli_event: Received unknown event '{event_msg}'")
            # If we're getting here, check the pattern provided to the HostapdCLIEventHandler constructor
            return


    async def _update_device_status_and_cache(self, mac, associated, connected) -> None:
        # Note: This method must only be called on authoritative changes in local station state
        #       i.e. This should only be called when a device is known to transition from CONNECTED to DISCONNECTED
        #            or vice-versa
        # The mac cache is for all devices in all services for the associated AP group
        mac_cache_entry = self.device_mac_cache.get(mac)
        if not mac_cache_entry:
            logger.warning(f"NetreachAdapter._update_device_status_and_cache: Could not find {mac} "
                           "in device-to-mac cache")
            return
        service_id = mac_cache_entry['serviceUuid']
        device_id = mac_cache_entry['deviceUuid']

        logger.info(f"NetreachAdapter._update_device_status_and_cache: Found device {device_id} for {mac} "
                    "in device-to-mac cache")

        # The associated device cache is for devices associated with this AP
        if associated:
            cache_entry = {"deviceUuid": device_id, "serviceUuid": service_id, "connectedTime": int(time.time())}
            self.associated_devices[mac] = cache_entry
        else:
            if self.associated_devices.get(mac):
                del self.associated_devices[mac]

        # Now update the Device on the controller
        async with httpx.AsyncClient() as httpx_client:
            device_patch = {"associated": associated, "connected": connected}
            result = await httpx_client.patch(f"{self.controller_base_url}/v1/services/{service_id}/devices/{device_id}",
                                              headers={"x-api-token": self.api_token},
                                              json=device_patch)
            if result.is_error:
                logger.warning(f"NetreachAdapter._update_device_status_and_cache: Could not update status of Device "
                               f"{device_id} in Service {service_id} to {device_patch} on NetReach Controller: "
                               f"{result.reason_phrase} ({result.status_code})")
            else:
                logger.info("NetreachAdapter._update_device_status_and_cache: Updated controller status of Device "
                            f"{device_id} in Service {service_id} to {device_patch}")

    def get_associated_devices(self, service_uuid=None):
        if service_uuid is None:
            return self.associated_devices
        connected_devs = {}
        for mac, entry in self.associated_devices.items():
            if entry['serviceUuid'] == service_uuid:
                connected_devs[mac] = entry
        return connected_devs

    def dump_associated_devices(self, service_uuid=None, prefix="") -> str:
        strcat = ""
        for mac, entry in self.associated_devices.items():
            if service_uuid and entry['serviceUuid'] != service_uuid:
                continue
            strcat += f"{prefix}{mac}: {entry}\n"
        return strcat
