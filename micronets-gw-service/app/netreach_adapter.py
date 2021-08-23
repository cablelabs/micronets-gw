import logging, base64, json, httpx, ssl, asyncio

from ipaddress import IPv4Network, IPv4Address, AddressValueError, NetmaskValueError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import paho.mqtt.client as mqtt
from urllib import parse as urllib_dot_parse
from uuid import UUID

from .hostapd_adapter import HostapdAdapter

logger = logging.getLogger ('micronets-gw-service-netreach')


class NetreachAdapter(HostapdAdapter.HostapdCLIEventHandler):

    def __init__ (self, config):
        self.serial_number_file = config['NETREACH_ADAPTER_SERIAL_NUM_FILE']
        self.pub_key_file = config['NETREACH_ADAPTER_PUBLIC_KEY_FILE']
        self.priv_key_file = config['NETREACH_ADAPTER_PRIVATE_KEY_FILE']
        self.wifi_interface = config['NETREACH_ADAPTER_WIFI_INTERFACE'] # TODO: Think...
        self.base_url = config['NETREACH_ADAPTER_CONTROLLER_BASE_URL']
        self.api_token_file = config['NETREACH_ADAPTER_API_KEY_FILE']
        self.token_request_time = config['NETREACH_ADAPTER_API_KEY_REFRESH_DAYS']
        self.mqtt_broker_url = config.get('NETREACH_ADAPTER_MQTT_BROKER_URL') # Optional
        self.mqtt_ca_certs = config.get('NETREACH_ADAPTER_MQTT_CA_CERTS')
        self.connection_startup_delay_s = config.get('NETREACH_ADAPTER_CONN_START_DELAY_S')
        self.api_token = None
        self.api_token_refresh = None
        self.ap_uuid = None
        self.ap_name = None
        self.ap_group_uuid = None
        self.ap_group_name = None
        self.api_token_expiration = None
        self.ap_name = None
        self.ap_enabled = None
        self.micronets_api_prefix = f"http://{config['LISTEN_HOST']}:{config['LISTEN_PORT']}/gateway"
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
        logger.info(f"NetreachAdapter: using micronets API prefix: \n{self.micronets_api_prefix}")
        self.mqtt_client = None
        self.mqtt_connection_state = "DISCONNECTED"

    async def handle_hostapd_ready(self):
        logger.info(f"NetreachAdapter.handle_hostapd_ready()")

    async def update (self, micronet_list, device_lists):
        logger.info (f"NetreachAdapter.update ()")
        logger.info (f"NetreachAdapter.update: device_lists: {device_lists}")

    async def connect(self):
        logger.info(f"NetreachAdapter:connect()")
        if self.connection_startup_delay_s:
            await asyncio.sleep(self.connection_startup_delay_s)

        self._login_to_controller()
        self._get_ap_info()
        self._setup_micronets_for_ap()
        self._register_controller_listener()

    def _login_to_controller(self):
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
        logger.info(f"Token registration response: {json.dumps(res_json, indent=4)}")
        self.api_token = res_json['token']
        self.api_token_refresh = res_json['refresh_token']
        self.ap_uuid = res_json['uuid']
        self.api_token_expiration = res_json['expires']
        logger.info(f"AP UUID: {self.ap_uuid}")
        if not self.mqtt_broker_url:
            self.mqtt_broker_url = res_json['mqttProxyUrl']

        with open(self.api_token_file, 'wt') as f:
            self.priv_key = f.write(self.api_token)
        logger.info(f"Saved NetReach Controller API token to {self.api_token_file}")

    def _register_controller_listener(self):
        logger.debug(f"NetreachAdapter: register_controller_listener()")
        logger.info(f"NetreachAdapter: Connecting with MQTT broker at {self.mqtt_broker_url}")

        # Instantiate mqtt broker.  This is a sync implementation.  Async implementations are available
        mqtt_client = mqtt.Client(self.ap_uuid)
        mqtt_client.username_pw_set(self.ap_uuid, self.api_token)

        mqtt_client.on_connect = self._on_mqtt_connect
        mqtt_client.on_message = self._on_mqtt_message
        mqtt_client.on_disconnect = self._on_mqtt_disconnect
        mqtt_client.on_log = self._on_mqtt_log

        url_parts = urllib_dot_parse.urlparse(self.mqtt_broker_url)
        if url_parts.scheme == "mqtt" or url_parts.scheme == "mqtts":
            if url_parts.scheme == "mqtts":
                mqtt_client.tls_set(ca_certs=self.mqtt_ca_certs)
                # mqtt_client.tls_insecure_set(True)
            mqtt_client.connect(url_parts.hostname, url_parts.port, keepalive=60)
            self.mqtt_connection_state = "CONNECTING"
            logger.info(f"NetreachAdapter: Connected to MQTT broker at {url_parts.hostname}:{url_parts.port}")
        else:
            raise Exception(f"Unrecognized mqtt url scheme {self.mqtt_broker_url}")

        self.mqtt_client = mqtt_client
        self.mqtt_client.loop_start()

    def _get_ap_info(self):
        # Retrieve info on myself
        result = httpx.get(f"{self.base_url}/v1/access-points/{self.ap_uuid}",
                           headers={"x-api-token": self.api_token})
        ap_info = result.json()
        logger.info(f"AP Info: {json.dumps(ap_info, indent=4)}")
        self.ap_name = ap_info['name']
        self.ap_enabled = ap_info['enabled']
        # TODO: Replace these with a call to get the ap_group for an AP guid
        self.ap_group_uuid = '9e8d3420-49bd-44f0-a86b-38a0a44de010'
        self.ap_group_name = "PLACEHOLDER"

    def _setup_micronets_for_ap(self):
        logger.info(f"NetreachAdapter: _setup_micronets_for_ap(apGroup={self.ap_group_uuid}/{self.ap_group_name})")
        result = httpx.get(f"{self.base_url}/v1/services/?apGroupUuid={self.ap_group_uuid}",
                           headers={"x-api-token": self.api_token})
        # Clear out all the micronets
        # result = httpx.delete(f"{self.micronets_api_prefix}/v1/gateway/micronets",
        #                       headers={"x-api-token": self.api_token})
        service_list = result.json()['results']
        for service in service_list:
            service_uuid = service['uuid']
            service_name = service['name']
            micronet_id = service['micronetId']
            micronet_subnet = IPv4Network(service['micronetSubnet']+"/24", strict=True)
            micronet_vlan = service['vlan']
            # TODO: Replace this with gateway reference from Service object
            micronet_gateway = str(next(micronet_subnet.hosts()))
            logger.info(f"NetreachAdapter: _setup_micronets_for_ap: Found service {service_uuid} ({service_name})")
            logger.info(f"NetreachAdapter: _setup_micronets_for_ap: micronet id {micronet_id} vlan {micronet_vlan}")
            if not (micronet_subnet and micronet_vlan):
                logger.info(f"NetreachAdapter: _setup_micronets_for_ap: netreach Service {service_name} ({service_uuid}) does not have a micronet ID/vlan - SKIPPING")
                pass
            micronet_subnet_addr = micronet_subnet.network_address
            micronet_subnet_netmask = micronet_subnet.netmask
            logger.info(f"NetreachAdapter: _setup_micronets_for_ap: micronet subnet {micronet_subnet} ({micronet_subnet_addr}/{micronet_subnet_netmask})")
            logger.info(f"NetreachAdapter: _setup_micronets_for_ap: micronet gateway {micronet_gateway}")

            micronet_to_add = {
                "micronet": {
                    "micronetId": micronet_id,
                    "ipv4Network": {"network": str(micronet_subnet_addr), "mask": str(micronet_subnet_netmask),
                                    "gateway": micronet_gateway},
                    "interface": self.wifi_interface,
                    "vlan": micronet_vlan,
                    "nameservers": [micronet_gateway]
                }
            }
            logger.info(f"NetreachAdapter: _setup_micronets_for_ap: Adding micronet: {json.dumps(micronet_to_add, indent=4)}")

            result = httpx.get(f"{self.base_url}/v1/services/{service_uuid}/devices",
                                   headers={"x-api-token": self.api_token})
            nr_device_list = result.json()['results']
            micronet_devices = []
            for device in nr_device_list:
                logger.info(f"NetreachAdapter: _setup_micronets_for_ap:   Found device {device['uuid']} ({device['name']})")
                device_name = device['name']
                device_mac = device['macAddress']
                device_ip = device['ipAddress']
                device_psks = device['psks']
                logger.info(f"NetreachAdapter: _setup_micronets_for_ap:   device name {device_name} mac {device_mac} ip {device_ip}")
                # if not device_mac:
                #     continue
                # if not device_psks:
                #     logger.info(f"NetreachAdapter: _setup_micronets_for_ap:   Device {device['name']} does not have a PSK ({device['uuid']})")
                device_to_add = {
                        "deviceId": device_name,
                        "macAddress": {"eui48": device_mac},
                        "networkAddress": {"ipv4": device_ip},
                        "psk": device_psks[0]
                }
                micronet_devices.append(device_to_add)
            micronet_device_list = {"devices": micronet_devices}
            logger.info(f"NetreachAdapter: _setup_micronets_for_ap: Micronet devices for service {service_name}: \n"
                        f"{json.dumps(micronet_device_list, indent=4)}")

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        # handles the connecting event of the mqtt broker
        logger.info(f"NetreachAdapter: _on_mqtt_connect(client:{client},userdata:{userdata},flags:{flags},rc:{rc})")
        # subscribe to the event topic
        ap_topic = f'access-points/{self.ap_uuid}/events'
        client.subscribe(f'access-points/{self.ap_uuid}/events', qos=1)
        client.subscribe(f'access-points/{self.ap_uuid}/data', qos=1)
        self.mqtt_connection_state = "CONNECTED"

    def _on_mqtt_disconnect(self, client, userdata, rc):
        # Notifies the controller of broker disconnection
        logger.info(f"NetreachAdapter: on_disconnect(client:{client},userdata:{userdata},rc:{rc})")
        self.mqtt_connection_state = "DISCONNECTED"

    def _on_mqtt_message(self, client, userdata, message):
        # handles all incoming mqtt messages
        logger.info(f"NetreachAdapter: _on_mqtt_message(client:{client},userdata:{userdata},message:{message})")

    def _on_mqtt_log(self, client, userdata, message):
        # handles all incoming mqtt messages
        logger.info(f"NetreachAdapter: _on_mqtt_log(client:{client},userdata:{userdata},message:{message})")

    def _report_event_success(self, data):
        logger.info(f"NetreachAdapter: _report_event_success: data={data}, uuid={data['uuid']})")

    def _report_event_failure(self, data, payload):
        logger.info(f"NetreachAdapter: _report_event_failure: data={data}, uuid={data['uuid']}, payload={payload})")

    def _parse_mqtt_topic(self, topic):
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

    def _send_status(self, status):
        pass
        # http.patch(f'/access-points/{access_point.get_attribute("uuid")}', data={
        #     "status": status
        # })

    def _validate_uuid(self, uuid):
        try:
            return int(UUID(uuid).version) > 0
        except ValueError:
            return False
