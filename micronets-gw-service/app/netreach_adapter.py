import re, logging, base64, json, httpx, ssl

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
import paho.mqtt.client as mqtt
from urllib import parse as urllib_dot_parse

from .hostapd_adapter import HostapdAdapter

logger = logging.getLogger ('micronets-gw-service-netreach')


class NetreachAdapter(HostapdAdapter.HostapdCLIEventHandler):

    def __init__ (self, config):
        self.serial_number_file = config['NETREACH_ADAPTER_SERIAL_NUM_FILE']
        self.pub_key_file = config['NETREACH_ADAPTER_PUBLIC_KEY_FILE']
        self.priv_key_file = config['NETREACH_ADAPTER_PRIVATE_KEY_FILE']
        self.base_url = config['NETREACH_ADAPTER_CONTROLLER_BASE_URL']
        self.api_token_file = config['NETREACH_ADAPTER_API_KEY_FILE']
        self.token_request_time = config['NETREACH_ADAPTER_API_KEY_REFRESH_DAYS']
        self.mqtt_broker_url = config.get('NETREACH_ADAPTER_MQTT_BROKER_URL') # Optional
        self.mqtt_ca_certs = config.get('NETREACH_ADAPTER_MQTT_CA_CERTS')
        self.api_token = None
        self.api_token_refresh = None
        self.ap_uuid = None
        self.api_token_expiration = None
        self.ap_name = None
        self.ap_enabled = None
        self.micronets_api_prefix = f"http//{config['LISTEN_HOST']}:{config['LISTEN_PORT']}"
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
        self._login_to_controller()
        self._get_ap_info()
        self._register_controller_listener()

        # Retrieve info on myself
        result = httpx.get(f"{self.base_url}/v1/access-points/{self.ap_uuid}",
                           headers={"x-api-token": self.api_token})


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

    def _get_ap_info(self):
        # Retrieve info on myself
        result = httpx.get(f"{self.base_url}/v1/access-points/{self.ap_uuid}",
                           headers={"x-api-token": self.api_token})
        ap_info = result.json()
        logger.info(f"AP Info: {json.dumps(ap_info, indent=4)}")
        self.ap_name = ap_info['name']
        self.ap_enabled = ap_info['enabled']

    def on_connect(self, client, userdata, flags, rc):
        # handles the connecting event of the mqtt broker
        logger.info(f"NetreachAdapter: on_connect(client:{client},userdata:{userdata},flags:{flags},rc:{rc})")

    def on_disconnect(self, client, userdata, rc):
        # Notifies the controller of broker disconnection
        logger.info(f"NetreachAdapter: on_disconnect(client:{client},userdata:{userdata},rc:{rc})")

    def on_message(self, client, userdata, message):
        # handles all incoming mqtt messages
        logger.info(f"NetreachAdapter: on_message(client:{client},userdata:{userdata},message:{message})")

    def _register_controller_listener(self):
        logger.debug(f"NetreachAdapter: register_controller_listener()")
        logger.info(f"NetreachAdapter: Connecting with MQTT broker at {self.mqtt_broker_url}")

        # Instantiate mqtt broker.  This is a sync implementation.  Async implementations are available
        client = mqtt.Client(self.ap_uuid)
        client.username_pw_set(self.ap_uuid, self.api_token)

        client.on_connect = self.on_connect
        client.on_message = self.on_message

        # client.tls_set(ca_certs=None, certfile=None, keyfile=None, cert_reqs=ssl.CERT_REQUIRED,
        #     tls_version=ssl.PROTOCOL_TLS, ciphers=None)
        url_parts = urllib_dot_parse.urlparse(self.mqtt_broker_url)
        if url_parts.scheme == "mqtt" or url_parts.scheme == "mqtts":
            if url_parts.scheme == "mqtts":
                client.tls_set(ca_certs=self.mqtt_ca_certs)
                # client.tls_insecure_set(True)
            client.connect(url_parts.hostname, url_parts.port, keepalive=60)
            logger.info(f"NetreachAdapter: Connected to MQTT broker at {url_parts.hostname}:{url_parts.port}")
        else:
            raise Exception(f"Unrecognized mqtt url scheme {self.mqtt_broker_url}")

        client.loop_start()


    async def handle_hostapd_ready(self):
        logger.info(f"NetreachAdapter.handle_hostapd_ready()")

    async def update (self, micronet_list, device_lists):
        logger.info (f"NetreachAdapter.update ()")
        logger.info (f"NetreachAdapter.update: device_lists: {device_lists}")

    # def on_connect(client, userdata, flags, rc):
    #     # handles the connecting event of the mqtt broker
    #     print("MQTT Connected")
    #
    #     # subscribe to the event topic
    #     ap_topic = f'access-points/{ap["uuid"]}/events'
    #     client.subscribe(ap_topic, qos=1)
    #     access_point.subscriptions[ap_topic] = None
    #
    #     # subscribe to the data topic
    #     ap_topic = f'access-points/{ap["uuid"]}/data'
    #     client.subscribe(ap_topic, qos=1)
    #     access_point.subscriptions[ap_topic] = None
    #
    #     send_status('CONNECTED')
    #
    #
    # def on_disconnect(client, userdata, rc):
    #     # Notifies the controller of broker disconnection
    #     print("Broker disconnected with code " + str(rc))
    #     send_status("DISCONNECTED")
    #
    #
    # def on_message(client, userdata, message):
    #     # handles all incoming mqtt messages
    #
    #     try:
    #         msg = json.loads(message.payload.decode("utf-8"))
    #
    #         if not type(msg) is dict:
    #             print(f"Got message that was not JSON: `{msg}`")
    #             return
    #
    #         # parse out topic uuids
    #         topic_parts = parse_mqtt_topic(message.topic)
    #
    #         if "events" in topic_parts:
    #             handle_event_topic(client, userdata, msg)
    #
    #     except Exception as e:
    #         print(message.topic)
    #         print(e)
    #         raise e