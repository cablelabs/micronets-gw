import asyncio
import websockets
import pathlib
import ssl
import multidict
import logging

from quart import Quart, Request, json
from app import app
from .utils import check_json_field

logger = logging.getLogger ('micronets-gw-service')

class WSMessageHandler:
    def __init__ (self, type_prefix):
        self.type_prefix = type_prefix
        self.ws_connector = None

    async def handle_message(self, message):
        pass

    async def send_message(self, message):
        message_body = message['message']
        messageType = message_body['messageType']
        message_body['messageType'] = self.type_prefix + ":" + messageType
        self.ws_connector.send_message(message)


class WSConnector:
    def __init__ (self, ws_server_address, ws_server_port, ws_server_path,
                        tls_certkey_file = None, tls_ca_file = None, retry_interval_s = 20):
        logger.info ("WSConnector: initializing...")
        self.ws_server_address = ws_server_address
        self.ws_server_port = ws_server_port
        self.ws_server_path = ws_server_path
        self.handler_table = {}
        self.websocket = None
        self.message_id = 0
        self.hello_received = False
        self.tls_certkey_file = tls_certkey_file
        self.tls_ca_file = tls_ca_file
        self.retry_interval_s = retry_interval_s
        logger.info (f"WSConnector: Websocket server/path: {ws_server_address}:{ws_server_port}/{ws_server_path}")
        logger.info (f"WSConnector: Client cert-key File: {tls_certkey_file}")
        logger.info (f"WSConnector: CA File: {tls_ca_file}")

    def connect (self):
        asyncio.ensure_future (self.setup_connection ())

    def is_connected (self):
        return not self.websocket is None

    def is_ready (self):
        return self.is_connected () and self.hello_received

    def register_handler(self, handler):
        logger.info (f"WSConnector: Registering handler for message type prefix {handler.type_prefix}: {handler}")
        self.handler_table[handler.type_prefix] = handler
        handler.ws_connector = self

    def unregister_handler(self, handler):
        del self.handler_table[handler.type_prefix]
        handler.ws_connector = None

    async def send_message (self, message, must_be_ready=True):
        if not self.is_connected ():
            raise Exception (f"Websocket not connected (to {self.get_connect_uri()})")
        if must_be_ready and not self.is_ready():
            raise Exception(f"Websocket not ready (connected to {self.get_connect_uri()})")
        message_id = self.message_id
        self.message_id += 1
        message ['messageId'] = message_id
        message_json = json.dumps ( {'message': message} )
        logger.debug (f"ws_connector: > sending event message: {message}")
        await self.websocket.send (message_json)
        return message_id

    def get_connect_uri (self):
        if (self.tls_certkey_file):
            scheme = "wss"
        else:
            scheme = "ws"
        return f"{scheme}://{self.ws_server_address}:{self.ws_server_port}{self.ws_server_path}"

    async def setup_connection (self):
        logger.debug ("WSConnector: setup_connection: starting...")
        ssl_context = None

        if (self.tls_certkey_file):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Setup the client's cert
            client_cert_path = pathlib.Path (self.tls_certkey_file)
            logger.debug (f"Loading test client certificate from {client_cert_path}")
            ssl_context.load_cert_chain (client_cert_path)

            if (self.tls_ca_file):
                # Verify peer certs using the websocket root as the CA
                root_cert_path = pathlib.Path (self.tls_ca_file)
                logger.debug (f"Loading CA certificate from {root_cert_path}")

            ssl_context.load_verify_locations (cafile = root_cert_path)
            ssl_context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
            ssl_context.check_hostname = False

        dest_uri = self.get_connect_uri ()
        while (True):
            try:
                await self.init_connection (dest_uri, ssl_context=ssl_context)
            except Exception as ex:
                logger.warn (f"WSConnector: setup_connection: Error connecting "
                             f"to {self.ws_server_address}:{self.ws_server_port}: {ex}", exc_info=False)
                # Note: Set "exc_info=True" to get a detailed traceback
                logger.info (f"WSConnector: Sleeping {self.retry_interval_s} seconds before reconnecting...")
                await asyncio.sleep (self.retry_interval_s)
                continue

            tasks = [ asyncio.ensure_future (self.sender ()),
                      asyncio.ensure_future (self.receiver ()) ]
            await asyncio.wait (tasks)
            self.websocket = None
            logger.info (f"WSConnector: sender/receiver closed. Attempting to reconnect...")

    async def init_connection (self, dest_uri, ssl_context=None):
        logger.info (f"WSConnector: init_connect opening {dest_uri}...")
        self.hello_received = False
        self.websocket = await websockets.connect (dest_uri, ssl=ssl_context)
        logger.info (f"WSConnector: init_connect opened {dest_uri}.")
        logger.info (f"WSConnector Sending HELLO message...")
        await self.send_hello_message (f"gw service {id(self)}")
        logger.info (f"WSConnector: Waiting for HELLO messages...")
        await self.wait_for_hello_message ()
        self.hello_received = True
        logger.info (f"WSConnector: HELLO handshake complete.")

    async def send_hello_message (self, peer_id):
        message = {'messageType': 'CONN:HELLO',
                   'requiresResponse': False,
                   'peerClass': 'micronets-gateway-service',
                   'peerId': peer_id }
        await self.send_message (message, must_be_ready=False)

    async def send_rest_request_message (self, blah):
        # TODO: IMPLEMENT/INTEGRATE
        return 0

    async def send_rest_response_message (self, blah):
        # TODO: IMPLEMENT/INTEGRATE
        return 0

    async def send_info_message (self, info_message):
        message = {'messageType': 'CONN:INFO', 'info': info_message}
        message_id = await self.send_message (message)
        return message_id

    async def send_event_message (self, event_namespace, event_name, event_object):
        message = { 'messageType': f'EVENT:{event_namespace}:{event_name}',
                    'requiresResponse': False,
                    'dataFormat': 'application/json',
                    'messageBody': event_object }
        message_id = await self.send_message (message)
        return message_id

    async def wait_for_hello_message (self):
        raw_message = await self.websocket.recv ()
        message = json.loads (raw_message)
        logger.debug (f"ws_connector: process_hello_messages: Received message: {message}")
        if (not message):
            raise Exception (f"message does not appear to be json")
        hello_message = check_json_field (message, 'message', dict, True)
        message_id = check_json_field (hello_message, 'messageId', int, True)
        message_type = check_json_field (hello_message, 'messageType', str, True)
        check_json_field (hello_message, 'requiresResponse', bool, False)

        if (not message_type == "CONN:HELLO"):
            raise Exception (f"Unexpected message while waiting for HELLO: {message_type}")
        logger.debug (f"ws_connector: process_hello_messages: Received HELLO message")

    async def sender (self):
        logger.debug ("WSConnector: sender: starting...")
        try:
            pass
#             i = 1
#             while (i <= 100):
#                 await asyncio.sleep (10)
#                 await self.send_info_message (self.websocket, f"gateway-server test message #{i}")
#                 i = i + 1
        finally:
            logger.debug ("WSConnector: sender: exiting.")

    async def receiver (self):
        logger.debug ("WSConnector: receiver: starting...")
        try:
            while (True):
                message = await self.websocket.recv ()
                try:
                    logger.info (f"Received message: {message}")
                    await self.handle_message (message)
                except Exception as ex:
                    logger.info (f"Caught an exception ({ex}) processing message: {message}", exc_info=True)
        finally:
            logger.debug ("WSConnector: receiver: exiting.")

    async def handle_message (self, raw_message):
        message = json.loads (raw_message)
        if (not message):
            raise Exception (f"message does not appear to be json")
        logger.debug ("WSConnector: handle_message:")
        logger.debug (json.dumps (message, indent=2))
        check_json_field (message, 'message', dict, True)
        message = message ['message'] # Drill down
        check_json_field (message, 'messageId', int, True)
        check_json_field (message, 'messageType', str, True)
        check_json_field (message, 'requiresResponse', bool, True)
        message_type = message ['messageType']
        message_type_prefix = message_type[:message_type.find(":")]
        logger.debug (f"ws_connector: handle_message: message type prefix: {message_type_prefix}")
        if message_type_prefix == "REST":
            await self.handle_rest_message (message)
        elif message_type_prefix == "EVENT:":
            await self.handle_event_message (message)
        else:
            if message_type_prefix not in self.handler_table:
                raise Exception (f"unknown message type prefix {message_type_prefix}")
            type_handler = self.handler_table[message_type_prefix]
            await type_handler.handle_message (message)

    async def handle_rest_message (self, message):
        received_message_id = message ['messageId']
        method = check_json_field (message, 'method', str, True)
        path = check_json_field (message, 'path', str, True)
        queries = check_json_field (message, 'queryStrings', list, False)
        headers = check_json_field (message, 'headers', list, False)
        data_format = check_json_field (message, 'dataFormat', str, False)
        message_body = check_json_field (message, 'messageBody', (str, dict), False)
        header_dict = multidict.CIMultiDict ()
        if (data_format):
            header_dict.add ("Content-Type", data_format)
        if (headers):
            for header in headers:
                header_dict.add (header ['name'], header ['value'])
        if (queries):
            for query in queries:
                path += f"&{query['name']}={query['value']}"
        query_part = b''
        request = Request (method, "http", path, query_part, header_dict)
        if ('messageBody' in message):
            if isinstance (message_body, dict):
                request.body.set_result (json.dumps (message_body).encode ('utf-8'))
            else:
                request.body.set_result (message_body.encode ('utf-8'))
            header_dict.add ('Content-Length', len (message_body))
        else:
            request.body.set_result (b'')

        response = await asyncio.ensure_future (app.handle_request (request))

        await self.handle_rest_response (received_message_id, response)

    async def handle_rest_response (self, request_message_id, response):
        encoded_payload = None
        if ('Content-Length' in response.headers):
            content_length = int (response.headers ['Content-Length'])
            del response.headers ['Content-Length']  # The length of content is length of the messageBody
            if (content_length > 0):
                raw_body = await response.get_data ()
                content_type = response.headers ['Content-Type']
                if (content_type == "application/json"):
                    body = json.loads (raw_body.decode ('utf-8'))
                else:
                    body = raw_body.decode ('utf-8')
                logger.info (f"WSConnector: handleRestResponse: Response body from Request: {body}")
                if (content_type == "application/json"):
                    encoded_payload = json.loads (raw_body)
                else:
                    encoded_payload = raw_body.decode ('utf-8')

        message = { 'messageType': 'REST:RESPONSE',
                    'requiresResponse': False,
                    'inResponseTo': request_message_id,
                    'statusCode': response.status_code,
                    'reasonPhrase': None}
        if encoded_payload:
            message ['dataFormat'] = content_type
            message ['messageBody'] = encoded_payload
        headers = []
        for header_name, header_val in response.headers.items ():
            headers.append ({'name': header_name, 'value': header_val})
        logger.debug (f"WSConnector: handle_rest_response: found headers: {headers}")

        await self.send_message (message)
        logger.debug (f"WSConnector: handle_rest_response: Response sent.")

    async def handle_event_message (self, message):
        logger.debug (f"WSConnector: handle EVENT message: {message}")
        # TODO: handle the event
