import asyncio
import websockets
import pathlib
import ssl
import multidict
import logging

from quart import Quart, Request, json
from app import app
from .utils import check_json_field
from .ws_connector import WSMessageHandler

logger = logging.getLogger ('micronets-gw-service')

class DPPHandler(WSMessageHandler):
    def __init__ (self):
        super().__init__("DPP")

    async def handle_message(self, message):
        logger.info("DPPHandler.handle_message: {message}")

    async def onboard_device(self, micronet_id, device_id, onboard_params):
        logger.info(f"DPPHandler.onboard_device(micronet '{micronet_id}, device '{device_id}', onboard_params '{onboard_params}')")
        return '', 200
