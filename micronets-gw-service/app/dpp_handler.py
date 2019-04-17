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
