import asyncio
import logging

from quart import Quart, Request, json
from app import get_ws_connector, get_conf_model
from .ws_connector import WSMessageHandler
from .hostapd_adapter import HostapdCLIEventHandler

logger = logging.getLogger ('micronets-gw-service')


class DPPHandler(WSMessageHandler, HostapdCLIEventHandler):
    def __init__ (self, config):
        WSMessageHandler.__init__(self, "DPP")
        HostapdCLIEventHandler.__init__(self, "DPP")
        self.config = config
        self.simulate_response_events = config ['SIMULATE_ONBOARD_RESPONSE_EVENTS']
        self.simulated_event_wait_s = 7

    async def handle_ws_message(self, message):
        logger.info("DPPHandler.handle_ws_message: {message}")

    async def handle_hostapd_cli_message(self, message):
        logger.info(f"DPPHandler.handle_hostapd_cli_message({message}")
        # TODO
        pass

    async def onboard_device(self, micronet_id, device_id, onboard_params):
        logger.info(f"DPPHandler.onboard_device(micronet '{micronet_id}, device '{device_id}', onboard_params '{onboard_params}')")
        conf_model = get_conf_model()
        micronet = conf_model.check_micronet_reference(micronet_id)
        device = conf_model.check_device_reference(micronet_id, device_id)

        if self.simulate_response_events:
            async def send_dpp_onboard_event_delayed(event_name, reason):
                await asyncio.sleep(self.simulated_event_wait_s)
                await self.send_dpp_onboard_event(micronet, device, event_name, reason)

            if self.simulate_response_events == "with success":
                logger.info (f"DPPHandler.onboard_device: simulating success response to onboard {device_id} "
                             f"in {self.simulated_event_wait_s} seconds")
                asyncio.ensure_future(send_dpp_onboard_event_delayed("DPPOnboardingCompleteEvent", "This is only a test"))
            elif self.simulate_response_events == "with failure":
                logger.info(f"DPPHandler.onboard_device: simulating fail response to onboard {device_id} "
                            f"in {self.simulated_event_wait_s} seconds")
                asyncio.ensure_future(send_dpp_onboard_event_delayed("DPPOnboardingFailedEvent", "This is only a test"))
            else:
                logger.warning(f"DPPHandler.onboard_device: unrecognized value for SIMULATE_ONBOARD_RESPONSE_EVENTS: "
                               + self.simulate_response_events)

        # TODO: IMPLEMENT ME
        return '', 200

    async def send_dpp_onboard_event(self, micronet, device, event_name, reason=None):
        ws_connector = get_ws_connector()
        if not ws_connector.is_ready ():
            ws_uri = ws_connector.get_connect_uri ()
            logger.info (f"DPPHandler.send_dpp_onboard_complete: websocket not connected (ws uri: {ws_uri})")
            return f"The websocket connection to {ws_uri} is not connected/ready", 500

        dev_mac_field = device['macAddress']['eui48']

        dpp_onboarding_complete_event = { event_name: {
                                          'micronetId': micronet['micronetId'],
                                          'deviceId': device['deviceId'],
                                          'macAddress': dev_mac_field
                                          } }
        if reason:
            dpp_onboarding_complete_event[event_name]['reason'] = reason
        logger.info (f"DPPHandler.send_dpp_onboard_complete: sending:")
        logger.info (json.dumps (dpp_onboarding_complete_event, indent=4))
        await ws_connector.send_event_message ("DPP", event_name, dpp_onboarding_complete_event)
