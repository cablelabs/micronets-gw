import asyncio
import logging

from quart import Quart, Request, json
from app import get_ws_connector, get_conf_model
from .ws_connector import WSMessageHandler
from .hostapd_adapter import HostapdAdapter 

logger = logging.getLogger ('micronets-gw-service')


class DPPHandler(WSMessageHandler, HostapdAdapter.HostapdCLIEventHandler):
    def __init__ (self, config, hostapd_adapter):
        WSMessageHandler.__init__(self, "DPP")
        HostapdAdapter.HostapdCLIEventHandler.__init__(self, "DPP")
        self.config = config
        self.simulate_response_events = config ['SIMULATE_ONBOARD_RESPONSE_EVENTS']
        self.simulated_event_wait_s = 7
        self.hostapd_adapter = hostapd_adapter

    async def handle_ws_message(self, message):
        logger.info("DPPHandler.handle_ws_message: {message}")

    async def handle_hostapd_cli_message(self, message):
        logger.info(f"DPPHandler.handle_hostapd_cli_message({message})")
        # TODO
        pass

    async def onboard_device(self, micronet_id, device_id, onboard_params):
        logger.info(f"DPPHandler.onboard_device(micronet '{micronet_id}', device '{device_id}', onboard_params '{onboard_params}')")
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
            return '', 200
        else:
            logger.info(f"DPPHandler.onboard_device: Issuing DPP onboarding commands for device '{device_id}' in micronet '{micronet_id}...")

            if 'psk' not in device:
                raise Exception("Device {device_id} does not have a PSK")
            psk = device['psk']

            status_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.StatusCLICommand())
            logger.info (f"{__name__}: Retrieving ssid...")
            ssid_list = await status_cmd.get_status_var("ssid")
            ssid = ssid_list[0]
            ssid_ascii = ssid.encode("ascii").hex()
            logger.info(f"DPPHandler.onboard_device:   SSID: {ssid} ({ssid_ascii})")

            qrcode_uri = onboard_params['dpp']['uri']
            logger.info (f"{__name__}:   QRCode URI: {qrcode_uri}")
            add_qrcode_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.DPPAddQRCodeCLICommand(qrcode_uri))
            qrcode_id = await add_qrcode_cmd.get_qrcode_id()
            logger.info (f"{__name__}:   DPP QRCode ID: {qrcode_id}")

            add_config_id_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.DPPAddConfiguratorCLICommand())
            configurator_id = await add_config_id_cmd.get_configurator_id()
            logger.info (f"{__name__}:   DPP Configurator ID: {configurator_id}")

            dpp_auth_init_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.DPPAuthInitPSKCommand(configurator_id, qrcode_id, ssid_ascii, psk))
            result = await dpp_auth_init_cmd.get_response()
            logger.info (f"{__name__}: Auth Init result: {result}")

            if await dpp_auth_init_cmd.was_successful():
                return '', 200
            else:
                return f"Onboarding could not be initiated ({result})", 500


    async def handle_hostapd_cli_event(self, event):
        logger.info(f"DPPHandler.handle_hostapd_cli_event({event})")


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
