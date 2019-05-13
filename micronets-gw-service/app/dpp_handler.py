import asyncio
import logging
import ecdsa

from pathlib import Path
from quart import Quart, Request, json
from app import get_ws_connector, get_conf_model
from .ws_connector import WSMessageHandler
from .hostapd_adapter import HostapdAdapter 
from .utils import InvalidUsage

logger = logging.getLogger ('micronets-gw-service')


class DPPHandler(WSMessageHandler, HostapdAdapter.HostapdCLIEventHandler):
    EVENT_ONBOARDING_STARTED = "DPPOnboardingStartedEvent"
    EVENT_ONBOARDING_PROGRESS = "DPPOnboardingProgressEvent"
    EVENT_ONBOARDING_COMPLETE = "DPPOnboardingCompleteEvent"
    EVENT_ONBOARDING_FAILED = "DPPOnboardingFailedEvent"
    DPP_ONBOARD_TIMEOUT_S = 20

    def __init__ (self, config, hostapd_adapter):
        WSMessageHandler.__init__(self, "DPP")
        HostapdAdapter.HostapdCLIEventHandler.__init__(self, ("DPP","AP-STA"))
        self.config = config
        self.simulate_response_events = config ['SIMULATE_ONBOARD_RESPONSE_EVENTS']
        self.simulated_event_wait_s = 6
        self.hostapd_adapter = hostapd_adapter
        self.pending_onboard = None
        self.dpp_config_key_file = Path (config ['DPP_CONFIG_KEY_FILE'])
        self.dpp_configurator_id = None

    async def handle_ws_message(self, message):
        logger.info("DPPHandler.handle_ws_message: {message}")

    async def onboard_device(self, micronet_id, device_id, onboard_params):
        logger.info(f"DPPHandler.onboard_device(micronet '{micronet_id}', device '{device_id}', onboard_params '{onboard_params}')")

        if self.pending_onboard:
            pending_device_id = self.pending_onboard['device']['deviceId']
            pending_micronet_id = self.pending_onboard['micronet']['micronetId']
            raise InvalidUsage (503, message="Only one onboard process can be performed at a time (currently onboarding "
                                            f"device {pending_device_id} into micronet (pending_micronet_id))")
        conf_model = get_conf_model()
        micronet = conf_model.check_micronet_reference(micronet_id)
        device = conf_model.check_device_reference(micronet_id, device_id)

        akms = onboard_params['dpp']['akms']
        if 'dpp' in akms:
            pass
        elif 'psk' in akms:
            if 'psk' not in device:
                raise InvalidUsage (503, message="Device {device_id} does not have a PSK - cannot onboard")
        else:
            raise InvalidUsage(503, message="Only PSK- and DPP-based on-boarding are currently supported")

        if self.simulate_response_events:
            async def send_dpp_onboard_event_delayed(event_name, delay, reason=None, terminal=False):
                await asyncio.sleep(delay)
                if self.pending_onboard:
                    pend_micronet = self.pending_onboard['micronet']
                    pend_device = self.pending_onboard['device']
                    await self.send_dpp_onboard_event(pend_micronet, pend_device, event_name, reason)
                    if terminal:
                        self.pending_onboard = None
                else:
                    logger.warning("DPPHandler.send_dpp_onboard_event_delayed: No onboard is pending - not sending event")

            asyncio.ensure_future(send_dpp_onboard_event_delayed(DPPHandler.EVENT_ONBOARDING_STARTED, 1))
            asyncio.ensure_future(send_dpp_onboard_event_delayed(DPPHandler.EVENT_ONBOARDING_PROGRESS,
                                                                 self.simulated_event_wait_s/2,
                                                                 reason="This is progress"))
            sim_terminal_event = DPPHandler.EVENT_ONBOARDING_COMPLETE \
                                 if self.simulate_response_events == "with success" \
                                 else DPPHandler.EVENT_ONBOARDING_FAILED
            logger.info (f"DPPHandler.onboard_device: simulating {sim_terminal_event} response to onboard {device_id} "
                         f"in {self.simulated_event_wait_s} seconds")
            asyncio.ensure_future(send_dpp_onboard_event_delayed(sim_terminal_event, self.simulated_event_wait_s,
                                                                 reason="This is only a test...", terminal=True))
            self.pending_onboard = {"micronet":micronet, "device": device, "onboard_params": onboard_params}
            return '', 200

        logger.info(f"DPPHandler.onboard_device: Issuing DPP onboarding commands for device '{device_id}' in micronet '{micronet_id}...")

        status_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.StatusCLICommand())
        logger.info (f"{__name__}: Retrieving ssid...")
        ssid_list = await status_cmd.get_status_var("ssid")
        ssid = ssid_list[0]
        logger.info(f"DPPHandler.onboard_device:   SSID: {ssid} ({ssid_ascii})")

        qrcode_uri = onboard_params['dpp']['uri']
        logger.info (f"{__name__}:   DPP QRCode URI: {qrcode_uri}")
        add_qrcode_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.DPPAddQRCodeCLICommand(qrcode_uri))
        qrcode_id = await add_qrcode_cmd.get_qrcode_id()
        logger.info(f"{__name__}:   DPP QRCode ID: {qrcode_id}")

        self.pending_onboard = {"micronet":micronet, "device": device, "onboard_params": onboard_params}
        if 'dpp' in akms:
            dpp_auth_init_cmd = HostapdAdapter.DPPAuthInitCommand(self.dpp_configurator_id, qrcode_id, ssid)
        elif 'psk' in akms:
            psk = device['psk']
            dpp_auth_init_cmd = HostapdAdapter.DPPAuthInitCommand(self.dpp_configurator_id, qrcode_id, ssid, psk=psk)
        else:
            raise InvalidUsage(503, message="Only PSK- and DPP-based on-boarding are currently supported")

        await self.hostapd_adapter.send_command(dpp_auth_init_cmd)
        result = await dpp_auth_init_cmd.get_response()
        logger.info(f"{__name__}: Auth Init result: {result}")

        if await dpp_auth_init_cmd.was_successful():
            async def onboard_timeout_handler():
                await asyncio.sleep(DPPHandler.DPP_ONBOARD_TIMEOUT_S)
                if self.pending_onboard:
                    logger.info(f"{__name__}: Onboarding TIMED OUT (after {DPPHandler.DPP_ONBOARD_TIMEOUT_S} seconds)")
                    pend_micronet = self.pending_onboard['micronet']
                    pend_device = self.pending_onboard['device']
                    await self.send_dpp_onboard_event(pend_micronet, pend_device,
                                                      DPPHandler.EVENT_ONBOARDING_FAILED,
                                                      f"Onboarding timed out (after {DPPHandler.DPP_ONBOARD_TIMEOUT_S} seconds)")
                    self.pending_onboard = None
                else:
                    logger.info(f"{__name__}: Onboarding completed before timeout (< {DPPHandler.DPP_ONBOARD_TIMEOUT_S} seconds)")

            self.pending_timeout_task = asyncio.ensure_future(onboard_timeout_handler())

            return '', 200
        else:
            self.pending_onboard = None
            return f"Onboarding could not be initiated ({result})", 500


    async def handle_hostapd_cli_event(self, event):
        logger.info(f"DPPHandler.handle_hostapd_cli_event({event})")
        logger.info(f"DPPHandler.handle_hostapd_cli_event({event}): pending_onboard {self.pending_onboard}")
        if self.pending_onboard:
            micronet = self.pending_onboard['micronet']
            device = self.pending_onboard['device']
            if event.startswith("DPP-AUTH-INIT-FAILED"):
                self.pending_onboard = None
                await self.send_dpp_onboard_event(micronet, device, DPPHandler.EVENT_ONBOARDING_FAILED, 
                                                  f"DPP Authorization failed ({event})")
            elif event.startswith("DPP-AUTH-SUCCESS") or event.startswith("DPP-CONF-SENT"):
                await self.send_dpp_onboard_event(micronet, device, DPPHandler.EVENT_ONBOARDING_PROGRESS, 
                                                  f"DPP Progress ({event})")
            elif event.startswith("AP-STA-CONNECTED") and device['macAddress']['eui48'] in event:
                self.pending_onboard = None
                await self.send_dpp_onboard_event(micronet, device, DPPHandler.EVENT_ONBOARDING_COMPLETE, 
                                                  f"DPP Onboarding Complete ({event})")

    async def handle_hostapd_ready(self):
        logger.info(f"DPPHandler.handle_hostapd_ready()")
        dpp_config_key = None
        if self.dpp_config_key_file.exists():
            try:
                dpp_config_key = self.dpp_config_key_file.read_text()
            except Exception as ex:
                logger.warning(f"DPPHandler: handle_hostapd_ready: Caught exception reading {self.dpp_config_key_file}: {ex}")
                return
        else:
            # Create a prime256v1 key
            dpp_config_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p).to_der().hex()
            self.dpp_config_key_file.write_text(dpp_config_key)

        add_configurator_cmd = HostapdAdapter.DPPAddConfiguratorCLICommand(curve="prime256v1", key=dpp_config_key)
        await self.hostapd_adapter.send_command(add_configurator_cmd)
        self.dpp_configurator_id = await add_configurator_cmd.get_configurator_id()
        logger.info(f"DPPHandler.handle_hostapd_ready: DPP Configurator ID: {self.dpp_configurator_id}")

    async def send_dpp_onboard_event(self, micronet, device, event_name, reason=None):
        ws_connector = get_ws_connector()
        if not ws_connector.is_ready():
            ws_uri = ws_connector.get_connect_uri()
            logger.info (f"DPPHandler.send_dpp_onboard_event: websocket not connected (ws uri: {ws_uri})")
            return f"The websocket connection to {ws_uri} is not connected/ready", 500

        dev_mac_field = device['macAddress']['eui48']

        dpp_onboarding_complete_event = { event_name: {
                                          'micronetId': micronet['micronetId'],
                                          'deviceId': device['deviceId'],
                                          'macAddress': dev_mac_field
                                          } }
        if reason:
            dpp_onboarding_complete_event[event_name]['reason'] = reason
        logger.info (f"DPPHandler.send_dpp_onboard_event: sending:")
        logger.info (json.dumps (dpp_onboarding_complete_event, indent=4))
        await ws_connector.send_event_message ("DPP", event_name, dpp_onboarding_complete_event)

