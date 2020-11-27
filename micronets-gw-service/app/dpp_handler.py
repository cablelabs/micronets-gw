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
        self.simulate_response_events = config['DPP_HANDLER_SIMULATE_ONBOARD_RESPONSE_EVENTS']
        self.simulated_event_wait_s = 6
        self.hostapd_adapter = hostapd_adapter
        self.pending_onboard = None
        self.dpp_config_key_file = Path (config['DPP_CONFIG_KEY_FILE'])
        self.dpp_configurator_id = None
        self.dpp_ap_connector_file = Path (config['DPP_AP_CONNECTOR_FILE'])
        self.dpp_ap_connector = None
        self.ssid = None
        self.freq = None

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

        # Make sure an pending updates have been processed
        await conf_model.update_conf_now()

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

        if not self.hostapd_adapter.is_cli_connected():
            return "Hostapd CLI is not connected", 500

        if not self.hostapd_adapter.is_cli_ready():
            return "Hostapd CLI is not ready (hostapd is probably not running)", 500

        logger.info(f"DPPHandler.onboard_device: Issuing DPP onboarding commands for device '{device_id}' in micronet '{micronet_id}...")

        qrcode_uri = onboard_params['dpp']['uri']
        logger.info (f"{__name__}:   DPP QRCode URI: {qrcode_uri}")
        add_qrcode_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.DPPAddQRCodeCLICommand(qrcode_uri))
        qrcode_id = await add_qrcode_cmd.get_qrcode_id()
        logger.info(f"{__name__}:   DPP QRCode ID: {qrcode_id}")

        dev_psk = device.get("psk")
        # For now, the psk field is dual-purpose. For WPA2, a <64char "psk" will be converted into a PSK internally
        # So send it through as a PSK and a passphrase
        if len(dev_psk) == 64:
            psk = dev_psk
            passphrase = None
        else:
            psk = None
            passphrase = dev_psk

        if ";V:2;" in qrcode_uri:
            # Perform DPP V2 onboarding (set bootstrapping info for DPP Chirp/Presence Announcement
            dpp_bootstrap_set_cmd = HostapdAdapter.DPPBootstrapSet(self.dpp_configurator_id, qrcode_id, self.ssid,
                                                                   akms, psk=psk, passphrase=passphrase)
            await self.hostapd_adapter.send_command(dpp_bootstrap_set_cmd)
            result = await dpp_bootstrap_set_cmd.get_response()
            logger.info(f"{__name__}: Bootstrap Set result: {result}")
            if await dpp_bootstrap_set_cmd.was_successful():
                logger.info(f"{__name__}: Successfully set credentials for URI {qrcode_uri}")
                return '', 200
            else:
                logger.info(f"{__name__}: Could not set credentials for URI {qrcode_uri}")
                return f"Could not set DPP V2 credentials for given URI ({result})", 400
        else:
            # Perform DPP V1 onboarding (send Auth Init)
            dpp_auth_init_cmd = HostapdAdapter.DPPAuthInitCommand(self.dpp_configurator_id, qrcode_id, self.ssid,
                                                                  akms, psk=psk, passphrase=passphrase, freq=self.freq)

            self.pending_onboard = {"micronet":micronet, "device": device, "onboard_params": onboard_params}
            asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device, DPPHandler.EVENT_ONBOARDING_STARTED,
                                                              f"DPP Started (issuing \"{dpp_auth_init_cmd.get_command_string()}\")"))
            await self.hostapd_adapter.send_command(dpp_auth_init_cmd)
            result = await dpp_auth_init_cmd.get_response()
            logger.info(f"{__name__}: Auth Init result: {result}")

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

            if await dpp_auth_init_cmd.was_successful():
                self.pending_timeout_task = asyncio.ensure_future(onboard_timeout_handler())
            else:
                asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device, DPPHandler.EVENT_ONBOARDING_FAILED,
                                                                  f"DPP Authorization failed {dpp_auth_init_cmd.get_command_string()} returned: ({result})"))
                self.pending_onboard = None
            return '', 200

    async def reprovision_device(self, micronet_id, device_id,):
        logger.info(f"DPPHandler.reprovision_device(micronet '{micronet_id}', device '{device_id}'')")
        conf_model = get_conf_model()

        # Make sure an pending updates have been processed
        await conf_model.update_conf_now()

        micronet = conf_model.check_micronet_reference(micronet_id)
        device = conf_model.check_device_reference(micronet_id, device_id)

        if not self.hostapd_adapter.is_cli_connected():
            return "Hostapd CLI is not connected", 500

        if not self.hostapd_adapter.is_cli_ready():
            return "Hostapd CLI is not ready (hostapd is probably not running)", 500

        logger.info(f"DPPHandler.onboard_device: Issuing DPP reprovisioning commands for device '{device_id}' in micronet '{micronet_id}...")

        dev_psk = device.get("psk")
        # For now, the psk field is dual-purpose. For WPA2, a <64char "psk" will be converted into a PSK internally
        # So send it through as a PSK and a passphrase
        if len(dev_psk) == 64:
            psk = dev_psk
            passphrase = None
        else:
            psk = None
            passphrase = dev_psk

        dpp_reprovision_params_cmd = HostapdAdapter.DPPSetDPPConfigParamsCommand(self.dpp_configurator_id, self.ssid,
                                                                          ["psk"], psk=psk, passphrase=passphrase)
        await self.hostapd_adapter.send_command(dpp_reprovision_params_cmd)
        result = await dpp_reprovision_params_cmd.get_response()
        logger.info(f"{__name__}: Result of setting reprovision params: {result}")

        if await dpp_reprovision_params_cmd.was_successful():
            logger.info(f"{__name__}: Successfully set reprovisioning credentials for micronet/device {micronet_id}/{device_id}")
            return '', 200
        else:
            logger.info(f"{__name__}: Failed to set reprovisioning credentials for micronet/device {micronet_id}/{device_id}")
            return f"Could not set DPP V2 reprovisioning credentials for micronet/device {micronet_id}/{device_id}", 400

    async def handle_hostapd_cli_event(self, event):
        logger.info(f"DPPHandler.handle_hostapd_cli_event({event})")
        if self.pending_onboard:
            micronet = self.pending_onboard['micronet']
            device = self.pending_onboard['device']
            if event.startswith("DPP-AUTH-INIT-FAILED"):
                self.pending_onboard = None
                self.pending_timeout_task.cancel()
                asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device, DPPHandler.EVENT_ONBOARDING_FAILED, 
                                                                  f"DPP Authorization failed ({event})"))
            elif event.startswith("DPP-AUTH-SUCCESS") or event.startswith("DPP-CONF-SENT"):
                asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device, DPPHandler.EVENT_ONBOARDING_PROGRESS, 
                                                                  f"DPP Progress ({event})"))
            elif event.startswith("AP-STA-CONNECTED") and device['macAddress']['eui48'].lower() in event:
                self.pending_onboard = None
                self.pending_timeout_task.cancel()
                asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device, DPPHandler.EVENT_ONBOARDING_COMPLETE, 
                                                                  f"DPP Onboarding Complete ({event})"))

    async def handle_hostapd_ready(self):
        logger.info(f"DPPHandler.handle_hostapd_ready()")

        self.ssid = self.hostapd_adapter.get_status_var('ssid')[0]
        logger.info(f"DPPHandler.handle_hostapd_ready:   SSID: {self.ssid}")

        self.freq = self.hostapd_adapter.get_status_var('freq')
        logger.info(f"DPPHandler.handle_hostapd_ready:   FREQ: {self.freq}")

        if self.dpp_config_key_file.exists():
            try:
                dpp_config_key = self.dpp_config_key_file.read_text()
                logger.info(f"DPPHandler.handle_hostapd_ready: Loaded DPP configurator key from {self.dpp_config_key_file}")
            except Exception as ex:
                logger.warning(f"DPPHandler: handle_hostapd_ready: Caught exception reading {self.dpp_config_key_file}: {ex}")
                return
        else:
            # Create a prime256v1 key
            dpp_config_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p).to_der().hex()
            self.dpp_config_key_file.write_text(dpp_config_key)
            logger.info(f"DPPHandler.handle_hostapd_ready: Saved new configurator key to {self.dpp_config_key_file}")

        add_configurator_cmd = HostapdAdapter.DPPAddConfiguratorCLICommand(curve="prime256v1", key=dpp_config_key)
        await self.hostapd_adapter.send_command(add_configurator_cmd)
        self.dpp_configurator_id = await add_configurator_cmd.get_configurator_id()
        logger.info(f"DPPHandler.handle_hostapd_ready: DPP Configurator ID: {self.dpp_configurator_id}")

        try:
            if self.dpp_ap_connector_file.exists():
                self.dpp_ap_connector = json.loads(self.dpp_ap_connector_file.read_text())
                logger.info(f"DPPHandler.handle_hostapd_ready: Loaded AP Connector from {self.dpp_ap_connector_file}")
            else:
                # Create the AP's connector and persist it
                logger.info(f"DPPHandler: handle_hostapd_ready: Creating a DPP Connector for the AP")
                dpp_config_sign_cmd = HostapdAdapter.DPPConfiguratorDPPSignCLICommand(self.dpp_configurator_id, self.ssid)
                await self.hostapd_adapter.send_command(dpp_config_sign_cmd)
                dpp_connector = await dpp_config_sign_cmd.get_connector()
                logger.info(f"DPPHandler: handle_hostapd_ready:   Connector: {dpp_connector}")
                dpp_c_sign_key = await dpp_config_sign_cmd.get_c_sign_key()
                logger.info(f"DPPHandler: handle_hostapd_ready:   DPP c-sign-key: {dpp_c_sign_key}")
                dpp_net_access_key = await dpp_config_sign_cmd.get_net_access_key()
                logger.info(f"DPPHandler: handle_hostapd_ready:   Net access key: {dpp_net_access_key}")
                self.dpp_ap_connector = {"dpp_connector": dpp_connector,
                                         "dpp_csign": dpp_c_sign_key,
                                         "dpp_netaccesskey": dpp_net_access_key}
                dpp_ap_connector_json = json.dumps(self.dpp_ap_connector, indent=3) + "\n"
                self.dpp_ap_connector_file.write_text(dpp_ap_connector_json)
            await self.hostapd_adapter.send_command(HostapdAdapter.SetCLICommand("dpp_connector",
                                                                                 self.dpp_ap_connector['dpp_connector']))
            await self.hostapd_adapter.send_command(HostapdAdapter.SetCLICommand("dpp_csign",
                                                                                 self.dpp_ap_connector['dpp_csign']))
            await self.hostapd_adapter.send_command(HostapdAdapter.SetCLICommand("dpp_netaccesskey",
                                                                                 self.dpp_ap_connector['dpp_netaccesskey']))
        except Exception as ex:
            logger.warning(f"DPPHandler: handle_hostapd_ready: Caught exception processing DPP AP connector {self.dpp_ap_connector_file}: {ex}",
                           exc_info=True)
            return

    async def send_dpp_onboard_event(self, micronet, device, event_name, reason=None):
        ws_connector = get_ws_connector()
        if not ws_connector:
            return f"No websocket connector configured", 500
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

