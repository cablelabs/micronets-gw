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


class DPPAdapter(WSMessageHandler, HostapdAdapter.HostapdCLIEventHandler):
    EVENT_ONBOARDING_STARTED = "DPPOnboardingStartedEvent"
    EVENT_ONBOARDING_PROGRESS = "DPPOnboardingProgressEvent"
    EVENT_ONBOARDING_COMPLETE = "DPPOnboardingCompleteEvent"
    EVENT_ONBOARDING_FAILED = "DPPOnboardingFailedEvent"
    DPP_ONBOARD_TIMEOUT_S = 20

    def __init__ (self, config, hostapd_adapter):
        WSMessageHandler.__init__(self, "DPP")
        HostapdAdapter.HostapdCLIEventHandler.__init__(self, ("DPP","AP-STA"))
        self.config = config
        self.simulate_response_events = config['DPP_ADAPTER_SIMULATE_ONBOARD_RESPONSE_EVENTS']
        self.simulated_event_wait_s = 6
        self.hostapd_adapter = hostapd_adapter
        self.pending_onboard = None
        self.dpp_config_key_filename = str(config['DPP_CONFIG_KEY_FILE'])
        self.dpp_configurator_id = None
        self.dpp_ap_connector_filename = str(config['DPP_AP_CONNECTOR_FILE'])
        self.dpp_ap_connector = None
        #self.akms = ["psk", "dpp", "sae"] # TODO: Consider making this configurable
        self.akms = ["psk"] # TODO: Consider making this configurable
        self.ssid = None
        self.freq = None
        self.bs_uri_cache = {}

    async def update(self, micronet_list, device_lists):
        logger.info (f"DPPAdapter.update()")
        await self._refresh_all_bootstrap_uris(micronet_list, device_lists)

    async def handle_ws_message(self, message):
        logger.info("DPPAdapter.handle_ws_message: {message}")

    async def onboard_device(self, micronet_id, device_id, onboard_params):
        logger.info(f"{__name__}(micronet '{micronet_id}', device '{device_id}', onboard_params '{onboard_params}')")

        if self.pending_onboard:
            pending_device_id = self.pending_onboard['device']['deviceId']
            pending_micronet_id = self.pending_onboard['micronet']['micronetId']
            raise InvalidUsage (503, message="Only one onboard process can be performed at a time (currently onboarding "
                                             f"device {pending_device_id} into micronet {pending_micronet_id})")
        conf_model = get_conf_model()

        # Make sure an pending updates have been processed
        await conf_model.update_conf_now()

        micronet = conf_model.check_micronet_reference(micronet_id)
        device = conf_model.check_device_reference(micronet_id, device_id)

        qrcode_uri = onboard_params['dpp']['uri']
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
                    logger.warning(f"{__name__}: No onboard is pending - not sending event")

            asyncio.ensure_future(send_dpp_onboard_event_delayed(DPPAdapter.EVENT_ONBOARDING_STARTED, 1))
            asyncio.ensure_future(send_dpp_onboard_event_delayed(DPPAdapter.EVENT_ONBOARDING_PROGRESS,
                                                                 self.simulated_event_wait_s / 2,
                                                                 reason="This is progress"))
            sim_terminal_event = DPPAdapter.EVENT_ONBOARDING_COMPLETE \
                                 if self.simulate_response_events == "with success" \
                                 else DPPAdapter.EVENT_ONBOARDING_FAILED
            logger.info (f"{__name__}: simulating {sim_terminal_event} response to onboard {device_id} "
                         f"in {self.simulated_event_wait_s} seconds")
            asyncio.ensure_future(send_dpp_onboard_event_delayed(sim_terminal_event, self.simulated_event_wait_s,
                                                                 reason="This is only a test...", terminal=True))
            self.pending_onboard = {"micronet":micronet, "device": device, "onboard_params": onboard_params}
            return '', 200

        try:
            qrcode_id = await self._setup_bootstrapping_uris_for_device(micronet, device, qrcode_uri, akms)
            return f'{{"qrcode_id": {qrcode_id}}}', 200
        except InvalidUsage as ex:
            logger.warning(f"{__name__}: Error setting up bootstrapping for device {device_id} in micronet "
                           f"{micronet_id}: {ex.message}", exc_info=True)
            return ex.message, ex.status_code

    async def _refresh_all_bootstrap_uris(self, micronet_list, device_lists):
        logger.info(f"{__name__}")

        for micronet_id, devices in device_lists.items ():
            micronet = micronet_list.get(micronet_id)
            for device_id, device in devices.items():
                dev_dpp_uri = device.get('dppBootstrapUri')
                dev_psk = device.get('psk')
                cached_uri_rec = self.bs_uri_cache.get((micronet_id, device_id))
                if cached_uri_rec:
                    (qrcode_id, cached_dpp_uri, cached_psk) = cached_uri_rec
                    if cached_dpp_uri == dev_dpp_uri and cached_psk == dev_psk:
                        continue
                    else:
                        dpp_uri_del_cmd = HostapdAdapter.DPPBootstrapUriDeleteCommand(qrcode_id=qrcode_id)
                        await self.hostapd_adapter.send_command(dpp_uri_del_cmd)
                        if not await dpp_uri_del_cmd.was_successful():
                            logger.warning(f"{__name__}: Could not delete DPP URI with ID {qrcode_id}"
                                           f"for {micronet_id} device {device_id}")
                        else:
                            logger.info(f"{__name__}: Deleted DPP URI with ID {qrcode_id}"
                                        f" for {micronet_id} device {device_id}")
                if not dev_dpp_uri or not dev_psk:
                    continue

                # Load the devices URI into hostapd
                # Assert: dev_dpp_uri and dev_psk are set and not known to hostapd
                logger.info(f"{__name__}: Setting up bootstrapping for device {device_id} in micronet {micronet_id} "
                            f"with URI {dev_dpp_uri} and PSK {dev_psk}")
                qrcode_id = await self._setup_bootstrapping_uris_for_device(micronet, device, dev_dpp_uri, self.akms)
                self.bs_uri_cache[(micronet_id,device_id)] = (qrcode_id, dev_dpp_uri, dev_psk)
                logger.info(f"{__name__}: Cached URI with ID {qrcode_id}"
                            f" for {micronet_id} device {device_id}: {dev_dpp_uri}")

    async def _setup_bootstrapping_uris_for_device(self, micronet, device, dpp_uri, akms) -> int:
        micronet_id = micronet['micronetId']
        device_id = device['deviceId']
        logger.info(f"{__name__}: Issuing DPP onboarding commands for device {device_id} in micronet {micronet_id}...")
        if not self.hostapd_adapter.is_cli_connected():
            raise InvalidUsage(500, message=f"Hostapd CLI is not connected (is hostapd running?)")

        if not self.hostapd_adapter.is_cli_ready():
            raise InvalidUsage(500, message=f"Hostapd CLI is not ready (is hostapd running?)")

        logger.info (f"{__name__}:   DPP QRCode URI: {dpp_uri}")
        add_qrcode_cmd = await self.hostapd_adapter.send_command(HostapdAdapter.DPPAddQRCodeCLICommand(dpp_uri))
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

        if ";V:2;" in dpp_uri:
            # Perform DPP V2 onboarding (set bootstrapping info for DPP Chirp/Presence Announcement)
            dpp_bootstrap_set_cmd = HostapdAdapter.DPPBootstrapSet(self.dpp_configurator_id, qrcode_id, self.ssid,
                                                                   akms, psk=psk, passphrase=passphrase)
            await self.hostapd_adapter.send_command(dpp_bootstrap_set_cmd)
            result = await dpp_bootstrap_set_cmd.get_response()
            logger.info(f"{__name__}: Bootstrap Set result: {result}")
            if await dpp_bootstrap_set_cmd.was_successful():
                logger.info(f"{__name__}: Successfully set credentials for URI {dpp_uri}")
            else:
                logger.warning(f"{__name__}: Could not set credentials for URI {dpp_uri}")
                raise InvalidUsage(503, message=f"Could not set DPP v2 DPP credentials for micronet "
                                                f"{micronet_id} device {device_id} URI {dpp_uri}")
        else:
            # Perform DPP V1 onboarding (send Auth Init)
            dpp_auth_init_cmd = HostapdAdapter.DPPAuthInitCommand(self.dpp_configurator_id, qrcode_id, self.ssid,
                                                                  akms, psk=psk, passphrase=passphrase, freq=self.freq)
            self.pending_onboard = {"micronet":micronet, "device": device, "dpp_uri": dpp_uri}
            asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device, DPPAdapter.EVENT_ONBOARDING_STARTED,
                                                              f"DPP Started (issuing \"{dpp_auth_init_cmd.get_command_string()}\")"))
            await self.hostapd_adapter.send_command(dpp_auth_init_cmd)
            result = await dpp_auth_init_cmd.get_response()
            logger.info(f"{__name__}: Auth Init result: {result}")

            async def onboard_timeout_handler():
                await asyncio.sleep(DPPAdapter.DPP_ONBOARD_TIMEOUT_S)
                if self.pending_onboard:
                    logger.info(f"{__name__}: Onboarding TIMED OUT (after {DPPAdapter.DPP_ONBOARD_TIMEOUT_S} seconds)")
                    pend_micronet = self.pending_onboard['micronet']
                    pend_device = self.pending_onboard['device']
                    await self.send_dpp_onboard_event(pend_micronet, pend_device,
                                                      DPPAdapter.EVENT_ONBOARDING_FAILED,
                                                      f"Onboarding timed out (after {DPPAdapter.DPP_ONBOARD_TIMEOUT_S} seconds)")
                    self.pending_onboard = None
                else:
                    logger.info(f"{__name__}: Onboarding completed before timeout (< {DPPAdapter.DPP_ONBOARD_TIMEOUT_S} seconds)")

            if await dpp_auth_init_cmd.was_successful():
                self.pending_timeout_task = asyncio.ensure_future(onboard_timeout_handler())
            else:
                asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device, DPPAdapter.EVENT_ONBOARDING_FAILED,
                                                                  f"DPP Authorization failed {dpp_auth_init_cmd.get_command_string()} returned: ({result})"))
                raise InvalidUsage(503, message=f"DPP authorization could not be initiated for micronet "
                                                f"{micronet['micronetId']} device {device['deviceId']}: "
                                                f"{dpp_auth_init_cmd.get_response()}")
        return qrcode_id

    async def reprovision_device(self, micronet_id, device_id,):
        logger.info(f"DPPAdapter.reprovision_device(micronet '{micronet_id}', device '{device_id}'')")
        conf_model = get_conf_model()

        # Make sure an pending updates have been processed
        await conf_model.update_conf_now()

        micronet = conf_model.check_micronet_reference(micronet_id)
        device = conf_model.check_device_reference(micronet_id, device_id)

        if not self.hostapd_adapter.is_cli_connected():
            return "Hostapd CLI is not connected", 500

        if not self.hostapd_adapter.is_cli_ready():
            return "Hostapd CLI is not ready (hostapd is probably not running)", 500

        logger.info(f"DPPAdapter.onboard_device: Issuing DPP reprovisioning commands for device '{device_id}' in micronet '{micronet_id}...")

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

    async def handle_hostapd_cli_event(self, event_msg):
        logger.info(f"DPPAdapter.handle_hostapd_cli_event({event_msg})")
        if self.pending_onboard:
            micronet = self.pending_onboard['micronet']
            device = self.pending_onboard['device']
            if event_msg.startswith("DPP-AUTH-INIT-FAILED"):
                self.pending_onboard = None
                self.pending_timeout_task.cancel()
                asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device,
                                                                  DPPAdapter.EVENT_ONBOARDING_FAILED,
                                                                  f"DPP Authorization failed ({event_msg})"))
            elif event_msg.startswith("DPP-AUTH-SUCCESS") or event_msg.startswith("DPP-CONF-SENT"):
                asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device,
                                                                  DPPAdapter.EVENT_ONBOARDING_PROGRESS,
                                                                  f"DPP Progress ({event_msg})"))
            elif event_msg.startswith("AP-STA-CONNECTED") and device['macAddress'].lower() in event_msg:
                self.pending_onboard = None
                self.pending_timeout_task.cancel()
                asyncio.ensure_future(self.send_dpp_onboard_event(micronet, device, DPPAdapter.EVENT_ONBOARDING_COMPLETE,
                                                                  f"DPP Onboarding Complete ({event_msg})"))
        else:
            (event_name, space, event_val) = event_msg.partition(' ')
            # The AP's DPP connector params for the active configurator comes via async events
            #  so need to put the (3) pieces together...
            check_ap_connector_complete = False
            if event_name == "DPP-CONNECTOR":
                logger.info(f"DPPAdapter.handle_hostapd_cli_event: Received AP connector: {event_val}")
                self.dpp_ap_connector['dpp_connector'] = event_val
                check_ap_connector_complete = True
                pass
            elif event_name == "DPP-C-SIGN-KEY":
                logger.info(f"DPPAdapter.handle_hostapd_cli_event: Received AP c-sign key: {event_val}")
                self.dpp_ap_connector['dpp_csign'] = event_val
                check_ap_connector_complete = True
                pass
            elif event_name == "DPP-NET-ACCESS-KEY":
                logger.info(f"DPPAdapter.handle_hostapd_cli_event: Received AP net access key: {event_val}")
                self.dpp_ap_connector['dpp_netaccesskey'] = event_val
                check_ap_connector_complete = True
                pass
            elif event_msg.startswith("DPP-CONFOBJ-SSID"):
                logger.info(f"DPPAdapter.handle_hostapd_cli_event: Received AP conf object SSID: {event_val}")

            if check_ap_connector_complete and self.dpp_ap_connector.get("dpp_connector") \
                    and self.dpp_ap_connector.get("dpp_csign") and  self.dpp_ap_connector.get("dpp_netaccesskey"):
                try:
                    dpp_ap_connector_json = json.dumps(self.dpp_ap_connector, indent=3) + "\n"
                    connector_filename_for_ssid = self.dpp_ap_connector_filename.format(**{"ssid": self.ssid})
                    logger.info(f"DPPAdapter.handle_hostapd_cli_event: Writing connector "
                                f"to file {connector_filename_for_ssid}: {dpp_ap_connector_json}")
                    connector_file_for_ssid = Path(connector_filename_for_ssid)
                    connector_file_for_ssid.write_text(dpp_ap_connector_json)
                except Exception as ex:
                    logger.warning(f"DPPAdapter: _configure_for_ssid: Caught exception "
                                   f"writing DPP AP connector to {connector_filename_for_ssid}: {ex}")

    async def handle_hostapd_ready(self):
        logger.info(f"DPPAdapter.handle_hostapd_ready()")

        self.ssid = self.hostapd_adapter.get_status_var('ssid')[0]
        logger.info(f"DPPAdapter.handle_hostapd_ready:   SSID: {self.ssid}")
        await self._configure_for_ssid()

    async def _configure_for_ssid(self):
        logger.info(f"DPPAdapter._configure_for_ssid: Handling SSID change to {self.ssid}")

        # Initialize the DPP config key/configurator for the current SSID
        dpp_config_key_filename_for_ssid = self.dpp_config_key_filename.format(**{"ssid": self.ssid})
        dpp_config_key_file_for_ssid = Path(dpp_config_key_filename_for_ssid)
        if dpp_config_key_file_for_ssid.exists():
            try:
                self.dpp_config_key = dpp_config_key_file_for_ssid.read_text()
                logger.info(f"DPPAdapter._configure_for_ssid: Loaded DPP configurator key "
                            f"from {dpp_config_key_filename_for_ssid}")
            except Exception as ex:
                logger.warning(f"DPPAdapter: _configure_for_ssid: Caught exception "
                               f"reading {dpp_config_key_filename_for_ssid}: {ex}")
                return
        else:
            # Create a prime256v1 key
            self.dpp_config_key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p).to_der().hex()
            dpp_config_key_file_for_ssid.write_text(self.dpp_config_key)
            logger.info(f"DPPAdapter._configure_for_ssid: Saved new configurator key to {dpp_config_key_filename_for_ssid}")

        add_configurator_cmd = HostapdAdapter.DPPAddConfiguratorCLICommand(curve="prime256v1", key=self.dpp_config_key)
        await self.hostapd_adapter.send_command(add_configurator_cmd)
        self.dpp_configurator_id = await add_configurator_cmd.get_configurator_id()
        logger.info(f"DPPAdapter._configure_for_ssid: DPP Configurator ID: {self.dpp_configurator_id}")

        # Initialize the AP's DPP connector for the current SSID/configurator
        connector_filename_for_ssid = self.dpp_ap_connector_filename.format(**{"ssid": self.ssid})
        connector_file_for_ssid = Path(connector_filename_for_ssid)
        try:
            if connector_file_for_ssid.exists():
                self.dpp_ap_connector = json.loads(connector_file_for_ssid.read_text())
                logger.info(f"DPPAdapter._configure_for_ssid: Loaded AP Connector from {connector_filename_for_ssid }")
            else:
                # Create the AP's connector
                logger.info(f"DPPAdapter: _configure_for_ssid: Creating a DPP Connector for the AP")
                self.dpp_ap_connector = {}
                dpp_config_sign_cmd = HostapdAdapter.DPPConfiguratorDPPSignCLICommand(self.dpp_configurator_id,
                                                                                      ssid=self.ssid)
                await self.hostapd_adapter.send_command(dpp_config_sign_cmd)
                result = await dpp_config_sign_cmd.get_response()
                logger.info(f"{__name__}: AP connector signing command result: {result}")
        except Exception as ex:
            logger.warning(f"DPPAdapter: _handle_ssid_change: Caught exception processing DPP AP connector "
                           f"{connector_filename_for_ssid}: {ex}",
                           exc_info=True)

        # Now reset all the bootstrap settings since they need to be associated with the changed SSID/configurator
        await self._reset_all_dev_bootstrap_info()

    async def _reset_all_dev_bootstrap_info(self):
        try:
            # Clear hostapd's URI DB - then reload it from the bootstrap URIs of micronet devices
            dpp_uri_del_cmd = HostapdAdapter.DPPBootstrapUriDeleteCommand()
            await self.hostapd_adapter.send_command(dpp_uri_del_cmd)
            if not await dpp_uri_del_cmd.was_successful():
                logger.warning(f"{__name__}: Could not delete all the DPP URIs")
            self.bs_uri_cache = {}
            (micronets, devices) = get_conf_model().get_micronets_and_devices()
            await self._refresh_all_bootstrap_uris(micronets, devices)
        except Exception as ex:
            logger.warning(f"DPPAdapter: _reset_all_bootstrap_uris: Caught exception setting up DPP URIs: {ex}",
                           exc_info=True)

    async def handle_hostapd_status_var_change(self):
        # Note: Handler is called whenever there's a change to one or more status variables
        logger.info(f"DPPAdapter.handle_hostapd_status_var_change()")
        cur_ssids = self.hostapd_adapter.get_status_var("ssid")
        if cur_ssids[0] == self.ssid:
            logger.info(f"DPPAdapter.handle_hostapd_status_var_change: DPP credentials "
                        f"already set for \"{cur_ssids[0]}\" - nothing to do")
            return
        logger.info(f"DPPAdapter.handle_hostapd_status_var_change: Changing DPP credentials "
                    f"from SSID '{self.ssid}' to SSID '{cur_ssids[0]}'")
        self.ssid = cur_ssids[0]

        # We need to change the hostapd DPP creds to reflect the changed SSID
        await self._configure_for_ssid()

    async def send_dpp_onboard_event(self, micronet, device, event_name, reason=None):
        ws_connector = get_ws_connector()
        if not ws_connector:
            return f"No websocket connector configured", 500
        if not ws_connector.is_ready():
            ws_uri = ws_connector.get_connect_uri()
            logger.info (f"DPPAdapter.send_dpp_onboard_event: websocket not connected (ws uri: {ws_uri})")
            return f"The websocket connection to {ws_uri} is not connected/ready", 500

        dpp_onboarding_complete_event = { event_name: {
                                          'micronetId': micronet['micronetId'],
                                          'deviceId': device['deviceId']
                                          } }
        dev_mac_field = device.get('macAddress')
        if dev_mac_field:
            dpp_onboarding_complete_event['macAddress'] = dev_mac_field
        if reason:
            dpp_onboarding_complete_event[event_name]['reason'] = reason
        logger.info (f"DPPAdapter.send_dpp_onboard_event: sending:")
        logger.info (json.dumps (dpp_onboarding_complete_event, indent=4))
        await ws_connector.send_event_message ("DPP", event_name, dpp_onboarding_complete_event)

