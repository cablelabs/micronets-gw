from quart import jsonify
from .utils import update_deep, InvalidUsage
from ipaddress import IPv4Network, IPv4Address, AddressValueError, NetmaskValueError
from netaddr import EUI

import asyncio
import json
import copy
import logging

# This is the Model for the gateway service conf file entries

logger = logging.getLogger ('micronets-gw-service')


class GatewayServiceConf:
    def __init__ (self, ws_connection, db_adapter, dhcp_adapter, flow_adapter, hostapd_adapter, netreach_adapter, min_update_interval_s):
        self.ws_connection = ws_connection
        self.db_adapter = db_adapter
        self.dhcp_adapter = dhcp_adapter
        self.flow_adapter = flow_adapter
        self.hostapd_adapter = hostapd_adapter
        self.netreach_adapter = netreach_adapter
        self.min_update_interval_s = min_update_interval_s
        self.update_conf_task = None
        read_conf = db_adapter.read_from_conf()
        self.micronet_list = read_conf['micronets']
        self.device_lists = read_conf['devices']
        self.device_status = {m: dict.fromkeys(self.device_lists[m], "unknown") for m in self.device_lists.keys()}
        logger.info ("GatewayServiceConf instantiated with:")
        logger.info ("Micronet list:")
        logger.info (json.dumps (self.micronet_list, indent=2))
        logger.info ("Device lists:")
        logger.info (json.dumps (self.device_lists, indent=2))
        logger.info ("Device status:")
        logger.info (json.dumps (self.device_status, indent=2))

    async def queue_conf_update (self):
        self.cancel_queued_update()
        logger.info ("Queueing configuration update...")
        self.update_conf_task = asyncio.ensure_future (self.update_conf_delayed())

    async def update_conf_delayed (self):
        await asyncio.sleep(self.min_update_interval_s)
        await self.update_conf()

    def cancel_queued_update(self):
        if self.update_conf_task and not self.update_conf_task.cancelled():
            logger.info("Cancelling queued configuration update...")
            self.update_conf_task.cancel ()
            try:
                self.update_conf_task.result()
            except Exception as ex:
                pass
        self.update_conf_task = None

    async def update_conf_now(self):
        self.cancel_queued_update()
        logger.info ("Updating configuration...")
        await self.update_conf()

    async def update_conf (self):
        try:
            await self.db_adapter.update (self.micronet_list, self.device_lists)
            if self.dhcp_adapter:
                await self.dhcp_adapter.update (self.micronet_list, self.device_lists)
            if self.flow_adapter:
                await self.flow_adapter.update(self.micronet_list, self.device_lists)
            if self.hostapd_adapter:
                await self.hostapd_adapter.update(self.micronet_list, self.device_lists)
        except Exception as ex:
            logger.warning(f"Caught exception performing update: {ex}", exc_info=True)

    #
    # Interface Operations
    #
    def retrieve_wifi_interfaces(self):
        interfaces = []
        if self.hostapd_adapter:
            bss = self.hostapd_adapter.get_status_var('bss')
            bssid = self.hostapd_adapter.get_status_var('bssid')
            ssid = self.hostapd_adapter.get_status_var('ssid')
            sta_count = self.hostapd_adapter.get_status_var('num_sta')

            for k in bss.keys():
                int_entry = {"medium": "wifi",
                             "interfaceId": bss[k],
                             "macAddress": bssid[k],
                             "ssid": ssid[k]}
                logger.debug(f"GatewayServiceConf: interface {k}: {json.dumps(int_entry)}")
                interfaces.append(int_entry)
        return interfaces

    def retrieve_wired_interfaces(self):
        interfaces = []
        # TODO: Implement
        return interfaces

    async def get_interfaces(self, medium=None):
        logger.info (f"GatewayServiceConf.get_interfaces()")
        interfaces = []
        if medium and not (medium == "wifi" or medium == "wired"):
            raise InvalidUsage(404, message=f"interface medium '{medium}' is unknown")
        if medium is None or medium == "wifi":
            interfaces += self.retrieve_wifi_interfaces()
        if medium is None or medium == "wired":
            interfaces += self.retrieve_wired_interfaces()

        return jsonify({'interfaces': interfaces}), 200

    #
    # micronet Operations
    #
    def check_micronet_reference (self, micronet_id):
        if micronet_id not in self.micronet_list:
            raise InvalidUsage (404, message=f"micronet '{micronet_id}' doesn't exist in micronet list")
        if micronet_id not in self.device_lists:
            raise InvalidUsage (404, message=f"micronet '{micronet_id}' doesn't exist in device list")
        return self.micronet_list[micronet_id]

    def check_micronet_unique (self, micronet):
        micronet_id = micronet ['micronetId'].lower ()
        if micronet_id in self.micronet_list:
            raise InvalidUsage (409, message=f"micronet '{micronet_id}' already exists")

    def check_micronet_params (self, micronet_to_check, excluded_micronet_id=None):
        micronet_id_to_check = micronet_to_check ['micronetId']
        ipv4_net_params_to_check = micronet_to_check ['ipv4Network']
        netaddr = ipv4_net_params_to_check ['network']
        netmask = ipv4_net_params_to_check ['mask']
        try:
            micronet_network_to_check = IPv4Network (netaddr + "/" + netmask, strict=True)
            if 'gateway' in ipv4_net_params_to_check:
                gateway_addr = ipv4_net_params_to_check ['gateway']
                gateway_net = IPv4Network (gateway_addr + "/32")
                if not gateway_net.overlaps (micronet_network_to_check):
                    raise InvalidUsage (400, message=f"Gateway address {gateway_addr} "
                                                     f"isn't in the '{micronet_id_to_check}' "
                                                     f"micronet ({micronet_network_to_check})")
            for micronet_id, micronet in self.micronet_list.items ():
                if (excluded_micronet_id == micronet_id):
                    continue
                ipv4_net_params = micronet ['ipv4Network']
                micronet_network = IPv4Network (ipv4_net_params ['network'] + "/" + ipv4_net_params ['mask'])
                if micronet_network_to_check.overlaps (micronet_network):
                    raise InvalidUsage (400, message=f"micronet '{micronet_id_to_check}' network "
                                                     f"{micronet_network_to_check} overlaps existing "
                                                     f"micronet '{micronet_id}' (network {micronet_network})")
        except (AddressValueError, NetmaskValueError) as ve:
            raise InvalidUsage (400, message=f"Error validating micronet '{micronet_id}' "
                                             f"(network {netaddr}/{netmask}): {ve}")

    async def get_all_micronets (self):
        logger.info (f"GatewayServiceConf.get_all_micronets ()")
        return jsonify ({'micronets': list (self.micronet_list.values ())}), 200

    async def create_micronets (self, micronets):
        # Check that all the supplied micronets are unique and valid before incorporating them
        for micronet in micronets:
            self.check_micronet_unique (micronet)
            self.check_micronet_params (micronet)
        for micronet in micronets:
            micronet_id = micronet ['micronetId'].lower ()
            self.micronet_list [micronet_id] = micronet
            self.device_lists [micronet_id] = {}
        await self.queue_conf_update ()
        return jsonify ({'micronets': micronets}), 201

    async def create_micronet (self, micronet):
        self.check_micronet_unique (micronet)
        self.check_micronet_params (micronet)
        micronet_id = micronet ['micronetId'].lower ()
        self.micronet_list [micronet_id] = micronet
        self.device_lists [micronet_id] = {}
        await self.queue_conf_update ()
        return jsonify ({'micronet': micronet}), 201

    async def delete_all_micronets (self):
        logger.info (f"GatewayServiceConf.delete_all_devices: micronet list: {self.micronet_list}")
        self.micronet_list.clear()
        self.device_lists.clear()
        await self.queue_conf_update ()
        return '', 204

    async def update_micronet (self, micronet_update, micronet_id):
        logger.info (f"GatewayServiceConf.update_micronet ({micronet_update}, {micronet_id})")
        self.check_micronet_reference (micronet_id)
        target_micronet = self.micronet_list [micronet_id]
        if 'micronetId' in micronet_update:
            micronet_update_id = micronet_update ['micronetId'].lower ()
            if micronet_update_id != micronet_id:
                raise InvalidUsage (409, message=f"Update can only update micronet '{micronet_id}' "
                                                 f"('{micronet_update_id}' provided)")
        updated_micronet = copy.deepcopy (target_micronet)
        update_deep (updated_micronet, micronet_update)

        self.check_micronet_params (updated_micronet, excluded_micronet_id=micronet_id)
        self.check_devices_for_micronet (updated_micronet, self.device_lists [micronet_id])

        self.micronet_list [micronet_id] = updated_micronet

        await self.queue_conf_update ()
        return jsonify ({'micronet': updated_micronet}), 200

    async def get_micronet (self, micronet_id):
        logger.info (f"GatewayServiceConf.get_micronet ({micronet_id})")
        if micronet_id not in self.micronet_list:
            raise InvalidUsage (404, message=f"micronet '{micronet_id}' not found")
        micronet = self.micronet_list [micronet_id]
        return jsonify ({'micronet': micronet}), 200

    async def delete_micronet (self, micronet_id):
        logger.info (f"GatewayServiceConf.delete_micronet ({micronet_id})")
        self.check_micronet_reference (micronet_id)
        del self.micronet_list [micronet_id]
        del self.device_lists [micronet_id]
        await self.queue_conf_update ()
        return '', 204

    #
    # Device Operations
    #
    def check_device_reference (self, micronet_id, device_id):
        micronet_devices = self.device_lists [micronet_id]
        if device_id not in micronet_devices:
            raise InvalidUsage (404, message=f"Device '{device_id}' doesn't exist in micronet '{micronet_id}'")
        return micronet_devices[device_id]

    def check_device_unique (self, device_id, micronet_id):
        device_list = self.device_lists [micronet_id]
        if device_id in device_list:
            raise InvalidUsage (409, message=f"Supplied device '{device_id}' already exists for "
                                             f"micronet '{micronet_id}'");
        return device_id

    def check_device_for_micronet (self, device, micronet):
        ipv4_net_params = micronet ['ipv4Network']
        netaddr = ipv4_net_params ['network']
        netmask = ipv4_net_params ['mask']
        devaddr = device ['networkAddress']['ipv4']
        try:
            micronet_network = IPv4Network (netaddr + "/" + netmask, strict=True)
            host_network = IPv4Network (devaddr + "/255.255.255.255")
            if not micronet_network.overlaps (host_network):
                raise InvalidUsage (400, message=f"Device '{device ['deviceId']}' address {devaddr} "
                                                 f"isn't compatible with micronet '{micronet ['micronetId']}' "
                                                 f"({micronet_network})")
        except (AddressValueError, NetmaskValueError) as ve:
            raise InvalidUsage (400, message=f"Error validating address {devaddr} for micronet "
                                             f"'{micronet ['micronetId']}' ({micronet_network}): {ve}")

    def check_devices_for_micronet (self, micronet, device_list):
        for device_id, device in device_list.items ():
            self.check_device_for_micronet (device, micronet)

    def check_device_mac_unique (self, device_to_check, excluded_micronet_id=None, excluded_device_id=None):
        addr_field_to_check = device_to_check ['macAddress']['eui48']
        addr_to_check = EUI (addr_field_to_check)
        for micronet_id, device_list in self.device_lists.items ():
            for device_id, device in device_list.items ():
                if (excluded_micronet_id == micronet_id) and (excluded_device_id == device_id):
                    continue
                dev_addr_field = device ['macAddress']['eui48']
                dev_addr = EUI (dev_addr_field)
                if (dev_addr == addr_to_check):
                    raise InvalidUsage (400, message=f"MAC address of device "
                                                     f"'{device_to_check ['deviceId']}' is not unique "
                                                     f"(MAC address {addr_to_check} found in micronet "
                                                     f"'{micronet_id}' device '{device_id}')")

    def check_device_ip_unique (self, device_to_check, micronet_id, excluded_device_id=None):
        addr_field_to_check = device_to_check ['networkAddress']['ipv4']
        deviceid_to_check = device_to_check ['deviceId']
        addr_to_check = IPv4Address (addr_field_to_check)
        device_list = self.device_lists [micronet_id]
        for device_id, device in device_list.items ():
            if (excluded_device_id == device_id):
                continue
            dev_addr_field = device ['networkAddress']['ipv4']
            dev_addr = IPv4Address (dev_addr_field)
            if (dev_addr == addr_to_check):
                raise InvalidUsage (400, message=f"IP address of device '{deviceid_to_check}' "
                                                 f"is not unique (IP address {addr_to_check} found "
                                                 f"in device '{device_id}')")

    async def get_micronetid_deviceid_for_mac (self, mac_address):
        addr_to_check = EUI (mac_address)
        for micronet_id, device_list in self.device_lists.items ():
            for device_id, device in device_list.items ():
                dev_addr_field = device ['macAddress']['eui48']
                dev_addr = EUI (dev_addr_field)
                if dev_addr == addr_to_check:
                    return micronet_id, device_id
        return None, None

    async def dump_mock_lists (self):
        logger.info ("micronets:")
        logger.info (json.dumps (self.micronet_list, indent=4))
        logger.info ("device_lists:")
        logger.info (json.dumps (self.device_lists, indent=4))

    async def get_all_devices (self, micronet_id):
        logger.info (f"GatewayServiceConf.get_all_devices ({micronet_id})")
        self.check_micronet_reference (micronet_id)
        return jsonify ({'devices': list (self.device_lists [micronet_id].values ())}), 200

    async def delete_all_devices (self, micronet_id):
        logger.info (f"GatewayServiceConf.delete_all_devices ({micronet_id})")
        self.check_micronet_reference (micronet_id)
        self.device_lists [micronet_id].clear ()
        await self.queue_conf_update ()
        return '', 204

    async def create_device (self, device, micronet_id):
        logger.info (f"GatewayServiceConf.create_device ({device}, {micronet_id})")
        self.check_micronet_reference (micronet_id)
        device_list = self.device_lists [micronet_id]
        device_id = device ['deviceId'].lower ()
        micronet = self.micronet_list [micronet_id]
        self.check_device_unique (device_id, micronet_id)
        self.check_device_for_micronet (device, micronet)
        self.check_device_mac_unique (device)
        self.check_device_ip_unique (device, micronet_id)
        device_list [device_id] = device
        await self.queue_conf_update ()
        return jsonify ({'device': device}), 201

    async def create_devices (self, devices, micronet_id):
        logger.info (f"GatewayServiceConf.create_devices ({devices}, {micronet_id})")
        self.check_micronet_reference (micronet_id)
        micronet = self.micronet_list [micronet_id]
        # Check that all the supplied deviceIds are unique before incorporating them
        for device in devices:
            device_id = device ['deviceId'].lower ()
            self.check_device_unique (device_id, micronet_id)
            self.check_device_for_micronet (device, micronet)
            self.check_device_mac_unique (device)
            self.check_device_ip_unique (device, micronet_id)

        device_list = self.device_lists [micronet_id]
        for device in devices:
            device_id = device ['deviceId'].lower ()
            device_list [device_id] = device
        await self.queue_conf_update ()
        return jsonify ({'devices': devices}), 201

    async def update_device (self, device_update, micronet_id, device_id):
        logger.info (f"GatewayServiceConf.update_device ({device_update}, {micronet_id}, {device_id})")
        self.check_micronet_reference (micronet_id)
        self.check_device_reference (micronet_id, device_id)
        device_list = self.device_lists [micronet_id]
        target_device = device_list [device_id]
        if 'deviceId' in device_update:
            device_update_id = device_update ['deviceId'].lower ()
            if device_update_id != device_id:
                raise InvalidUsage (409, message=f"Update can only update device '{device_id}' "
                                                 f"('{device_update_id}' provided)")
        updated_device = copy.deepcopy (target_device)
        update_deep (updated_device, device_update)

        self.check_device_for_micronet (updated_device, self.micronet_list [micronet_id])
        self.check_device_mac_unique (updated_device, excluded_micronet_id = micronet_id,
                                                      excluded_device_id = device_id)
        self.check_device_ip_unique (updated_device, micronet_id, excluded_device_id = device_id)

        device_list [device_id] = updated_device
        await self.queue_conf_update ()
        return jsonify ({'device': updated_device}), 200

    async def get_device (self, micronet_id, device_id):
        logger.info (f"GatewayServiceConf.get_device ({micronet_id}, {device_id})")
        logger.info (json.dumps (self.device_lists, indent=4))
        self.check_micronet_reference (micronet_id)
        self.check_device_reference (micronet_id, device_id)
        return jsonify ({'device': self.device_lists [micronet_id] [device_id]}), 200

    async def delete_device (self, micronet_id, device_id):
        logger.info (f"GatewayServiceConf.delete_device ({micronet_id}, {device_id})")
        self.check_micronet_reference (micronet_id)
        self.check_device_reference (micronet_id, device_id)
        del self.device_lists [micronet_id] [device_id]
        await self.queue_conf_update ()
        return '', 204

    async def process_dhcp_lease_event (self, dhcp_lease_event):
        logger.info (f"GatewayServiceConf.process_lease_event ({dhcp_lease_event})")

        event_fields = dhcp_lease_event ['leaseChangeEvent']
        action = event_fields ['action']

        mac_addr = event_fields ['macAddress']['eui48']
        net_addr = event_fields ['networkAddress']['ipv4']
        micronet_id, device_id = await self.get_micronetid_deviceid_for_mac (mac_addr)
        if not (micronet_id and device_id):
            logger.info (f"GatewayServiceConf.process_lease_event: Could not find device with mac {mac_addr}")
            raise InvalidUsage (404, message=f"No device found with mac address {mac_addr}")
        logger.info (f"GatewayServiceConf.process_lease_event: found micronet/device {micronet_id}/{device_id} for mac {mac_addr}")

        if self.ws_connection:
            await self.ws_connection.process_dhcp_lease_event(micronet_id, device_id, action, mac_addr, net_addr)
        if self.netreach_adapter:
            await self.netreach_adapter.process_dhcp_lease_event(micronet_id, device_id, action, mac_addr, net_addr)

        return '', 200

    async def process_psk_lookup(self, psk_lookup_fields):
        logger.info(f"GatewayServiceConf.process_psk_lookup({psk_lookup_fields})")

        if self.netreach_adapter:
            return await self.netreach_adapter.lookup_psk_for_device(psk_lookup_fields)
        else:
            return f"Could not lookup PSK {psk_lookup_fields['psk']} for MAC {psk_lookup_fields['mac']}: "\
                    "The NetReach adapter is not enabled", 400