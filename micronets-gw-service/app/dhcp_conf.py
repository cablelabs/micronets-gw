from quart import jsonify
from .utils import update_deep, InvalidUsage
from threading import Timer
from ipaddress import IPv4Network, IPv4Address, AddressValueError, NetmaskValueError
from netaddr import EUI

import asyncio
import json
import copy
import logging

# This is the Model for the DHCP conf file entries

logger = logging.getLogger ('micronets-gw-service')

class DHCPConf:
    def __init__ (self, ws_connector, dhcp_adapter, flow_adapter, min_update_interval_s):
        self.ws_connector = ws_connector
        self.dhcp_adapter = dhcp_adapter
        self.flow_adapter = flow_adapter
        self.min_update_interval_s = min_update_interval_s
        self.update_conf_task = None
        read_conf = dhcp_adapter.read_from_conf ()
        self.subnet_list = read_conf ['subnets']
        self.device_lists = read_conf ['devices']
        logger.info ("DHCPConf Instantiated with:")
        logger.info ("Subnet list:")
        logger.info (json.dumps (self.subnet_list, indent=2))
        logger.info ("Device lists:")
        logger.info (json.dumps (self.device_lists, indent=2))

    async def update_conf (self):
        if self.update_conf_task:
            logger.info("Cancelling queued configuration update...")
            self.update_conf_task.cancel ()
        logger.info ("Queueing configuration update...")
        self.update_conf_task = asyncio.ensure_future (self.update_conf_delayed())

    async def update_conf_delayed (self):
        await asyncio.sleep(self.min_update_interval_s)
        logger.info ("Updating configuration...")

        self.update_conf_task = None
        self.dhcp_adapter.save_to_conf (self.subnet_list, self.device_lists)
        if self.flow_adapter:
            await self.flow_adapter.update(self.subnet_list, self.device_lists)

    #
    # Subnet Operations
    #
    def check_subnet_reference (self, subnet_id):
        if subnet_id not in self.subnet_list:
            raise InvalidUsage (404, message=f"Subnet '{subnet_id}' doesn't exist in subnet list")
        if subnet_id not in self.device_lists:
            raise InvalidUsage (404, message=f"Subnet '{subnet_id}' doesn't exist in device list")

    def check_subnet_unique (self, subnet):
        subnet_id = subnet ['subnetId'].lower ()
        if subnet_id in self.subnet_list:
            raise InvalidUsage (409, message=f"Subnet '{subnet_id}' already exists")

    def check_subnet_params (self, subnet_to_check, excluded_subnet_id=None):
        subnet_id_to_check = subnet_to_check ['subnetId']
        ipv4_net_params_to_check = subnet_to_check ['ipv4Network']
        netaddr = ipv4_net_params_to_check ['network']
        netmask = ipv4_net_params_to_check ['mask']
        try:
            subnet_network_to_check = IPv4Network (netaddr + "/" + netmask, strict=True)
            if 'gateway' in ipv4_net_params_to_check:
                gateway_addr = ipv4_net_params_to_check ['gateway']
                gateway_net = IPv4Network (gateway_addr + "/32")
                if not gateway_net.overlaps (subnet_network_to_check):
                    raise InvalidUsage (400, message=f"Gateway address {gateway_addr} "
                                                     f"isn't in the '{subnet_id_to_check}' "
                                                     f"subnet ({subnet_network_to_check})")
            for subnet_id, subnet in self.subnet_list.items ():
                if (excluded_subnet_id == subnet_id):
                    continue
                ipv4_net_params = subnet ['ipv4Network']
                subnet_network = IPv4Network (ipv4_net_params ['network'] + "/" + ipv4_net_params ['mask'])
                if subnet_network_to_check.overlaps (subnet_network):
                    raise InvalidUsage (400, message=f"Subnet '{subnet_id_to_check}' network "
                                                     f"{subnet_network_to_check} overlaps existing "
                                                     f"subnet '{subnet_id}' (network {subnet_network})")
        except (AddressValueError, NetmaskValueError) as ve:
            raise InvalidUsage (400, message=f"Error validating subnet '{subnet_id}' "
                                             f"(network {netaddr}/{netmask}): {ve}")

    async def get_all_subnets (self):
        logger.info (f"DHCPConf.get_all_subnets ()")
        return jsonify ({'subnets': list (self.subnet_list.values ())}), 200

    async def create_subnets (self, subnets):
        # Check that all the supplied subnets are unique and valid before incorporating them
        for subnet in subnets:
            self.check_subnet_unique (subnet)
            self.check_subnet_params (subnet)
        for subnet in subnets:
            subnet_id = subnet ['subnetId'].lower ()
            self.subnet_list [subnet_id] = subnet
            self.device_lists [subnet_id] = {}
        await self.update_conf ()
        return jsonify ({'subnets': subnets}), 201

    async def create_subnet (self, subnet):
        self.check_subnet_unique (subnet)
        self.check_subnet_params (subnet)
        subnet_id = subnet ['subnetId'].lower ()
        self.subnet_list [subnet_id] = subnet
        self.device_lists [subnet_id] = {}
        await self.update_conf ()
        return jsonify ({'subnet': subnet}), 201

    async def delete_all_subnets (self):
        logger.info (f"DHCPConf.delete_all_devices: Subnet list: {self.subnet_list}")
        self.subnet_list.clear()
        self.device_lists.clear()
        await self.update_conf ()
        return '', 204

    async def update_subnet (self, subnet_update, subnet_id):
        logger.info (f"DHCPConf.update_subnet ({subnet_update}, {subnet_id})")
        self.check_subnet_reference (subnet_id)
        target_subnet = self.subnet_list [subnet_id]
        if 'subnetId' in subnet_update:
            subnet_update_id = subnet_update ['subnetId'].lower ()
            if subnet_update_id != subnet_id:
                raise InvalidUsage (409, message=f"Update can only update subnet '{subnet_id}' "
                                                 f"('{subnet_update_id}' provided)")
        updated_subnet = copy.deepcopy (target_subnet)
        update_deep (updated_subnet, subnet_update)

        self.check_subnet_params (updated_subnet, excluded_subnet_id=subnet_id)
        self.check_devices_for_subnet (updated_subnet, self.device_lists [subnet_id])

        self.subnet_list [subnet_id] = updated_subnet

        await self.update_conf ()
        return jsonify ({'subnet': updated_subnet}), 200

    async def get_subnet (self, subnet_id):
        logger.info (f"DHCPConf.get_subnet ({subnet_id})")
        if subnet_id not in self.subnet_list:
            raise InvalidUsage (404, message=f"Subnet '{subnet_id}' not found")
        subnet = self.subnet_list [subnet_id]
        return jsonify ({'subnet': subnet}), 200

    async def delete_subnet (self, subnet_id):
        logger.info (f"DHCPConf.delete_subnet ({subnet_id})")
        self.check_subnet_reference (subnet_id)
        del self.subnet_list [subnet_id]
        del self.device_lists [subnet_id]
        await self.update_conf ()
        return '', 204

    #
    # Device Operations
    #
    def check_device_reference (self, subnet_id, device_id):
        subnet_devices = self.device_lists [subnet_id]
        if device_id not in subnet_devices:
            raise InvalidUsage (404, message=f"Device '{device_id}' doesn't exist in subnet '{subnet_id}'")

    def check_device_unique (self, device_id, subnet_id):
        device_list = self.device_lists [subnet_id]
        if device_id in device_list:
            raise InvalidUsage (409, message=f"Supplied device '{device_id}' already exists for "
                                             f"subnet '{subnet_id}'");

    def check_device_for_subnet (self, device, subnet):
        ipv4_net_params = subnet ['ipv4Network']
        netaddr = ipv4_net_params ['network']
        netmask = ipv4_net_params ['mask']
        devaddr = device ['networkAddress']['ipv4']
        try:
            subnet_network = IPv4Network (netaddr + "/" + netmask, strict=True)
            host_network = IPv4Network (devaddr + "/255.255.255.255")
            if not subnet_network.overlaps (host_network):
                raise InvalidUsage (400, message=f"Device '{device ['deviceId']}' address {devaddr} "
                                                 f"isn't compatible with subnet '{subnet ['subnetId']}' "
                                                 f"({subnet_network})")
        except (AddressValueError, NetmaskValueError) as ve:
            raise InvalidUsage (400, message=f"Error validating address {devaddr} for subnet "
                                             f"'{subnet ['subnetId']}' ({subnet_network}): {ve}")

    def check_devices_for_subnet (self, subnet, device_list):
        for device_id, device in device_list.items ():
            self.check_device_for_subnet (device, subnet)

    def check_device_mac_unique (self, device_to_check, excluded_subnet_id=None, excluded_device_id=None):
        addr_field_to_check = device_to_check ['macAddress']['eui48']
        addr_to_check = EUI (addr_field_to_check)
        for subnet_id, device_list in self.device_lists.items ():
            for device_id, device in device_list.items ():
                if (excluded_subnet_id == subnet_id) and (excluded_device_id == device_id):
                    continue
                dev_addr_field = device ['macAddress']['eui48']
                dev_addr = EUI (dev_addr_field)
                if (dev_addr == addr_to_check):
                    raise InvalidUsage (400, message=f"MAC address of device "
                                                     f"'{device_to_check ['deviceId']}' is not unique "
                                                     f"(MAC address {addr_to_check} found in subnet "
                                                     f"'{addr_to_check}' device '{device_id}')")

    def check_device_ip_unique (self, device_to_check, subnet_id, excluded_device_id=None):
        addr_field_to_check = device_to_check ['networkAddress']['ipv4']
        deviceid_to_check = device_to_check ['deviceId']
        addr_to_check = IPv4Address (addr_field_to_check)
        device_list = self.device_lists [subnet_id]
        for device_id, device in device_list.items ():
            if (excluded_device_id == device_id):
                continue
            dev_addr_field = device ['networkAddress']['ipv4']
            dev_addr = IPv4Address (dev_addr_field)
            if (dev_addr == addr_to_check):
                raise InvalidUsage (400, message=f"IP address of device '{deviceid_to_check}' "
                                                 f"is not unique (IP address {addr_to_check} found "
                                                 f"in device '{device_id}')")

    async def get_subnetid_deviceid_for_mac (self, mac_address):
        addr_to_check = EUI (mac_address)
        for subnet_id, device_list in self.device_lists.items ():
            for device_id, device in device_list.items ():
                dev_addr_field = device ['macAddress']['eui48']
                dev_addr = EUI (dev_addr_field)
                if (dev_addr == addr_to_check):
                    return {'subnetId': subnet_id, 'deviceId': device_id}
        return None

    async def dump_mock_lists (self):
        logger.info ("mock_subnets:")
        logger.info (json.dumps (self.subnet_list, indent=4))
        logger.info ("device_lists:")
        logger.info (json.dumps (self.device_lists, indent=4))

    async def get_all_devices (self, subnet_id):
        logger.info (f"DHCPConf.get_all_devices ({subnet_id})")
        self.check_subnet_reference (subnet_id)
        return jsonify ({'devices': list (self.device_lists [subnet_id].values ())}), 200

    async def delete_all_devices (self, subnet_id):
        logger.info (f"DHCPConf.delete_all_devices ({subnet_id})")
        self.check_subnet_reference (subnet_id)
        self.device_lists [subnet_id].clear ()
        await self.update_conf ()
        return '', 204

    async def create_device (self, device, subnet_id):
        logger.info (f"DHCPConf.create_device ({device}, {subnet_id})")
        self.check_subnet_reference (subnet_id)
        device_list = self.device_lists [subnet_id]
        device_id = device ['deviceId'].lower ()
        subnet = self.subnet_list [subnet_id]
        self.check_device_unique (device_id, subnet_id)
        self.check_device_for_subnet (device, subnet)
        self.check_device_mac_unique (device)
        self.check_device_ip_unique (device, subnet_id)
        device_list [device_id] = device
        await self.update_conf ()
        return jsonify ({'device': device}), 201

    async def create_devices (self, devices, subnet_id):
        logger.info (f"DHCPConf.create_devices ({devices}, {subnet_id})")
        self.check_subnet_reference (subnet_id)
        subnet = self.subnet_list [subnet_id]
        # Check that all the supplied deviceIds are unique before incorporating them
        for device in devices:
            device_id = device ['deviceId'].lower ()
            self.check_device_unique (device_id, subnet_id)
            self.check_device_for_subnet (device, subnet)
            self.check_device_mac_unique (device)
            self.check_device_ip_unique (device, subnet_id)

        device_list = self.device_lists [subnet_id]
        for device in devices:
            device_id = device ['deviceId'].lower ()
            device_list [device_id] = device
        await self.update_conf ()
        return jsonify ({'devices': devices}), 201

    async def update_device (self, device_update, subnet_id, device_id):
        logger.info (f"DHCPConf.update_device ({device_update}, {subnet_id}, {device_id})")
        self.check_subnet_reference (subnet_id)
        self.check_device_reference (subnet_id, device_id)
        device_list = self.device_lists [subnet_id]
        target_device = device_list [device_id]
        if 'deviceId' in device_update:
            device_update_id = device_update ['deviceId'].lower ()
            if device_update_id != device_id:
                raise InvalidUsage (409, message=f"Update can only update device '{device_id}' "
                                                 f"('{device_update_id}' provided)")
        updated_device = copy.deepcopy (target_device)
        update_deep (updated_device, device_update)

        self.check_device_for_subnet (updated_device, self.subnet_list [subnet_id])
        self.check_device_mac_unique (updated_device, excluded_subnet_id = subnet_id, 
                                                      excluded_device_id = device_id)
        self.check_device_ip_unique (updated_device, subnet_id, excluded_device_id = device_id)

        device_list [device_id] = updated_device
        await self.update_conf ()
        return jsonify ({'device': updated_device}), 200

    async def get_device (self, subnet_id, device_id):
        logger.info (f"DHCPConf.get_device ({subnet_id}, {device_id})")
        logger.info (json.dumps (self.device_lists, indent=4))
        self.check_subnet_reference (subnet_id)
        self.check_device_reference (subnet_id, device_id)
        return jsonify ({'device': self.device_lists [subnet_id] [device_id]}), 200

    async def delete_device (self, subnet_id, device_id):
        logger.info (f"DHCPConf.delete_device ({subnet_id}, {device_id})")
        self.check_subnet_reference (subnet_id)
        self.check_device_reference (subnet_id, device_id)
        del self.device_lists [subnet_id] [device_id]
        await self.update_conf ()
        return '', 204

    async def process_dhcp_lease_event (self, dhcp_lease_event):
        logger.info (f"DHCPConf.process_lease_event ({dhcp_lease_event})")

        event_fields = dhcp_lease_event ['leaseChangeEvent']
        action = event_fields ['action']

        if not self.ws_connector.is_ready ():
            ws_uri = self.ws_connector.get_connect_uri ()
            logger.info (f"DHCPConf.process_dhcp_lease_event: Cannot send {action} event - the websocket to {ws_uri} is not connected/ready")
            return f"The websocket connection to {ws_uri} is not connected/ready", 500

        mac_addr = event_fields ['macAddress']['eui48']
        net_addr = event_fields ['networkAddress']['ipv4']
        ids = await self.get_subnetid_deviceid_for_mac (mac_addr)
        if (not ids):
            logger.info (f"DHCPConf.process_lease_event: ERROR: Could not find device/subnet for mac {mac_addr}")
            raise InvalidUsage (404, message=f"No device found with mac address {mac_addr}")
        logger.info (f"DHCPConf.process_lease_event: found {ids} for mac {mac_addr}")
        lease_change_event = { f"{action}Event": {
                                 'subnetId': ids['subnetId'],
                                 'deviceId': ids['deviceId'],
                                 'macAddress': {"eui48": mac_addr},
                                 'networkAddress': {"ipv4": net_addr} }
                             }
        logger.info (f"DHCPConf.process_dhcp_lease_event: Sending: {action}")
        logger.info (json.dumps (lease_change_event, indent=4))
        await self.ws_connector.send_event_message ("DHCP", action, lease_change_event)
        return '', 200
