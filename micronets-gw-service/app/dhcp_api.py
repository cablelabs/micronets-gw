from quart import request, jsonify
from ipaddress import IPv4Address, IPv4Network
from app import app, get_dhcp_conf_model
from .utils import InvalidUsage

import re
import netaddr
import logging

logger = logging.getLogger ('micronets-gw-service')

dhcp_api_prefix = '/micronets/v1/dhcp'

# This installs the handler to turn the InvalidUsage exception into a response
# See: http://flask.pocoo.org/docs/1.0/patterns/apierrors/
@app.errorhandler (InvalidUsage)
def handle_invalid_usage (error):
    response = jsonify (error.to_dict())
    response.status_code = error.status_code
    logger.info (f"Returning status {response.status_code} for {request.method} request for {request.path}: {error.message}")
    return response

@app.errorhandler (500)
def error_handler_500 (exception):
    return jsonify ({"error": str (exception)}), 500, {'Content-Type': 'application/json'}

@app.errorhandler (400)
def error_handler_400 (exception):
    logger.info (f"Caught 400 error handing request: {exception}")
    return jsonify (exception.to_dict ()), 400, {'Content-Type': 'application/json'}

@app.errorhandler (404)
def error_handler_404 (exception):
    return jsonify ({"error": str (exception)}), 404, {'Content-Type': 'application/json'}

def check_for_json_payload (request):
    if not request.is_json:
        raise InvalidUsage (400, message="supplied data is not a valid json object")

def abort_if_field_missing (json_obj, field):
    if field not in json_obj:
        raise InvalidUsage (400, message=f"Required field '{field}' missing from {json_obj}")

def check_field (json_obj, field, field_type, required):
    if field not in json_obj:
        if required:
            raise InvalidUsage (400, message=f"Required field '{field}' missing from {json_obj}")
        else:
            return
    field_val = json_obj [field]
    if not isinstance (field_val, field_type):
        raise InvalidUsage (400, message=f"Supplied field value '{field_val}' for '{field}' field"
                                         f" in '{json_obj}' is not a {field_type}")
    return field_val

def check_for_unrecognized_entries (container, allowed_field_names):
    keys = container.keys ()
    unrecognized_keys = keys - allowed_field_names  # This is set subtraction
    if ((len (unrecognized_keys)) > 0):
        raise InvalidUsage (400, message=f"Illegal field(s) {unrecognized_keys} in '{container}'")
    return True

subnet_id_re = re.compile ('^\w+[-.\w]*$', re.ASCII)

def check_subnet_id (subnet_id, location):
    if not subnet_id_re.match (subnet_id):
        raise InvalidUsage (400, message="Supplied subnet ID '{}' in '{}' is not alpha-numeric"
                                         .format (subnet_id, location))

ip_re = re.compile ('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', re.ASCII)

def check_ipv4_network (container, subnet_id, required):
    ipv4_network = check_field (container, 'ipv4Network', (dict, list), required)
    if ipv4_network:
        check_for_unrecognized_entries (ipv4_network, ['network','mask','gateway'])
        check_ipv4_address_field (ipv4_network, 'gateway', False)
        net_address = check_ipv4_address_field (ipv4_network, 'network', required)
        net_mask = check_ipv4_address_field (ipv4_network, 'mask', required)
        if (required or (net_address and net_mask)):
            try:
                IPv4Network (net_address + "/" + net_mask, strict=True)
            except Exception as ex:
                raise InvalidUsage (400, message=f"Supplied IP network/mask value '{net_address}/"
                                                 f"{net_mask}' in subnet '{subnet_id}' is not valid: {ex}")
    return ipv4_network

def get_ipv4_address_error (ip_address):
    if not ip_address:
        return "Address is empty"
    try:
        addr = IPv4Address (ip_address)
        if not addr:
            return "Invalid address"
        if addr.is_loopback or addr.is_multicast:
            return "Address is a loopback or broadcast address"
        return None;
    except Exception as ex:
        return str (ex)

def check_ipv4_address_field (json_obj, ip_addr_field, required):
    ip_address = check_field (json_obj, ip_addr_field, str, required)
    if not ip_address and not required:
        return
    ipv4_address_error = get_ipv4_address_error (ip_address)
    if (ipv4_address_error):
        raise InvalidUsage (400, message=f"Supplied IP address value '{ip_address}' for '{ip_addr_field}'"
                                         f" field in '{json_obj}' is not valid: {ipv4_address_error}")
    return ip_address

def check_nameservers (container, field_name, required):
    nameservers = check_field (container, 'nameservers', (list), False)
    if nameservers:
        for ip_address in nameservers:
            ipv4_address_error = get_ipv4_address_error (ip_address)
            if (ipv4_address_error):
                raise InvalidUsage (400, message=f"Supplied IP address value '{ip_address}' in "
                                                 f"'{container}' field '{field_name}' is not valid: "
                                                 f"{ipv4_address_error}")
    return nameservers

def check_subnet (subnet, subnet_id=None, required=True):
    check_for_unrecognized_entries (subnet, ['subnetId','ipv4Network','nameservers','ovsPort','interface'])
    body_subnet_id = check_field (subnet, 'subnetId', str, required)
    if subnet_id and body_subnet_id:
        if subnet_id != body_subnet_id:
            raise InvalidUsage (400, message=f"The subnet ID in the path ('{subnet_id}') must match the one "
                                             f"in the body ('{body_subnet_id}')")
    if body_subnet_id:
        subnet_id = body_subnet_id
    subnet_id = subnet_id.lower ()
    check_subnet_id (subnet_id, subnet)
    check_ipv4_network (subnet, subnet_id, required)
    check_nameservers (subnet, 'nameservers', required)
    check_field (subnet, 'ovsPort', int, required)
    check_field (subnet, 'interface', str, required)

def check_subnets (subnets, required):
    for subnet in subnets:
        check_subnet (subnet, required=required)

@app.route (dhcp_api_prefix + '/subnets', methods=['POST'])
async def create_subnets ():
    check_for_json_payload (request)
    top_level = await request.get_json ()
    check_for_unrecognized_entries (top_level, ['subnet', 'subnets'])
    if 'subnets' in top_level:
        subnets = top_level ['subnets']
        check_subnets (subnets, required=True)
        return get_dhcp_conf_model ().create_subnets (subnets)
    elif 'subnet' in top_level:
        subnet = top_level ['subnet']
        check_subnet (subnet, required=True)
        return get_dhcp_conf_model ().create_subnet (subnet)

@app.route (dhcp_api_prefix + '/subnets', methods=['GET'])
async def get_all_subnets ():
    return get_dhcp_conf_model ().get_all_subnets ()

@app.route (dhcp_api_prefix + '/subnets', methods=['DELETE'])
async def delete_all_subnets ():
    return get_dhcp_conf_model ().delete_all_subnets ()

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>', methods=['PUT'])
async def update_subnet (subnet_id):
    subnet_id = subnet_id.lower ()
    check_for_json_payload (request)
    check_subnet_id (subnet_id, request.path)

    top_level = await request.get_json ()
    check_for_unrecognized_entries (top_level, ['subnet'])
    subnet = top_level ['subnet']
    check_subnet (subnet, subnet_id=subnet_id, required=False)
    updated_subnet = get_dhcp_conf_model ().update_subnet (subnet, subnet_id)
    return updated_subnet

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>', methods=['GET'])
async def get_subnet (subnet_id):
    subnet_id = subnet_id.lower ()
    check_subnet_id (subnet_id, request.path)
    return get_dhcp_conf_model ().get_subnet (subnet_id)

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>', methods=['DELETE'])
async def delete_subnet (subnet_id):
    subnet_id = subnet_id.lower()
    check_subnet_id (subnet_id, request.path)
    return get_dhcp_conf_model ().delete_subnet (subnet_id)

device_id_re = re.compile ('^\w+[-.\w]*$', re.ASCII)

def check_device_id (device_id, location):
    if not device_id_re.match (device_id):
        raise InvalidUsage (400, message=f"Supplied device ID '{device_id}' in '{location}'"
                                         f" is not alpha-numeric")

def check_mac_address_field (json_obj, mac_addr_field, required):
    mac_field = check_field (json_obj, mac_addr_field, str, required)
    if not mac_field and not required:
        return
    if not netaddr.valid_mac (mac_field):
        raise InvalidUsage (400, message=f"Supplied MAC '{mac_field}' in '{mac_addr_field}' is not valid")
    return mac_field

def check_device (device, required):
    check_for_unrecognized_entries (device, ['deviceId','macAddress','networkAddress'])
    device_id = check_field (device, 'deviceId', str, required)
    if device_id:
        device_id = device_id.lower ()
        check_device_id (device_id, device)

    mac_address = check_field (device, 'macAddress', (dict, list), required)
    if not mac_address:
        if required:
            raise InvalidUsage (400, message=f"macAddress missing from device '{device_id}'")
    else:
        check_for_unrecognized_entries (mac_address, ['eui48'])
        check_mac_address_field (mac_address, 'eui48', required)

    network_address = check_field (device, 'networkAddress', (dict, list), required)
    if not network_address:
        if required:
            raise InvalidUsage (400, message=f"networkAddress missing from device '{device_id}'")
    else:
        check_for_unrecognized_entries (network_address, ['ipv4'])
        check_ipv4_address_field (network_address, 'ipv4', required)

def check_devices (devices, required):
    for device in devices:
        check_device (device, required)

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>/devices', methods=['POST'])
async def create_devices (subnet_id):
    subnet_id = subnet_id.lower ()
    check_for_json_payload (request)
    top_level = await request.get_json ()
    check_for_unrecognized_entries (top_level, ['device', 'devices'])
    if 'devices' in top_level:
        devices = top_level ['devices']
        check_devices (devices, required=True)
        return get_dhcp_conf_model ().create_devices (devices, subnet_id)
    elif 'device' in top_level:
        device = top_level ['device']
        check_device (device, required=True)
        return get_dhcp_conf_model ().create_device (device, subnet_id)

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>/devices', methods=['GET'])
async def get_devices (subnet_id):
    subnet_id = subnet_id.lower ()
    check_subnet_id (subnet_id, request.path)
    return get_dhcp_conf_model ().get_all_devices (subnet_id)

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>/devices', methods=['DELETE'])
async def delete_devices (subnet_id):
    subnet_id = subnet_id.lower()
    check_subnet_id (subnet_id, request.path)
    return get_dhcp_conf_model ().delete_all_devices (subnet_id)

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>/devices/<device_id>', methods=['PUT'])
async def update_device (subnet_id, device_id):
    subnet_id = subnet_id.lower ()
    device_id = device_id.lower ()
    check_for_json_payload (request)
    check_subnet_id (subnet_id, request.path)
    check_device_id (device_id, request.path)
    top_level = await request.get_json ()
    check_for_unrecognized_entries (top_level, ['device'])
    device_update = top_level ['device']
    check_device (device_update, required=False)
    return get_dhcp_conf_model ().update_device (device_update, subnet_id, device_id)

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>/devices/<device_id>', methods=['GET'])
async def get_device (subnet_id, device_id):
    subnet_id = subnet_id.lower ()
    device_id = device_id.lower ()
    check_subnet_id (subnet_id, request.path)
    check_device_id (device_id, request.path)
    return get_dhcp_conf_model ().get_device (subnet_id, device_id)

@app.route (dhcp_api_prefix + '/subnets/<subnet_id>/devices/<device_id>', methods=['DELETE'])
async def delete_device (subnet_id, device_id):
    subnet_id = subnet_id.lower ()
    device_id = device_id.lower ()
    check_subnet_id (subnet_id, request.path)
    check_device_id (device_id, request.path)
    return get_dhcp_conf_model ().delete_device (subnet_id, device_id)

async def check_lease_event (lease_event):
    event_fields = check_field (lease_event, 'leaseChangeEvent', dict, True)
    check_for_unrecognized_entries (event_fields, ['action','macAddress','networkAddress','hostname'])
    action = check_field (event_fields, 'action', str, True)
    if action != "leaseAcquired" and action != "leaseExpired":
        raise InvalidUsage (400, message=f"unrecognized lease action '{action}'"
                                         f" (must be 'leaseAcquired' or 'leaseExpired')")

    mac_address = check_field (event_fields, 'macAddress', dict, True)
    check_for_unrecognized_entries (mac_address, ['eui48'])
    check_mac_address_field (mac_address, 'eui48', True)

    network_address = check_field (event_fields, 'networkAddress', dict, True)
    check_for_unrecognized_entries (network_address, ['ipv4'])
    check_ipv4_address_field (network_address, 'ipv4', True)

    hostname = check_field (event_fields, 'hostname', str, True)

@app.route (dhcp_api_prefix + '/leases', methods=['PUT'])
async def process_lease ():
    check_for_json_payload (request)
    lease_event = await request.get_json ()
    await check_lease_event (lease_event)
    return await get_dhcp_conf_model ().process_dhcp_lease_event (lease_event)
