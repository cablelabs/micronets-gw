from quart import request, jsonify
from ipaddress import IPv4Address, IPv4Network
from app import app, get_conf_model, get_dpp_handler
from .utils import InvalidUsage, get_ipv4_hostports_for_hostportspec, parse_portlistspec

import re
import netaddr
import logging

logger = logging.getLogger ('micronets-gw-service')

api_prefix = '/micronets/v1/gateway'

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

micronet_id_re = re.compile ('^\w+[-.\w]*$', re.ASCII)

def check_micronet_id (micronet_id, location):
    if not micronet_id_re.match (micronet_id):
        raise InvalidUsage (400, message="Supplied micronet ID '{}' in '{}' is not alpha-numeric"
                                         .format (micronet_id, location))

ip_re = re.compile ('^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', re.ASCII)

def check_ipv4_network (container, micronet_id, required):
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
                                                 f"{net_mask}' in micronet '{micronet_id}' is not valid: {ex}")
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
    nameservers = check_field (container, field_name, (list), required)
    if nameservers:
        for ip_address in nameservers:
            ipv4_address_error = get_ipv4_address_error (ip_address)
            if (ipv4_address_error):
                raise InvalidUsage (400, message=f"Supplied IP address value '{ip_address}' in "
                                                 f"'{container}' field '{field_name}' is not valid: "
                                                 f"{ipv4_address_error}")
    return nameservers

def check_vlan (container, field_name, required):
    vlan = check_field (container, field_name, int, required)
    if vlan is not None:
        if vlan < 1 or vlan > 4094:
            raise InvalidUsage(400, message=f"Supplied vlan ID '{vlan}' in '{container}' field"
                                    f"'{field_name}' is not valid: vlans must be between 1 and 4094")

@app.route (api_prefix + '/interfaces', methods=['GET'])
async def get_interfaces ():
    medium_param = request.args.get("medium")
    return await get_conf_model().get_interfaces(medium=medium_param)

def check_micronet (micronet, micronet_id=None, required=True):
    check_for_unrecognized_entries (micronet, ['micronetId','ipv4Network','nameservers','interface','vlan'])
    body_micronet_id = check_field (micronet, 'micronetId', str, required)
    if micronet_id and body_micronet_id:
        if micronet_id != body_micronet_id:
            raise InvalidUsage (400, message=f"The micronet ID in the path ('{micronet_id}') must match the one "
                                             f"in the body ('{body_micronet_id}')")
    if body_micronet_id:
        micronet_id = body_micronet_id
    micronet_id = micronet_id.lower ()
    check_micronet_id (micronet_id, micronet)
    check_ipv4_network (micronet, micronet_id, required)
    check_nameservers (micronet, 'nameservers', False)
    check_field (micronet, 'interface', str, required)
    check_vlan (micronet, 'vlan', False) # Optional

def check_micronets (micronets, required):
    for micronet in micronets:
        check_micronet (micronet, required=required)

@app.route (api_prefix + '/micronets', methods=['POST'])
async def create_micronets ():
    check_for_json_payload (request)
    top_level = await request.get_json ()
    check_for_unrecognized_entries (top_level, ['micronet', 'micronets'])
    if 'micronets' in top_level:
        micronets = top_level ['micronets']
        check_micronets (micronets, required=True)
        return await get_conf_model ().create_micronets (micronets)
    elif 'micronet' in top_level:
        micronet = top_level ['micronet']
        check_micronet (micronet, required=True)
        return await get_conf_model ().create_micronet (micronet)

@app.route (api_prefix + '/micronets', methods=['GET'])
async def get_all_micronets ():
    return await get_conf_model ().get_all_micronets ()

@app.route (api_prefix + '/micronets', methods=['DELETE'])
async def delete_all_micronets ():
    return await get_conf_model ().delete_all_micronets ()

@app.route (api_prefix + '/micronets/<micronet_id>', methods=['PUT'])
async def update_micronet (micronet_id):
    micronet_id = micronet_id.lower ()
    check_for_json_payload (request)
    check_micronet_id (micronet_id, request.path)

    top_level = await request.get_json ()
    check_for_unrecognized_entries (top_level, ['micronet'])
    micronet = top_level ['micronet']
    check_micronet (micronet, micronet_id=micronet_id, required=False)
    updated_micronet = await get_conf_model ().update_micronet (micronet, micronet_id)
    return updated_micronet

@app.route (api_prefix + '/micronets/<micronet_id>', methods=['GET'])
async def get_micronet (micronet_id):
    micronet_id = micronet_id.lower ()
    check_micronet_id (micronet_id, request.path)
    return await get_conf_model ().get_micronet (micronet_id)

@app.route (api_prefix + '/micronets/<micronet_id>', methods=['DELETE'])
async def delete_micronet (micronet_id):
    micronet_id = micronet_id.lower()
    check_micronet_id (micronet_id, request.path)
    return await get_conf_model ().delete_micronet (micronet_id)

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

device_wpa_psk_re = re.compile('^[0-9a-fA-F]{64}$', re.ASCII)
device_wpa_passphrase_re = re.compile('^[ -~]{8,63}$')

def check_wpa_psk(container, field_name, required):
    psk = check_field(container, field_name, str, required)
    if psk:
        if len(psk) == 64:
            if not device_wpa_psk_re.match(psk):
                raise InvalidUsage(400, message=f"Supplied WPA PSK '{psk}' is invalid (must be 64 hex digits)")
        else:
            if not device_wpa_passphrase_re.match(psk):
                raise InvalidUsage(400, message=f"Supplied WPA passphrase '{psk}' is invalid (must be 8-63 ASCII characters)")
    return psk

async def check_rules (container, field_name, required):
    rules = check_field (container, field_name, (list), required)
    if rules:
        for rule in rules:
            await check_rule (rule)
    return rules

async def check_rule (rule):
    check_for_unrecognized_entries (rule, ['action', 'sourceIp', 'sourcePort', 'destIp', 'destMac', 'destPort'])
    action = check_field (rule, 'action', str, True)
    if not (action == "allow" or action == "deny"):
        raise InvalidUsage(400, message=f"Supplied action '{action}' in rule '{rule}' is not valid "
                                        "(allowed actions are 'allow" and 'deny')

    await check_hostspec (rule, 'sourceIp', False)
    check_portspec (rule, 'sourcePort', False)

    await check_hostspec (rule, 'destIp', False)
    await check_hostspec (rule, 'destMac', False)
    check_portspec (rule, 'destPort', False)

    return rule

async def check_hostspecs (container, field_name, required):
    hosts = check_field (container, field_name, (list), required)
    if hosts:
        for host in hosts:
            try:
                hosts = await get_ipv4_hostports_for_hostportspec (host)
            except Exception as ex:
                raise InvalidUsage (400, message=f"Supplied hostname '{host}' in field '{field_name}' "
                                    f"of '{container}' is not valid: {ex}")
    return hosts

async def check_hostspec (container, field_name, required):
    hostspec = check_field (container, field_name, (str), required)
    if not hostspec:
        return None
    try:
        hosts = await get_ipv4_hostports_for_hostportspec (hostspec)
    except Exception as ex:
        raise InvalidUsage (400, message=f"Supplied hostname '{hostspec}' in field '{field_name}' "
                            f"of '{container}' is not valid: {ex}")
    return hostspec

def check_portspec (container, field_name, required):
    portspec = check_field (container, field_name, (str), required)
    if not portspec:
        return None
    try:
        portspecelem_list = parse_portlistspec (portspec)
    except Exception as ex:
        raise InvalidUsage (400, message=f"Supplied port specification '{portspec}' in field '{field_name}' "
                            f"of '{container}' is not valid: {ex}")
    return portspec

async def check_device (device, required):
    check_for_unrecognized_entries (device, ['deviceId', 'macAddress', 'networkAddress', 'psk', 'outRules', 'inRules',
                                             'allowHosts','denyHosts'])
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

    check_wpa_psk (device, 'psk', False)

    await check_rules (device, 'outRules', False)
    await check_rules (device, 'inRules', False)
    await check_hostspecs (device, 'allowHosts', False)
    await check_hostspecs (device, 'denyHosts', False)

async def check_devices (devices, required):
    for device in devices:
        await check_device (device, required)

@app.route (api_prefix + '/micronets/<micronet_id>/devices', methods=['POST'])
async def create_devices (micronet_id):
    micronet_id = micronet_id.lower ()
    check_for_json_payload (request)
    top_level = await request.get_json ()
    check_for_unrecognized_entries (top_level, ['device', 'devices'])
    if 'devices' in top_level:
        devices = top_level ['devices']
        await check_devices (devices, required=True)
        return await get_conf_model ().create_devices (devices, micronet_id)
    elif 'device' in top_level:
        device = top_level ['device']
        await check_device (device, required=True)
        return await get_conf_model ().create_device (device, micronet_id)

@app.route (api_prefix + '/micronets/<micronet_id>/devices', methods=['GET'])
async def get_devices (micronet_id):
    micronet_id = micronet_id.lower ()
    check_micronet_id (micronet_id, request.path)
    return await get_conf_model ().get_all_devices (micronet_id)

@app.route (api_prefix + '/micronets/<micronet_id>/devices', methods=['DELETE'])
async def delete_devices (micronet_id):
    micronet_id = micronet_id.lower()
    check_micronet_id (micronet_id, request.path)
    return await get_conf_model ().delete_all_devices (micronet_id)

@app.route (api_prefix + '/micronets/<micronet_id>/devices/<device_id>', methods=['PUT'])
async def update_device (micronet_id, device_id):
    micronet_id = micronet_id.lower ()
    device_id = device_id.lower ()
    check_for_json_payload (request)
    check_micronet_id (micronet_id, request.path)
    check_device_id (device_id, request.path)
    top_level = await request.get_json ()
    check_for_unrecognized_entries (top_level, ['device'])
    device_update = top_level ['device']
    await check_device (device_update, required=False)
    return await get_conf_model ().update_device (device_update, micronet_id, device_id)

@app.route (api_prefix + '/micronets/<micronet_id>/devices/<device_id>', methods=['GET'])
async def get_device (micronet_id, device_id):
    micronet_id = micronet_id.lower ()
    device_id = device_id.lower ()
    check_micronet_id (micronet_id, request.path)
    check_device_id (device_id, request.path)
    return await get_conf_model ().get_device (micronet_id, device_id)

@app.route (api_prefix + '/micronets/<micronet_id>/devices/<device_id>', methods=['DELETE'])
async def delete_device (micronet_id, device_id):
    micronet_id = micronet_id.lower ()
    device_id = device_id.lower ()
    check_micronet_id (micronet_id, request.path)
    check_device_id (device_id, request.path)
    return await get_conf_model ().delete_device (micronet_id, device_id)

@app.route (api_prefix + '/micronets/<micronet_id>/devices/<device_id>/onboard', methods=['PUT'])
async def onboard_device (micronet_id, device_id):
    micronet_id = micronet_id.lower ()
    device_id = device_id.lower ()
    check_micronet_id (micronet_id, request.path)
    check_device_id (device_id, request.path)
    top_level = await request.get_json ()
    logger.info(f"onboad_device: top_level: {top_level}")
    check_for_unrecognized_entries (top_level, ['dpp'])
    dpp_obj = top_level['dpp']
    logger.info(f"onboad_device: dpp_obj: {dpp_obj}")
    check_for_unrecognized_entries(dpp_obj, ['uri','akms'])
    uri = check_field (dpp_obj, 'uri', str, True)
    akms = check_akms (dpp_obj, 'akms', True)
    return await get_dpp_handler().onboard_device (micronet_id, device_id, top_level)

valid_akms = ("psk", "dpp", "sae")

def check_akms (container, field_name, required):
    akms = check_field (container, field_name, (list), required)
    if akms:
        for akm in akms:
            if akm not in valid_akms:
                raise InvalidUsage (400, message=f"akms entry '{akm}' is invalid (must be one of: {valid_akms})")
    return akms

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

@app.route (api_prefix + '/leases', methods=['PUT'])
async def process_lease ():
    check_for_json_payload (request)
    lease_event = await request.get_json ()
    await check_lease_event (lease_event)
    return await get_conf_model ().process_dhcp_lease_event (lease_event)
