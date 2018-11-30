import collections
import re
import asyncio
import socket
from copy import deepcopy
from ipaddress import IPv4Address, IPv4Network, AddressValueError, NetmaskValueError

ip_addr_pattern = '(?:\\d{1,3}\\.){3}\\d{1,3}'

mac_addr_pattern = '(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'

blank_line_re = re.compile ('^\s*$', re.ASCII)

comment_line_re = re.compile ('^\s*\#.*$', re.ASCII)

def check_json_field (json_obj, field, field_type, required):
    '''Thrown an Exception of json_obj doesn't contain field and/or it isn't of type field_type'''
    if field not in json_obj:
        if required:
            raise Exception (f"message doesn't contain a '{field}' field")
        else:
            return None
    field_val = json_obj [field]
    if not isinstance (field_val, field_type):
        raise Exception (f"Field type for '{field}' field is not a {field_type}")
    return field_val

def update_deep (d, u):
    for k, v in u.items ():
        if isinstance (v, collections.Mapping):
            d [k] = update_deep (d.get (k, {}), v)
        else:
            d [k] = v
    return d

def merge_deep (dict1, dict2):
    ''' Return a new dictionary by merging two dictionaries recursively. '''
    result = deepcopy (dict1)
    for key, value in dict2.items ():
        if isinstance (value, collections.Mapping):
            result [key] = merge (result.get (key, {}), value)
        else:
            result [key] = deepcopy (dict2 [key])
    return result

def find_subnet_id_for_host (subnets, host_ip_address):
    host_network = IPv4Network (host_ip_address + "/255.255.255.255")
    for subnet_id, subnet in subnets.items ():
        ipv4_net_params = subnet ['ipv4Network']
        netaddr = ipv4_net_params ['network']
        netmask = ipv4_net_params ['mask']
        subnet_network = IPv4Network (netaddr + "/" + netmask, strict=True)
        if subnet_network.overlaps (host_network):
            return subnet_id
    return None

class InvalidUsage (Exception):
    def __init__ (self, status_code, message, payload=None):
        Exception.__init__ (self)
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict (self):
        rv = dict (self.payload or ())
        rv ['message'] = self.message
        rv ['status_code'] = self.status_code
        return rv

async def unroll_host_list (host_list):
    unrolled_host_list = []
    for hostspec in host_list:
        addrs_for_spec = await get_addrs_for_hostspec (hostspec)
        unrolled_host_list += addrs_for_spec
    return unrolled_host_list

async def get_ipv4_addrs_for_hostspec (hostspec):
    if not hostspec:
        return []
    try:
        net = IPv4Network (hostspec)
        if net:
            return [str(net)]
    except Exception as ex:
        pass
    # Assume it's a hostname
    addrs = await asyncio.get_event_loop().getaddrinfo (hostspec, None, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
    address_list = []
    for addr in addrs:
        address_list.append (addr[5][0])
    return address_list

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

def check_ipv4_address_field (json_obj, ip_addr_field, required):
    ip_address = check_field (json_obj, ip_addr_field, str, required)
    if not ip_address and not required:
        return
    ipv4_address_error = get_ipv4_address_error (ip_address)
    if (ipv4_address_error):
        raise InvalidUsage (400, message=f"Supplied IP address value '{ip_address}' for '{ip_addr_field}'"
                                         f" field in '{json_obj}' is not valid: {ipv4_address_error}")
    return ip_address

