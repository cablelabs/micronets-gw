import collections
import re
from copy import deepcopy
from ipaddress import IPv4Network, AddressValueError, NetmaskValueError

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
        return rv