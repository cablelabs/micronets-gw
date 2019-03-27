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

def find_micronet_id_for_host (micronets, host_ip_address):
    host_network = IPv4Network (host_ip_address + "/255.255.255.255")
    for micronet_id, micronet in micronets.items ():
        ipv4_net_params = micronet ['ipv4Network']
        netaddr = ipv4_net_params ['network']
        netmask = ipv4_net_params ['mask']
        micronet_network = IPv4Network (netaddr + "/" + netmask, strict=True)
        if micronet_network.overlaps (host_network):
            return micronet_id
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

async def unroll_hostportspec_list (hostportspec_list):
    unrolled_host_list = []
    for hostportspec in hostportspec_list:
        addrs_for_spec = await get_ipv4_hostports_for_hostportspec (hostportspec)
        unrolled_host_list += addrs_for_spec
    return unrolled_host_list


portspec_pattern = "(?:(?P<startport>[0-9]+)(?:-(?P<endport>[0-9]+))?)?(?:/(?P<protocol>tcp|udp))?"
# e.g. 22/tcp, 1000-2000, 1200-1300/udp, /tcp

portspec_re = re.compile ("^" + portspec_pattern + "$")

async def get_ipv4_hostports_for_hostportspec (hostandportspec):
    if not hostandportspec:
        return []
    hostandport = hostandportspec.split(':')
    hostspec = hostandport[0]
    if len(hostandport) > 1:
        portspec_list = hostandport[1].split(',')
    else:
        portspec_list = None
    host_addrs = []
    try:
        net = IPv4Network (hostspec)
        if net:
            host_addrs = [str(net)]
    except Exception as ex:
        # If it doesn't work as an IP4 dotted host/network, assume it's a hostname
        addrs = await asyncio.get_event_loop().getaddrinfo (hostspec, None, family=socket.AF_INET,
                                                            proto=socket.IPPROTO_TCP)
        for addr in addrs:
            host_addrs.append (addr[4][0])  # This is just the IP address portion of what's returned
    hostandport_list = []
    for addr in host_addrs:
        if portspec_list:
            for portspec in portspec_list:
                if not portspec_re.match(portspec):
                    raise Exception(f"Port specification '{portspec}' in host specification '{hostandportspec}' is invalid")
                hostandport_list.append(addr+":"+portspec)
        else:
            hostandport_list.append(addr)
    return hostandport_list

hostportspec_pattern = "(?P<ip_addr>" + ip_addr_pattern + "(?:/\d{1,3})?)" + "(?::" + portspec_pattern + ")?"
# e.g. 1.2.3.4, 1.2.3.4:22/tcp, 1.2.3.0/24:1-1024, 1.2.0.0/16:1024-2000/udp

hostportspec_re = re.compile ("^" + hostportspec_pattern + "$")

def parse_portspec (portspec):
    m = portspec_re.match(portspec)
    if not m:
        raise Exception(f"Port specification '{portspec}' is invalid")
    portspec_elems = m.groupdict() # Will return {'startport': x, 'endport': y, 'protocol': tcp/udp}
    if 'startport' not in portspec_elems:
        raise Exception(f"Port specification '{portspec}' does not have a port/start port number")
    return

def parse_hostportspec (portspec):
    m = hostportspec_re.match(portspec)
    if not m:
        raise Exception(f"Port specification '{portspec}' is invalid")
    portspec_elems = m.groupdict() # Will return {'startport': x, 'endport': y, 'protocol': tcp/udp}
    if 'startport' not in portspec_elems:
        raise Exception(f"host-port specification '{portspec}' does not have a port/start port number")
    return portspec_elems


async def main():
    print("Running utils tests...")
    hpsl = ["1.2.3.4", "5.6.7.8:99", "example.com", "bogus.org:80", "www.yahoo.com:443,80,8080", "www.example.com:443/tcp,80/tcp,7/udp"]
    for hostportspec in hpsl:
        hostports = await get_ipv4_hostports_for_hostportspec(hostportspec)
        print (f"hostportspecs for {hostportspec}: {hostports}")
    print (f"unrolled hosts for hostportspeclist {hpsl}:")
    hostports = await unroll_hostportspec_list(hpsl)
    print (hostports)
    print ("Done.")

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
