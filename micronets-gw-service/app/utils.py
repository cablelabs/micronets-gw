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

mac_addr_re = re.compile('^(' + mac_addr_pattern + ')$')

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
            result [key] = merge_deep (result.get (key, {}), value)
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

portspec_pattern = "(?:(?P<port>[0-9]+)(?:/(?P<protocol>tcp|udp))?)"
# e.g. 22/tcp, 1000, 1200/udp, /tcp

portspec_re = re.compile ("^" + portspec_pattern + "$")

portlistspec_re = re.compile ("^(?:" + portspec_pattern + ")+$")

async def get_ipv4_hostports_for_hostportspec (hostandportspec):
    if not hostandportspec:
        return []
    hostandport = hostandportspec.split(':')
    if len(hostandport) >= 6:
        mac_addr = hostandportspec[0:17]
        portspec = hostandportspec[18:]
        if not mac_addr_re.match(mac_addr):
            raise Exception(f"Mac address specification '{mac_addr}' in host specification '{hostandportspec}' is invalid")
        hostandport_list = []
        if portspec:
            portspec_list = portspec.split(',')
            for portspec in portspec_list:
                hostandport_list.append(mac_addr + ":" + portspec)
        else:
            hostandport_list.append(mac_addr)
    else:
        hostspec = hostandport[0]
        if len(hostandport) == 2:
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
# e.g. 1.2.3.4, 1.2.3.4:22/tcp, 1.2.3.0/24:/tcp, 1.2.0.0/16:25,465,587,2525

hostportspec_re = re.compile ("^" + hostportspec_pattern + "$")

def parse_portspec (portspec):
    m = portspec_re.match(portspec)
    if not m:
        raise Exception(f"Port specification '{portspec}' is invalid")
    portspec_elems = m.groupdict() # Will return {'port': x, 'protocol': tcp/udp}
    if 'port' not in portspec_elems:
        raise Exception(f"Port specification '{portspec}' does not have a port/start port number")
    return m.groupdict()

def parse_hostportspec (hostportspec):
    m = hostportspec_re.match(hostportspec)
    if not m:
        raise Exception(f"Port specification '{hostportspec}' is invalid")
    hostportspec_elems = m.groupdict() # Will return {'port': x, 'protocol': tcp/udp}
    if 'port' not in hostportspec_elems:
        raise Exception(f"host-port specification '{hostportspec}' does not have a port number")
    return hostportspec_elems

macportspec_pattern = "(?P<mac_addr>" + mac_addr_pattern + ")(?::" + portspec_pattern + ")?"
# e.g. b8:27:eb:75:a4:8b, b8:27:eb:75:a4:8b:22/tcp, b8:27:eb:75:a4:8b:/tcp, b8:27:eb:75:a4:8b:25,465,587,2525

macportspec_re = re.compile ("^" + macportspec_pattern + "$")

def parse_macportspec (macportspec):
    m = macportspec_re.match(macportspec)
    if not m:
        raise Exception(f"MAC/Port specification '{macportspec}' is invalid")
    macportspec_elems = m.groupdict() # Will return {'mac_addr': mac, 'port': x, 'protocol': tcp/udp}
    if 'port' not in macportspec_elems:
        raise Exception(f"host-port specification '{macportspec}' does not have a port number")
    return macportspec_elems


def parse_portlistspec (portlistspec):
    portspecs = portlistspec.split(",")
    portelem_list = []
    for portspec in portspecs:
        portspec_elems = parse_portspec(portspec)
        if 'port' not in portspec_elems:
            raise Exception(f"host-port specification '{portspec}' does not have a port number")
        portelem_list.append(portspec_elems)
    return portelem_list

async def main():
    print("Running utils tests...")
    hpsl = ["1.2.3.4", "5.6.7.8:99", "example.com", "bogus.org:80", "www.yahoo.com:443,80/tcp,8080", "www.example.com:443/tcp,80/tcp,7/udp", \
            "b8:27:eb:75:a4:8b", "b8:27:eb:75:a4:8b:80", "b8:27:eb:75:a4:8b:443,80/tcp,8080"]
    for hostportspec in hpsl:
        hostports = await get_ipv4_hostports_for_hostportspec(hostportspec)
        print (f"hostportspecs for {hostportspec}: {hostports}")
    print (f"unrolled hosts for hostportspeclist {hpsl}:")
    hostports = await unroll_hostportspec_list(hpsl)
    print (hostports)
    print (f"Fields from parse_macportspec('b8:27:eb:75:a4:8b'): {parse_macportspec('b8:27:eb:75:a4:8b')}")
    print (f"Fields from parse_macportspec('b8:27:eb:75:a4:8b:80/tcp'): {parse_macportspec('b8:27:eb:75:a4:8b:80/tcp')}")
    print ("Done.")

if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
