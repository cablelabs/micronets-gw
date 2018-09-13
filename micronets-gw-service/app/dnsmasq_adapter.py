import os, sys
import re
import json
import netaddr
import logging

from pathlib import Path
from ipaddress import IPv4Network, IPv4Address
from netaddr import EUI
from subprocess import call
from .utils import ip_addr_pattern, mac_addr_pattern, blank_line_re, comment_line_re, find_subnet_id_for_host

logger = logging.getLogger ('micronets-dhcp-server')

class DnsMasqAdapter:
    lease_duration_re = 'infinite|[0-9]+[hm]?'

    # dhcp-range=set:testsubnet001,10.40.0.0,static,255.255.255.0,3m
    dhcp_range_re = re.compile ('^\s*dhcp-range\s*=\s*set:\s*(\w.[\w-]*),(' + ip_addr_pattern 
                                + '),\s*static,\s*(' + ip_addr_pattern
                                + '),\s*(' + lease_duration_re + ')\s*$', re.ASCII)

    dhcp_range_option_prefix = '^\s*dhcp-option\s*=\s*tag:\s*(\w.[\w-]*),\s*'

    # dhcp-option=tag:testsubnet001, option:router,10.40.0.1
    dhcp_range_router_re = re.compile (dhcp_range_option_prefix
                                       + 'option:\s*router\s*,(' + ip_addr_pattern + ')$', re.ASCII)

    # dhcp-option=tag:testsubnet001, option:dns-server,8.8.8.8,4.4.4.4
    dhcp_range_dns_server_re = re.compile (dhcp_range_option_prefix
                                           + 'option:\s*dns-server((?:\s*,\s*'
                                           + ip_addr_pattern + ')+)', re.ASCII)

    # dhcp-hostsfile=/home/micronut/projects/micronets/micronets-dhcp/dnsmasq-hosts
    dhcp_hostfile_re = re.compile ('dhcp-hostsfile\s*=\s*(.+)$')

    # 08:00:27:e5:77:c5,micronet-client-1,set:micronet-client-1,10.40.0.71,2m
    dhcp_host_re = re.compile ('^\s*dhcp-host\s*=\s*(' + mac_addr_pattern + ')\s*,\s*(\w.[\w-]*)\s*,'
                               + '\s*set:\s*(\w.[\w-]*)\s*,\s*('
                               + ip_addr_pattern + ')\s*(?:,\s*(' + lease_duration_re + '))?', re.ASCII)

    # dhcp-script=/home/micronut/projects/micronets/micronets-dhcp/app/dnsmasq_lease_notify.py
    dhcp_scriptfile_re = re.compile ('dhcp-script\s*=\s*(.+)$')

    def __init__ (self, config):
        self.conffile_path = Path (config ['DNSMASQ_CONF_FILE'])
        self.dnsmasq_restart_command = config ['DNSMASQ_RESTART_COMMAND']
        self.default_lease_period = config ['DEFAULT_LEASE_PERIOD']
        self.lease_script = config ['SERVER_BIN_DIR'] + "/dnsmasq_lease_notify.py"
        with self.conffile_path.open ('a'):
            pass
        logger.info  (f"Instantiated DnsMasq with conf file {self.conffile_path.absolute()}")

    def read_from_conf (self):
        with self.conffile_path.open ('r') as infile:
            try:
                infile.line_no = 0
                logger.info (f"IscDhcpdAdapter: Loading subnet data from {self.conffile_path.absolute ()}")
                read_conf = self.parse_conffile (infile)
                subnets = read_conf ['subnets']
                devices = read_conf ['devices']
                return {"subnets": subnets, "devices": devices}
            except Exception as e:
                raise Exception ("IscDhcpdAdapter: Error on line {} of {}: {}"
                                 .format (infile.line_no, self.conffile_path.absolute (), e))

    def parse_conffile (self, infile):
        subnets = {}
        devices_list = {}
        for line in infile:
            infile.line_no += 1
            if (blank_line_re.match (line)):
                continue
            if (comment_line_re.match (line)):
                continue
            dhcp_range_match_result = self.dhcp_range_re.match (line)
            if (dhcp_range_match_result):
                subnet_id = dhcp_range_match_result.group (1)
                subnet_network = dhcp_range_match_result.group (2)
                subnet_netmask = dhcp_range_match_result.group (3)
                subnet_lease_duration = dhcp_range_match_result.group (4)
                network = IPv4Network (subnet_network + "/" + subnet_netmask, strict=True)
                logger.debug ("DnsMasqAdapter.parse_conffile: Found subnet range: {} {} {} {}"
                              .format (subnet_id, subnet_network, subnet_netmask, subnet_lease_duration))

                if subnet_id in subnets:
                    raise Exception ("Duplicate subnet ID '{}'".format (subnet_id))
                if not network:
                    raise Exception ("Invalid subnet network/netmask '{}/{}'"
                                     .format (subnet_network, subnet_netmask))
                subnet = {}
                subnet ['subnetId'] = subnet_id
                subnet ['ipv4Network'] = {'network' : str (network.network_address), 'mask' : str (network.netmask)}
                subnets [subnet_id] = subnet
                devices_list [subnet_id] = {}
                continue
            dhcp_range_router_match = self.dhcp_range_router_re.match (line)
            if (dhcp_range_router_match):
                subnet_id = dhcp_range_router_match.group (1)
                router_address = dhcp_range_router_match.group (2)
                logger.debug (f"DnsMasqAdapter.parse_conffile: Found router address: "
                              f"{subnet_id} {router_address}")
                if not subnet_id in subnets:
                    raise Exception ("Could not find subnet ID '{}'".format (subnet_id))
                addr = IPv4Address (router_address)
                if not addr or addr.is_loopback or addr.is_multicast:
                    raise Exception ("Invalid router/gateway address '{}'".format (router_address))
                subnet = subnets [subnet_id]
                logger.debug (f"DnsMasqAdapter.parse_conffile: subnet {subnet_id}: {subnet}")
                logger.debug (f"DnsMasqAdapter.parse_conffile: subnet {subnet_id}"
                              f"ipv4Network: {subnet ['ipv4Network']}")
                subnet ['ipv4Network']['gateway'] = str (addr)
                continue
            dhcp_range_dns_server_match = self.dhcp_range_dns_server_re.match (line)
            if (dhcp_range_dns_server_match):
                subnet_id = dhcp_range_dns_server_match.group (1)
                dns_server_addresses = dhcp_range_dns_server_match.group (2)
                logger.debug (f"DnsMasqAdapter.parse_conffile: Found dns server addresses: "
                              f"{subnet_id} {dns_server_addresses}")
                if not subnet_id in subnets:
                    raise Exception ("Could not find subnet ID '{}'".format (subnet_id))
                nameservers = []
                for dns_server in dns_server_addresses.split (','):
                    if not dns_server:
                        continue
                    logger.info (f"DnsMasqAdapter.parse_conffile:  Found dns server address: {dns_server}")
                    addr = IPv4Address (dns_server)
                    if not addr or addr.is_loopback or addr.is_multicast:
                        raise Exception ("Invalid DNS server address '{}'".format (router_address))
                    nameservers.append (str (addr))
                logger.debug (f"DnsMasqAdapter.parse_conffile: DNS server list: {nameservers}")
                subnets [subnet_id]['nameservers'] = nameservers
                continue
            dhcp_host_match = self.dhcp_host_re.match (line)
            if (dhcp_host_match):
                dhcp_host_mac = dhcp_host_match.group (1)
                dhcp_host_id = dhcp_host_match.group (2)
                dhcp_host_tag = dhcp_host_match.group (3)
                dhcp_host_ip = dhcp_host_match.group (4)
                dhcp_host_lease_durection = dhcp_host_match.group (5)
                logger.debug ("DnsMasqAdapter.parse_conffile: Found dhcp host entry: {} {} {} {} {}"
                              .format (dhcp_host_mac, dhcp_host_id, dhcp_host_ip, dhcp_host_tag, 
                                       dhcp_host_lease_durection))
                if not netaddr.valid_mac (dhcp_host_mac):
                    raise Exception ("Invalid host MAC address '{}'".format (dhcp_host_mac))
                eui_mac_addr = EUI (dhcp_host_mac)
                eui_mac_addr.dialect = netaddr.mac_unix_expanded
                addr = IPv4Address (dhcp_host_ip)
                if not addr or addr.is_loopback or addr.is_multicast:
                    raise Exception ("Invalid host IP address '{}'".format (dhcp_host_ip))
                subnet_id = find_subnet_id_for_host (subnets, dhcp_host_ip)
                if not subnet_id:
                    raise Exception ("Could not find a subnet compatible with host '{}'".format (addr))
                device = {'deviceId': dhcp_host_id}
                device ['macAddress'] = {'eui48': str(eui_mac_addr)}
                device ['networkAddress'] = {'ipv4': str (addr)}
                device_list = devices_list [subnet_id]
                device_list [dhcp_host_id] = device
                continue
            dhcp_hostfile_match = self.dhcp_hostfile_re.match (line)
            if (dhcp_hostfile_match):
                hostfile = dhcp_hostfile_match.group (1)
                logger.debug (f"DnsMasqAdapter.parse_conffile: Found dhcp hostfile entry: {hostfile}")
                continue
            dhcp_scriptfile_match = self.dhcp_scriptfile_re.match (line)
            if (dhcp_scriptfile_match):
                scriptfile = dhcp_scriptfile_match.group (1)
                logger.debug (f"DnsMasqAdapter.parse_conffile: Found dhcp script file entry: {scriptfile}")
                continue
            # If none of the REs match, bail out
            raise Exception ("Unrecognized dnsmasq config entry: {}".format (line.rstrip ()))

        logger.info ("DnsMasqAdapter.parse_conffile: Done reading {}".format (infile))
        logger.info ("DnsMasqAdapter.parse_conffile: Subnets:")
        logger.info (json.dumps (subnets, indent=4))
        return {'subnets': subnets, 'devices': devices_list}

    def save_to_conf (self, subnets, devices):
        logger.debug ("DnsMasqAdapter.save_to_conf")
        with self.conffile_path.open ('w') as outfile:
            logger.info (f"DnsMasqAdapter: Saving subnet data to {self.conffile_path.absolute ()}")
            outfile.write ("# MODIFICATIONS TO THIS FILE WILL BE OVER-WRITTEN\n\n")
            outfile.write ("dhcp-script={}\n\n".format (self.lease_script))
            self.write_subnets (outfile, subnets)
            self.write_devices (outfile, devices)

        if self.dnsmasq_restart_command:
            logger.info (f"Restarting dnsmasq daemon ('{self.dnsmasq_restart_command}')")
            call (self.dnsmasq_restart_command)

    def write_subnets (self, outfile, subnets):
        for subnet_id, subnet in subnets.items ():
            outfile.write ("# Subnet: {}\n".format (subnet_id))
            ipv4_params = subnet ['ipv4Network']
            network_addr = ipv4_params['network']
            netmask = ipv4_params ['mask']
            if 'leasePeriod' in subnet:
                lease_period = subnet ['leasePeriod']
            else:
                lease_period = self.default_lease_period
            outfile.write ("dhcp-range=set:{},{},static,{},{}\n"
                           .format (subnet_id, network_addr, netmask,lease_period))
            if 'gateway' in ipv4_params:
                outfile.write ("dhcp-option=tag:{}, option:router,{}\n"
                               .format (subnet_id, ipv4_params['gateway']))
            if 'nameservers' in subnet:
                dns_server=""
                for server in subnet['nameservers']:
                    dns_server += "," + server
                outfile.write ("dhcp-option=tag:{}, option:dns-server{}\n"
                               .format (subnet_id, dns_server))
            outfile.write ("\n")

    def write_devices (self, outfile, devices):
        for subnet_id, devices in devices.items ():
            outfile.write ("# DEVICES FOR SUBNET: {}\n".format (subnet_id))
            for device_id, device in devices.items ():
                mac_addr = EUI (device ['macAddress']['eui48'])
                mac_addr.dialect = netaddr.mac_unix_expanded
                ip_addr = IPv4Address (device ['networkAddress']['ipv4'])
                if 'leasePeriod' in device:
                    lease_period = device ['leasePeriod']
                else:
                    lease_period = self.default_lease_period
                outfile.write ("\n# Device: {}\n".format (device_id))
                # 08:00:27:3c:ae:02,micronet-client-2,set:micronet-client-2,10.50.0.43,2m
                outfile.write ("dhcp-host={},{},set:{},{},{}\n"
                               .format (mac_addr, device_id[0:11], device_id, ip_addr, lease_period))
            outfile.write ("\n")

if __name__ == '__main__':
    print ("Running dnsmask parse/generation test smoke tests")
    dhcp_conffile_path = "doc/dnsmasq_configfile.conf"
    dnsmasq_adapter = DnsMasqAdapter ()
    dnsmasq_adapter.parse_conffile (dhcp_conffile_path)