import os, sys
import re
import json
import netaddr
import logging

from pathlib import Path
from ipaddress import IPv4Network, IPv4Address
from netaddr import EUI
from subprocess import call
from .utils import ip_addr_pattern, mac_addr_pattern, blank_line_re, comment_line_re, find_micronet_id_for_host

logger = logging.getLogger ('micronets-gw-service')

class DnsMasqAdapter:
    lease_duration_re = 'infinite|[0-9]+[hm]?'

    # # Micronet: testmicronet001, interface: enxac7f3ee61832
    # # Micronet: wired-micronet-1, interface: enp3s0, vlan: 2112
    dhcp_range_prefix_re = re.compile ('^\s*#\s*Micronet:\s*(\w.[\w-]*)\s*,'
                                       '\s*interface:\s*(\w+)\s*(?:,\s*vlan:\s*([0-9]+)?\s*)?$',
                                       re.ASCII)

    # dhcp-range=set:testmicronet001,10.40.0.0,static,255.255.255.0,3m
    dhcp_range_re = re.compile ('^\s*dhcp-range\s*=\s*set:\s*(\w.[\w-]*),(' + ip_addr_pattern 
                                + '),\s*static,\s*(' + ip_addr_pattern
                                + '),\s*(' + lease_duration_re + ')\s*$', re.ASCII)

    dhcp_range_option_prefix = '^\s*dhcp-option\s*=\s*tag:\s*(\w.[\w-]*),\s*'

    # dhcp-option=tag:testmicronet001, option:router,10.40.0.1
    dhcp_range_router_re = re.compile (dhcp_range_option_prefix
                                       + 'option:\s*router\s*,(' + ip_addr_pattern + ')$', re.ASCII)

    # dhcp-option=tag:testmicronet001, option:dns-server,8.8.8.8,4.4.4.4
    dhcp_range_dns_server_re = re.compile (dhcp_range_option_prefix
                                           + 'option:\s*dns-server((?:\s*,\s*'
                                           + ip_addr_pattern + ')+)', re.ASCII)

    # dhcp-hostsfile=/home/micronut/projects/micronets/micronets-dhcp/dnsmasq-hosts
    dhcp_hostfile_re = re.compile ('dhcp-hostsfile\s*=\s*(.+)$')

    # Device: mydevice03, inRules: [], outRules: [], allowHosts: [], denyHosts: ["8.8.8.8"],psk: []
    dhcp_device_prefix_re = re.compile ('^\s*#\sDevice:\s*(\w.[\w-]*)\s*,\s*'
                                        'inRules:\s*(\[[^\[\]]*\]),\s*'
                                        'outRules:\s*(\[[^\[\]]*\]),\s*'
                                        'allowHosts:\s*(\[[^\[\]]*\]),\s*'
                                        'denyHosts:\s*(\[[^\[\]]*\]),\s*'
                                        'psk:\s*(\w*)\s*$', re.ASCII)

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
        self.lease_script = Path (config ['DNSMASQ_LEASE_SCRIPT'])
        with self.conffile_path.open ('a'):
            pass
        logger.info  (f"Instantiated DnsMasq with conf file {self.conffile_path.absolute()}")
        logger.info  (f"dnsmasq lease script location: {self.lease_script.absolute()}")

    def read_from_conf (self):
        with self.conffile_path.open ('r') as infile:
            try:
                infile.line_no = 0
                logger.info (f"DnsMasqAdapter: Loading micronet data from {self.conffile_path.absolute ()}")
                read_conf = self.parse_conffile (infile)
                micronets = read_conf ['micronets']
                devices = read_conf ['devices']
                return {"micronets": micronets, "devices": devices}
            except Exception as e:
                raise Exception ("DnsMasqAdapter: Error on line {} of {}: {}"
                                 .format (infile.line_no, self.conffile_path.absolute (), e))

    def parse_conffile (self, infile):
        micronets = {}
        devices_list = {}
        prefix_micronet_id = None
        prefix_host_id = None

        for line in infile:
            infile.line_no += 1
            if (blank_line_re.match (line)):
                continue
            dhcp_range_prefix_match_result = self.dhcp_range_prefix_re.match (line)
            if (dhcp_range_prefix_match_result):
                (prefix_micronet_id, prefix_interface, prefix_vlan) = dhcp_range_prefix_match_result.groups()
                continue
            dhcp_host_prefix_match = self.dhcp_device_prefix_re.match (line)
            if dhcp_host_prefix_match:
                prefix_host_id = dhcp_host_prefix_match.group(1)
                prefix_host_out_rules_str = dhcp_host_prefix_match.group(2)
                prefix_host_in_rules_str = dhcp_host_prefix_match.group(3)
                prefix_host_allow_hosts_str = dhcp_host_prefix_match.group(4)
                prefix_host_deny_hosts_str = dhcp_host_prefix_match.group(5)
                prefix_host_psk_str = dhcp_host_prefix_match.group(6)
                logger.info(f"DnsMasqAdapter.parse_conffile:  Found host {prefix_host_id}: "
                            f"outRules:{prefix_host_out_rules_str}, inRules:{prefix_host_in_rules_str}, "
                            f"allowHosts:{prefix_host_out_rules_str}, denyHosts:{prefix_host_in_rules_str}, "
                            f"psk:{prefix_host_psk_str}")

                prefix_host_out_rules = json.loads(prefix_host_out_rules_str)
                prefix_host_in_rules = json.loads(prefix_host_in_rules_str)
                prefix_host_allow_hosts = json.loads(prefix_host_allow_hosts_str)
                prefix_host_deny_hosts = json.loads(prefix_host_deny_hosts_str)
                logger.info(f"DnsMasqAdapter.parse_conffile:  Found host {prefix_host_id}: "
                            f"outRules:{prefix_host_out_rules}, inRules:{prefix_host_in_rules}, "
                            f"allowHosts:{prefix_host_allow_hosts}, denyHosts:{prefix_host_deny_hosts}")
            if (comment_line_re.match (line)):
                continue
            dhcp_range_match_result = self.dhcp_range_re.match (line)
            if (dhcp_range_match_result):
                if not prefix_micronet_id:
                    raise Exception ("Found dhcp-range without preceding '# Micronet:' line")
                micronet_id = dhcp_range_match_result.group (1)
                micronet_network = dhcp_range_match_result.group (2)
                micronet_netmask = dhcp_range_match_result.group (3)
                micronet_lease_duration = dhcp_range_match_result.group (4)
                if prefix_micronet_id != micronet_id:
                    raise Exception(f"Found dhcp-range with mismatched micronet id ({micronet_id} != {prefix_micronet_id})")
                prefix_micronet_id = None
                network = IPv4Network (micronet_network + "/" + micronet_netmask, strict=True)
                logger.debug ("DnsMasqAdapter.parse_conffile: Found micronet range: {} {} {} {}"
                              .format (micronet_id, micronet_network, micronet_netmask, micronet_lease_duration))

                if micronet_id in micronets:
                    raise Exception ("Duplicate micronet ID '{}'".format (micronet_id))
                if not network:
                    raise Exception ("Invalid micronet network/netmask '{}/{}'"
                                     .format (micronet_network, micronet_netmask))
                micronet = {}
                micronet ['micronetId'] = micronet_id
                micronet ['ipv4Network'] = {'network' : str (network.network_address), 'mask' : str (network.netmask)}
                micronet ['interface'] = prefix_interface
                if prefix_vlan:
                    micronet ['vlan'] = prefix_vlan
                micronets [micronet_id] = micronet
                devices_list [micronet_id] = {}
                prefix_micronet_id = None
                continue
            dhcp_range_router_match = self.dhcp_range_router_re.match (line)
            if (dhcp_range_router_match):
                micronet_id = dhcp_range_router_match.group (1)
                router_address = dhcp_range_router_match.group (2)
                logger.debug (f"DnsMasqAdapter.parse_conffile: Found router address: "
                              f"{micronet_id} {router_address}")
                if not micronet_id in micronets:
                    raise Exception ("Could not find micronet ID '{}'".format (micronet_id))
                addr = IPv4Address (router_address)
                if not addr or addr.is_loopback or addr.is_multicast:
                    raise Exception ("Invalid router/gateway address '{}'".format (router_address))
                micronet = micronets [micronet_id]
                logger.debug (f"DnsMasqAdapter.parse_conffile: micronet {micronet_id}: {micronet}")
                micronet ['ipv4Network']['gateway'] = str (addr)
                continue
            dhcp_range_dns_server_match = self.dhcp_range_dns_server_re.match (line)
            if (dhcp_range_dns_server_match):
                micronet_id = dhcp_range_dns_server_match.group (1)
                dns_server_addresses = dhcp_range_dns_server_match.group (2)
                logger.debug (f"DnsMasqAdapter.parse_conffile: Found dns server addresses: "
                              f"{micronet_id} {dns_server_addresses}")
                if not micronet_id in micronets:
                    raise Exception ("Could not find micronet ID '{}'".format (micronet_id))
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
                micronets [micronet_id]['nameservers'] = nameservers
                continue
            dhcp_host_match = self.dhcp_host_re.match (line)
            if (dhcp_host_match):
                if not prefix_host_id:
                    raise Exception ("Found dhcp-host without preceding '# Device:' line")
                dhcp_host_mac = dhcp_host_match.group (1)
                dhcp_host_id = dhcp_host_match.group (2)
                dhcp_host_tag = dhcp_host_match.group (3)
                dhcp_host_ip = dhcp_host_match.group (4)
                dhcp_host_lease_duration = dhcp_host_match.group (5)
                logger.debug ("DnsMasqAdapter.parse_conffile: Found dhcp host entry: {} {} {} {} {}"
                              .format (dhcp_host_mac, dhcp_host_id, dhcp_host_ip, dhcp_host_tag,
                                       dhcp_host_lease_duration))
                if not netaddr.valid_mac (dhcp_host_mac):
                    raise Exception ("Invalid host MAC address '{}'".format (dhcp_host_mac))
                eui_mac_addr = EUI (dhcp_host_mac)
                eui_mac_addr.dialect = netaddr.mac_unix_expanded
                addr = IPv4Address (dhcp_host_ip)
                if not addr or addr.is_loopback or addr.is_multicast:
                    raise Exception ("Invalid host IP address '{}'".format (dhcp_host_ip))
                micronet_id = find_micronet_id_for_host (micronets, dhcp_host_ip)
                if not micronet_id:
                    raise Exception ("Could not find a micronet compatible with host '{}'".format (addr))
                device = {'deviceId': prefix_host_id}
                device ['macAddress'] = {'eui48': str(eui_mac_addr)}
                device ['networkAddress'] = {'ipv4': str (addr)}
                if len(prefix_host_out_rules) > 0:
                    device ['outRules'] = prefix_host_out_rules
                if len(prefix_host_in_rules) > 0:
                    device ['inRules'] = prefix_host_in_rules
                if len(prefix_host_allow_hosts) > 0:
                    device ['allowHosts'] = prefix_host_allow_hosts
                if len(prefix_host_deny_hosts) > 0:
                    device ['denyHosts'] = prefix_host_deny_hosts
                if prefix_host_psk_str:
                    device ['psk'] = prefix_host_psk_str
                device_list = devices_list [micronet_id]
                device_list [prefix_host_id] = device
                prefix_host_id = None
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
        logger.info ("DnsMasqAdapter.parse_conffile: Micronets:")
        logger.info (json.dumps (micronets, indent=4))
        return {'micronets': micronets, 'devices': devices_list}

    def save_to_conf (self, micronets, devices):
        logger.debug ("DnsMasqAdapter.save_to_conf")
        with self.conffile_path.open ('w') as outfile:
            logger.info (f"DnsMasqAdapter: Saving micronet data to {self.conffile_path.absolute ()}")
            outfile.write ("# THIS CONF FILE IS MANAGED BY THE MICRONETS GW SERVICE\n\n")
            outfile.write ("# MODIFICATIONS TO THIS FILE WILL BE OVER-WRITTEN\n\n")
            outfile.write ("dhcp-script={}\n\n".format (self.lease_script.absolute ()))
            self.write_micronets (outfile, micronets)
            self.write_devices (outfile, devices)

        if self.dnsmasq_restart_command:
            logger.info (f"Restarting dnsmasq daemon ('{self.dnsmasq_restart_command}')")
            call (self.dnsmasq_restart_command)

    def write_micronets (self, outfile, micronets):
        for micronet_id, micronet in micronets.items ():
            # # Micronet: wired-micronet-1, interface: enp3s0
            interface = micronet ['interface']
            if 'vlan' in micronet:
                vlan_elem = f", vlan: {micronet ['vlan']}"
            else:
                vlan_elem = ""
            outfile.write (f"# Micronet: {micronet_id}, interface: {interface}{vlan_elem}\n")
            ipv4_params = micronet ['ipv4Network']
            network_addr = ipv4_params['network']
            netmask = ipv4_params ['mask']
            if 'leasePeriod' in micronet:
                lease_period = micronet ['leasePeriod']
            else:
                lease_period = self.default_lease_period
            outfile.write ("dhcp-range=set:{},{},static,{},{}\n"
                           .format (micronet_id, network_addr, netmask,lease_period))
            if 'gateway' in ipv4_params:
                outfile.write ("dhcp-option=tag:{}, option:router,{}\n"
                               .format (micronet_id, ipv4_params['gateway']))
            if 'nameservers' in micronet:
                dns_server=""
                for server in micronet['nameservers']:
                    dns_server += "," + server
                outfile.write ("dhcp-option=tag:{}, option:dns-server{}\n"
                               .format (micronet_id, dns_server))
            outfile.write ("\n")

    def write_devices (self, outfile, devices):
        for micronet_id, devices in devices.items ():
            outfile.write ("# DEVICES FOR MICRONET: {}\n".format (micronet_id))
            for device_id, device in devices.items ():
                mac_addr = EUI (device ['macAddress']['eui48'])
                mac_addr.dialect = netaddr.mac_unix_expanded
                ip_addr = IPv4Address (device ['networkAddress']['ipv4'])
                if 'leasePeriod' in device:
                    lease_period = device ['leasePeriod']
                else:
                    lease_period = self.default_lease_period
                if 'outRules' in device:
                    out_rules = json.dumps(device['outRules'])
                else:
                    out_rules = []
                if 'inRules' in device:
                    in_rules = json.dumps(device['inRules'])
                else:
                    in_rules = []
                if 'allowHosts' in device:
                    allow_hosts = json.dumps(device['allowHosts'])
                else:
                    allow_hosts = []
                if 'denyHosts' in device:
                    deny_hosts = json.dumps(device['denyHosts'])
                else:
                    deny_hosts = []
                psk = device.get('psk',"")
                if (len(device_id) <= 12):
                    short_device_id = device_id
                else:
                    short_device_id = device_id[0:8]+device_id[-4:]
                outfile.write ("\n# Device: {}, inRules: {}, outRules: {}, allowHosts: {}, denyHosts: {},psk: {}\n"
                               .format (device_id, out_rules, in_rules, allow_hosts, deny_hosts, psk))
                # 08:00:27:3c:ae:02,micronet-client-2,set:micronet-client-2,10.50.0.43,2m
                outfile.write ("dhcp-host={},{},set:{},{},{}\n"
                               .format (mac_addr, short_device_id, device_id, ip_addr, lease_period))
            outfile.write ("\n")

if __name__ == '__main__':
    print ("Running dnsmask parse/generation test smoke tests")
    dhcp_conffile_path = "doc/dnsmasq_configfile.conf"
    dnsmasq_adapter = DnsMasqAdapter ()
    dnsmasq_adapter.parse_conffile (dhcp_conffile_path)
