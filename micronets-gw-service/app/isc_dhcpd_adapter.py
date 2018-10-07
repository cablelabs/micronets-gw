import re
import json
import netaddr
import logging

from pathlib import Path
from ipaddress import IPv4Network
from netaddr import EUI
from subprocess import call
from .utils import ip_addr_pattern, mac_addr_pattern, blank_line_re, comment_line_re

logger = logging.getLogger ('micronets-gw-service')

class IscDhcpdAdapter:
    block_start_re = re.compile ('^# %%MICRONET BLOCK START', re.ASCII)
    block_end_re = re.compile ('^# %%MICRONET BLOCK END', re.ASCII)

    subnet_block_prefix_re = re.compile ('^# %%MICRONET SUBNET (\w.[\w-]*)', re.ASCII)
    open_curly_line_re = re.compile ('^\s*{\s*(#.*)?$')
    closed_curly_line_re = re.compile ('^\s*}\s*(#.*)?$')

    # format: subnet <network address> netmask <network mask>
    subnet_start_re = re.compile ('^\s*subnet\s+(' + ip_addr_pattern + ')\s+netmask\s+('
                                  + ip_addr_pattern + ')\s*$', re.ASCII)

    # format: host <device/host name>
    host_start_re = re.compile ('^\s*host\s+([\w-]+)\s*$', re.ASCII)
    
    # format: hardware ethernet <host mac address> ; 
    hardware_ethernet_re = re.compile ('^\s*hardware\s+ethernet\s+(' + mac_addr_pattern + ')\s*;\s*$')
    
    # format: fixed-address <ip address> ; 
    fixed_address_re = re.compile ('^\s*fixed-address\s+(' + ip_addr_pattern + ')\s*;\s*$')

    # format: option routers <ip address> ;
    router_address_re = re.compile ('^\s*option\s+routers\s+(' + ip_addr_pattern + ')\s*;\s*$')

    # format: option broadcast-address <ip address> ;
    broadcast_address_re = re.compile ('^\s*option\s+broadcast-address\s+(' + ip_addr_pattern + ')\s*;\s*$')

    def __init__ (self, config):
        self.dhcpconf_path = Path (config ['ISC_DHCPD_CONF_FILE'])
        self.dhcpd_restart_command = config ['ISC_DHCPD_RESTART_COMMAND']
        logger.info (f"Instantiated IscDhcpdAdapter with {self.dhcpconf_path.absolute ()}")

    def read_from_conf (self):
        with self.dhcpconf_path.open ('r') as infile:
            infile.line_no = 0
            logger.info (f"IscDhcpdAdapter: Loading subnet data from {self.dhcpconf_path.absolute ()}")
            return self.parse_dhcp_conf (infile)

    def parse_dhcp_conf (self, infile):
        in_prefix = True
        self.prefix_lines = []
        self.postfix_lines = []
        for line in infile:
            infile.line_no += 1
            if in_prefix and self.block_start_re.match (line):
                self.micronet_block = self.parse_micronet_block (infile)
                in_prefix = False
            else:
                if in_prefix:
                    self.prefix_lines.append (line)
                else:
                    self.postfix_lines.append (line)
        logger.info (f"Done reading {self.dhcpconf_path.absolute()}")
        return { 'prefix': self.prefix_lines, 
                 'subnets': self.micronet_block ['subnets'], 
                 'devices' : self.micronet_block ['devices'], 
                 'postfix': self.postfix_lines}

    def parse_micronet_block (self, infile):
        subnets = {}
        devices = {}
        for line in infile:
            infile.line_no += 1
            if self.block_end_re.match (line):
                break
            if (self.blank_line_re.match (line)):
                continue
            subnet_prefix_match_result = self.subnet_block_prefix_re.match (line)
            if (subnet_prefix_match_result):
                subnet_block_name = subnet_prefix_match_result.group (1)
                # logger.debug ("  Found subnet prefix: {}".format (subnet_block_name))
                subnet_block = self.parse_subnet_block (infile, subnet_block_name)
                subnets [subnet_block_name] = subnet_block ['subnet']
                devices [subnet_block_name] = subnet_block ['devices']
                continue
            if (self.comment_line_re.match (line)):
                continue
        return {'subnets' : subnets, 'devices': devices}

    def parse_subnet_block (self, infile, subnet_name):
        # The first line of a subnet block has to start with "subnet"
        line = infile.readline ()
        infile.line_no += 1
        subnet_match_result = self.subnet_start_re.match (line)
        if (not subnet_match_result):
            return None
        subnet = {}
        subnet ['subnetId'] = subnet_name
        subnet ['ipv4Network'] = {'network' : subnet_match_result.group (1), 
                                  'mask' : subnet_match_result.group (2)}
        devices = {}
        if (not self.open_curly_line_re.match (infile.readline ())):
            return None
        for line in infile:
            infile.line_no += 1
            if (self.closed_curly_line_re.match (line)):
                break
            if (self.blank_line_re.match (line)):
                continue
            if (self.comment_line_re.match (line)):
                continue
            router_match_result = self.router_address_re.match (line)
            if (router_match_result):
                router_address = router_match_result.group (1)
                subnet ['gateway'] = router_address
                continue
            broadcast_match_result = self.broadcast_address_re.match (line)
            if (broadcast_match_result):
                broadcast_address = broadcast_match_result.group (1)
                # Not really anything to do here 
                continue
            host_match_result = self.host_start_re.match (line)
            if (host_match_result):
                host_name = host_match_result.group (1)
                device_result = self.parse_device_block (infile, host_name)
                if (not isinstance (device_result, dict)): # There must have been an error
                    return device_result
                devices [device_result ['deviceId']] = device_result
                continue
            # If none of the REs match, bail out
            raise Exception ("Unrecognized subnet entry on line {}: {}".format (infile.line_no, line.rstrip ()))
        return {'subnetId' : subnet_name, 'subnet': subnet, 'devices': devices}

    def parse_device_block (self, infile, device_name):
        infile.line_no += 1
        if (not self.open_curly_line_re.match (infile.readline ())):
            return None
        device = {}
        device ['deviceId'] = device_name
        for line in infile:
            infile.line_no += 1
            if (self.closed_curly_line_re.match (line)):
                break
            if (blank_line_re.match (line)):
                continue
            if (comment_line_re.match (line)):
                continue
            hardware_ethernet_match_result = self.hardware_ethernet_re.match (line)
            if (hardware_ethernet_match_result):
                host_mac_address = hardware_ethernet_match_result.group (1)
                device ['macAddress'] = {'eui48': host_mac_address}
                continue
            fixed_address_match_result = self.fixed_address_re.match (line)
            if (fixed_address_match_result):
                ipv4_address = fixed_address_match_result.group (1)
                device ['networkAddress'] = {'ipv4': ipv4_address}
                continue
            # If none of the REs match, bail out
            raise Exception ("Unrecognized device entry on line {}: {}".format (infile.line_no, line.rstrip ()))
        if (not 'macAddress' in device):
            return 'Error: Device {} is missing a "hardware ethernet" entry'.format (device_name)
        if (not 'networkAddress' in device):
            return 'Error: Device {} is missing a fixed-address entry'.format (infile.fileno (), device_name)
        return device

    def save_to_conf (self, subnets, devices):
        with self.dhcpconf_path.open ('w') as outfile:
            logger.info ("IscDhcpdAdapter: Saving subnet data to {self.dhcpconf_path.absolute ()}")
            self.write_dhcp_conf (outfile)
        if self.dhcpd_restart_command:
            logger.info (f"Restarting ISC dhcp daemon ('{self.dhcpd_restart_command}')")
            call (self.dhcpd_restart_command)

    def write_dhcp_conf (self, outfile):
        for line in self.prefix_lines:
            outfile.write (line)
        self.write_subnets (outfile)
        for line in self.postfix_lines:
            outfile.write (line)

    def write_subnets (self, outfile):
        outfile.write ("# %%MICRONET BLOCK START\n")
        outfile.write ("# DO NOT modify anything between here and %%MICRONET BLOCK END\n")
        for subnet_id, subnet in self.micronet_block ['subnets'].items ():
            outfile.write ("\n# %%MICRONET SUBNET {}\n".format (subnet_id))
            ipv4_params = subnet ['ipv4Network']
            network_addr = ipv4_params['network']
            netmask = ipv4_params ['mask']
            outfile.write ("subnet {} netmask {}\n".format (network_addr, netmask))
            outfile.write ("{\n")
            network = IPv4Network (network_addr + "/" + netmask)
            outfile.write ("  option broadcast-address {};\n".format (network.broadcast_address))
            if 'gateway' in ipv4_params:
                outfile.write ("  option routers {};\n".format (ipv4_params['gateway']))
            self.write_devices_for_subnet (outfile, subnet_id)
            outfile.write ("}\n")
        outfile.write ("# %%MICRONET BLOCK END\n")

    def write_devices_for_subnet (self, outfile, subnetId):
        device_list = self.micronet_block ['devices'] [subnetId].items ()
        for device_id, device in device_list:
            mac_addr = EUI (device ['macAddress']['eui48'])
            mac_addr.dialect = netaddr.mac_unix_expanded
            outfile.write ("  host {}\n".format (device_id))
            outfile.write ("  {\n")
            outfile.write ("    hardware ethernet {};\n".format (mac_addr))
            outfile.write ("    fixed-address {};\n".format (device ['networkAddress'] ['ipv4']))
            outfile.write ("  }\n")
        
if __name__ == '__main__':
    print ("Running ISC DHCPD conf parse/generation test smoke tests")
    dhcp_conf_path = "doc/dhcpd-sample.conf"
    dhcp_conf_parser = IscDhcpdAdapter (dhcp_conf_path)

    dhcp_conf = dhcp_conf_parser.read_from_conf ()
    print ("Done parsing. Found: ")
    print ("\nFound prefix:\n")
    for line in dhcp_conf ['prefix']:
        print (line.rstrip ())
    print ("Found subnets:")
    print (json.dumps (dhcp_conf ['subnets'], indent=2))
    print ("Found devices:")
    print (json.dumps (dhcp_conf ['devices'], indent=2))
    print ("\Found postfix:\n")
    for line in dhcp_conf ['postfix']:
        print (line.rstrip ())
