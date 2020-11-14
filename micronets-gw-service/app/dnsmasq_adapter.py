import netaddr
import logging

from pathlib import Path
from ipaddress import IPv4Network, IPv4Address
from netaddr import EUI
from subprocess import call

logger = logging.getLogger ('micronets-gw-service')


class DnsMasqAdapter:

    def __init__ (self, config):
        self.conffile_path = Path (config ['DNSMASQ_ADAPTER_CONF_FILE'])
        self.dnsmasq_restart_command = config ['DNSMASQ_ADAPTER_RESTART_COMMAND']
        self.default_lease_period = config ['DHCP_ADAPTER_DEFAULT_LEASE_PERIOD']
        lease_script_settings = config ['DNSMASQ_ADAPTER_LEASE_SCRIPT']
        self.lease_script = Path (lease_script_settings) if lease_script_settings else None
        with self.conffile_path.open ('a'):
            pass
        logger.info  (f"Instantiated DnsMasq with conf file {self.conffile_path.absolute()}")
        logger.info  (f"dnsmasq lease script location: {self.lease_script.absolute() if self.lease_script else None}")

    async def update (self, micronets, devices):
        logger.debug ("DnsMasqAdapter.update")
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
                if (len(device_id) <= 12):
                    short_device_id = device_id
                else:
                    short_device_id = device_id[0:8]+device_id[-4:]
                outfile.write (f"\n# Device: {device_id}\n")
                outfile.write ("dhcp-host={},{},set:{},{},{}\n"
                               .format (mac_addr, short_device_id, device_id, ip_addr, lease_period))
            outfile.write ("\n")
