import re, logging

from pathlib import Path
from .utils import blank_line_re, comment_line_re

logger = logging.getLogger ('micronets-gw-service')

class OpenFlowAdapter:
    # iface brmn001 inet dhcp
    #   ovs_type OVSBridge
    #   ovs_ports enp3s0 enxac7f3ee61832 enx00e04c534458
    #   ovs_bridge_uplink_port enp3s0
    interfaces_ovs_bridge_uplink_re = re.compile ('^\s*ovs_bridge_uplink_port\s+(\w+)\s*$')
    interfaces_ovs_ports_re = re.compile ('\s*ovs_ports\s+([\w ]+)\s*$')

    def __init__ (self, config):
        self.interfaces_file_path = Path (config ['FLOW_ADAPTER_NETWORK_INTERFACES_PATH'])

        with self.interfaces_file_path.open ('r') as infile:
            try:
                infile.line_no = 0
                logger.info (f"IscDhcpdAdapter: Loading bridge port {self.interfaces_file_path.absolute ()}")
                self.read_interfaces_file (infile)
            except Exception as e:
                raise Exception ("IscDhcpdAdapter: Error on line {} of {}: {}"
                                 .format (infile.line_no, self.interfaces_file_path.absolute (), e))

    def read_interfaces_file (self, infile):
        self.ovs_micronet_ports = None
        self.ovs_uplink_port = None
        for line in infile:
            infile.line_no += 1
            if (blank_line_re.match (line)):
                continue
            if (comment_line_re.match (line)):
                continue
            interfaces_ovs_ports_match = self.interfaces_ovs_ports_re.match (line)
            if interfaces_ovs_ports_match:
                self.ovs_micronet_ports = interfaces_ovs_ports_match.group (1).split ()
                continue
            interfaces_uplink_port = self.interfaces_ovs_bridge_uplink_re.match (line)
            if interfaces_uplink_port:
                self.ovs_uplink_port = interfaces_uplink_port.group (1)
                continue
            continue

        logger.info (f"OpenFlowAdapter.read_interfaces_file: Done reading {infile}")
        if not self.ovs_micronet_ports:
            raise Exception (f"Did not find a ovs_ports entry in {infile}")
        if not self.ovs_uplink_port:
            raise Exception (f"Did not find a ovs_bridge_uplink_port entry in {infile}")
        self.ovs_micronet_ports.remove (self.ovs_uplink_port)
        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_micronet_ports: {self.ovs_micronet_ports}")
        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_uplink_port: {self.ovs_uplink_port}")

    def update (self, subnet_list, device_lists):
        pass