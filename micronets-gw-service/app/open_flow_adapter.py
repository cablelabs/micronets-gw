import re, logging, tempfile, subprocess

from pathlib import Path
from .utils import blank_line_re, comment_line_re
from subprocess import call

logger = logging.getLogger ('micronets-gw-service')

class OpenFlowAdapter:
    # iface brmn001 inet dhcp
    #   ovs_type OVSBridge
    #   ovs_ports enp3s0 enxac7f3ee61832 enx00e04c534458
    #   ovs_bridge_uplink_port enp3s0
    interfaces_ovs_bridge_uplink_re = re.compile ('^\s*ovs_bridge_uplink_port\s+(\w+)\s*$')
    interfaces_ovs_ports_re = re.compile ('\s*ovs_ports\s+([\w ]+)\s*$')
    port_intface_re = re.compile('^\s*port ([0-9]+): (\w+).*$')

    def __init__ (self, config):
        self.interfaces_file_path = Path (config ['FLOW_ADAPTER_NETWORK_INTERFACES_PATH'])
        self.apply_openflow_command = config['FLOW_ADAPTER_APPLY_FLOWS_COMMAND']

        with self.interfaces_file_path.open ('r') as infile:
            try:
                infile.line_no = 0
                logger.info (f"OpenFlowAdapter: Loading bridge port {self.interfaces_file_path.absolute ()}")
                self.read_interfaces_file (infile)
            except Exception as e:
                raise Exception ("OpenFlowAdapter: Error on line {} of {}: {}"
                                 .format (infile.line_no, self.interfaces_file_path.absolute (), e))

        try:
            self.determine_port_mappings ()
        except Exception as e:
            raise Exception ("OpenFlowAdapter: Error determining port mppings: {}".format (e))

    def read_interfaces_file (self, infile):
        self.ovs_micronet_interfaces = None
        self.ovs_uplink_interface = None
        for line in infile:
            infile.line_no += 1
            if (blank_line_re.match (line)):
                continue
            if (comment_line_re.match (line)):
                continue
            interfaces_ovs_ports_match = self.interfaces_ovs_ports_re.match (line)
            if interfaces_ovs_ports_match:
                self.ovs_micronet_interfaces = interfaces_ovs_ports_match.group (1).split ()
                continue
            interfaces_uplink_port = self.interfaces_ovs_bridge_uplink_re.match (line)
            if interfaces_uplink_port:
                self.ovs_uplink_interface = interfaces_uplink_port.group (1)
                continue
            continue

        logger.info (f"OpenFlowAdapter.read_interfaces_file: Done reading {infile}")
        if not self.ovs_micronet_interfaces:
            raise Exception (f"Did not find a ovs_ports entry in {infile}")
        if not self.ovs_uplink_interface:
            raise Exception (f"Did not find a ovs_bridge_uplink_port entry in {infile}")
        self.ovs_micronet_interfaces.remove (self.ovs_uplink_interface)
        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_micronet_ports: {self.ovs_micronet_interfaces}")
        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_uplink_port: {self.ovs_uplink_interface}")

    def determine_port_mappings (self):
        # TODO: Consider using ovsdb-query to get the port mappings
        self.interface_for_port = {}
        self.port_for_interface = {}
        cp = subprocess.run(["/usr/bin/ovs-dpctl", "show"], stdout=subprocess.PIPE)
        if not cp or not cp.stdout:
            raise Exception (f"Error running ovs-dpctl: no stdout")
        dpctl_out = cp.stdout.decode (encoding="utf-8")

        logger.info ("Port interfaces:\n"
                     "------------------------------------------------------------------------\n"
                     + dpctl_out)
        lines = dpctl_out.split ("\n")
        for line in lines:
            match = self.port_intface_re.match (line)
            if match:
                port = match.group (1)
                interface = match.group (2)
                logger.info(f"Found port {port} for interface {interface}")
                self.interface_for_port[port] = interface
                self.port_for_interface[interface] = port

    def update (self, subnet_list, device_lists):
        logger.info (f"OpenFlowAdapter.update ()")
        logger.info (f"OpenFlowAdapter.update: device_lists: {device_lists}")
        disabled_interfaces = self.ovs_micronet_interfaces.copy ()
        logger.info (f"OpenFlowAdapter.update: configured interfaces: {disabled_interfaces}")

        with tempfile.NamedTemporaryFile (mode='wt') as flow_file:
            flow_file_path = Path (flow_file.name)
            start_table = 0
            port_filter_table = 20
            logger.info(f"created temporary file {flow_file_path}")
            flow_file.write ("del\n") # This will clear all flows
            target_bridge = "brmn001"

            # Walk the subnets
            cur_subnet_table = 100
            for subnet_id, subnet in subnet_list.items ():
                subnet_int = subnet ['interface']
                subnet_bridge = subnet ['ovsBridge']
                logger.info (f"Enabling flow for subnet {subnet_id} (interface {subnet_int})")
                if not target_bridge:
                    target_bridge = subnet_bridge
                else:
                    if subnet_bridge != target_bridge:
                        raise Exception(f"subnet {subnet_id} has a different ovsBridge ('{subnet_bridge}')"
                                        f"than other subnets ({target_bridge})")

                if subnet_int not in self.ovs_micronet_interfaces:
                    raise Exception (f"interface {subnet_int} in subnet {subnet_id} not found "
                                     "in configured micronet interfaces ({self.ovs_micronet_interfaces})")
                disabled_interfaces.remove (subnet_int)
                subnet_port = self.port_for_interface [subnet_int]
                flow_file.write (f"add table={start_table},priority=10,in_port={subnet_port} "
                                 f"actions=resubmit(,{cur_subnet_table})\n")
                # Walk the devices and create a device filter table for each interface
                for device_id, device in device_lists [subnet_id].items ():
                    device_mac = device ['macAddress']['eui48']
                    logger.info (f"Looking at device {device_id}: {device}")
                    flow_file.write (f"add table={cur_subnet_table},priority=10,dl_src={device_mac} "
                                     f"actions=resubmit(,{port_filter_table})\n")
                flow_file.write (f"add table={cur_subnet_table},priority=5 "
                                 f"actions=drop\n")
                cur_subnet_table += 1
            for interface in disabled_interfaces:
                logger.info (f"Disabling flow for interface {interface}")
                subnet_port = self.port_for_interface [interface]
                flow_file.write (f"add table={start_table},priority=10,in_port={subnet_port} "
                                 f"actions=drop\n")
            # All requests that aren't associated with a micronet go to NORMAL
            flow_file.write (f"add table={start_table},priority=5 "
                             f"actions=NORMAL\n")
            # The common port filtering rules (after a packet has flowed through the
            #  interface and mac tables

            # Don't allow DHCP requests to flow out of the gateway
            flow_file.write (f"add table={port_filter_table},priority=10,udp,tp_dst=67 "
                             f"actions=LOCAL\n")
            # TODO: Consider blocking other traffic (all broadcast packets?)
            flow_file.write (f"add table={port_filter_table},priority=5 "
                             f"actions=NORMAL\n")
            flow_file.flush ()

            with flow_file_path.open('r') as infile:
                infile.line_no = 0
                logger.info ("Issuing new flows:")
                logger.info ("------------------------------------------------------------------------")
                for line in infile:
                    logger.info (line)
                logger.info ("------------------------------------------------------------------------")

            run_cmd = self.apply_openflow_command.format (target_bridge, flow_file_path)
            try:
                logger.info ("Running: " + run_cmd)
                status_code = call (run_cmd.split ())
                logger.info (f"Flow application command returned status code {status_code}")
            except Exception as e:
                logger.warning (f"ERROR: Flow application command failed: {e}")
