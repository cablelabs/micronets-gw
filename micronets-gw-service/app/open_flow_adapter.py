import re, logging, tempfile, subprocess, asyncio

from pathlib import Path
from .utils import blank_line_re, comment_line_re, unroll_host_list
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
    ovs_dpctl_show_filename = None
    ovs_dpctl_show_command = None

    def __init__ (self, config):
        self.interfaces_file_path = Path (config ['FLOW_ADAPTER_NETWORK_INTERFACES_PATH'])
        self.apply_openflow_command = config['FLOW_ADAPTER_APPLY_FLOWS_COMMAND']
        if 'FLOW_ADAPTER_DPCTL_SHOW_FILE' in config:
            # Really just for development/test
            self.ovs_dpctl_show_filename = config['FLOW_ADAPTER_DPCTL_SHOW_FILE']
        else:
            self.ovs_dpctl_show_command = config['FLOW_ADAPTER_DPCTL_SHOW_COMMAND']

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
            raise Exception ("OpenFlowAdapter: Error determining port mappings: {}".format (e))

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
        if self.ovs_dpctl_show_filename:
            ovs_dpctl_show_filepath = Path (self.ovs_dpctl_show_filename)
            with ovs_dpctl_show_filepath.open('r') as infile:
                try:
                    dpctl_out = infile.read()
                except Exception as e:
                    raise Exception("OpenFlowAdapter: Error reading dpctl-show file: {}".format(e))
        else:
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

    async def update (self, subnet_list, device_lists):
        logger.info (f"OpenFlowAdapter.update ()")
        logger.info (f"OpenFlowAdapter.update: device_lists: {device_lists}")

        # Note: These flows are a work-in-progress

        disabled_interfaces = self.ovs_micronet_interfaces.copy ()
        logger.info (f"OpenFlowAdapter.update: configured interfaces: {disabled_interfaces}")

        with tempfile.NamedTemporaryFile (mode='wt') as flow_file:
            flow_file_path = Path (flow_file.name)
            logger.info(f"created temporary file {flow_file_path}")
            target_bridge = None
            start_table = 0
            trunk_table = 2
            unrestricted_device_table = 3
            flow_file.write ("del\n") # This will clear all flows

            flow_file.write(f"add table={start_table},priority=20,dl_dst=01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0, "
                            f"actions=drop\n")
            flow_file.write(f"add table={start_table},priority=20,dl_src=01:00:00:00:00:00/01:00:00:00:00:00, "
                            f"actions=drop\n")
            # This NORMAL action for LOCAL means the packet will be delivered
            flow_file.write(f"add table={start_table},priority=10,in_port=LOCAL "
                            f"actions=NORMAL\n")
            flow_file.write(f"add table={start_table},priority=10,in_port=1 "
                            f"actions=NORMAL\n")

            # Walk the subnets
            cur_table = 10
            for subnet_id, subnet in subnet_list.items ():
                subnet_int = subnet ['interface']
                subnet_bridge = subnet ['ovsBridge']
                subnet_network = subnet ['ipv4Network']['network']
                cur_subnet_table = cur_table
                cur_table += 1
                logger.info (f"Creating flow table {cur_subnet_table} for subnet {subnet_id} (interface {subnet_int})")
                if not target_bridge:
                    target_bridge = subnet_bridge
                else:
                    # Currently only support all subnets on the same bridge
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
                # Walk the devices in the interface and create appropriate device filter tables
                flow_file.write (f"  # TABLE {cur_subnet_table}: micronet {subnet_id}"
                                 f" (interface {subnet_int}, subnet {subnet_network})\n")
                for device_id, device in device_lists [subnet_id].items ():
                    device_mac = device ['macAddress']['eui48']
                    host_spec_list = None
                    if 'allowHosts' in device:
                        hosts = device['allowHosts']
                        host_spec_list = await unroll_host_list (hosts)
                        host_action = "NORMAL"
                        default_host_action = "drop"
                        # Add critical hosts to the allow list
                        host_spec_list.append(subnet['ipv4Network']['gateway'])
                        if 'nameservers' in subnet:
                            host_spec_list += subnet['nameservers']
                        if 'nameservers' in device:
                            host_spec_list += device['nameservers']
                    elif 'denyHosts' in device:
                        hosts = device ['denyHosts']
                        host_spec_list = await unroll_host_list (hosts)
                        host_action = "drop"
                        default_host_action = "NORMAL"

                    if host_spec_list:
                        cur_dev_table = cur_table
                        cur_table += 1
                        flow_file.write (f"  add table={cur_subnet_table},priority=20,dl_src={device_mac} "
                                         f"actions=resubmit(,{cur_dev_table})\n")
                        flow_file.write (f"    # TABLE {cur_dev_table}: hosts allowed/denied for device {device_id} (MAC {device_mac})\n")
                        flow_file.write (f"    add table={cur_dev_table},priority=20,udp,tp_dst=67 "
                                         f"actions=LOCAL\n")
                        flow_file.write (f"    add table={cur_dev_table},priority=20,arp "
                                         f"actions={host_action}\n")
                        flow_file.write (f"    #   hosts: {hosts}\n")
                        for host_spec in host_spec_list:
                            flow_file.write(f"    add table={cur_dev_table},priority=10,ip,ip_dst={host_spec} "
                                            f"actions=NORMAL\n")
                        flow_file.write (f"    add table={cur_dev_table},priority=5 "
                                         f"actions={default_host_action}\n")
                    else:
                        flow_file.write (f"  add table={cur_subnet_table},priority=20,dl_src={device_mac} "
                                         f"actions=resubmit(,{unrestricted_device_table})\n")
                flow_file.write (f"  add table={cur_subnet_table},priority=5 "
                                 f"actions=drop\n")
            for interface in disabled_interfaces:
                logger.info (f"Disabling flow for interface {interface}")
                subnet_port = self.port_for_interface [interface]
                flow_file.write (f"add table={start_table},priority=10,in_port={subnet_port} "
                                 f"actions=drop\n")
            # The common port filtering rules (after a packet has flowed through the
            #  interface and mac tables

            # Table for all trunk traffic
            flow_file.write (f"add table={start_table},priority=10,in_port={self.ovs_uplink_interface} "
                             f"actions=resubmit(,{trunk_table})\n")
            flow_file.write(f"  # TABLE {trunk_table}: Trunk ingress table\n")
            flow_file.write (f"  add table={trunk_table},priority=10,udp,tp_dst=67 "
                             f"actions=LOCAL\n")
            flow_file.write (f"  add table={trunk_table},priority=5 "
                             f"actions=NORMAL\n")

            # All requests that don't match a known port are dropped (like a cold stone)
            flow_file.write (f"add table={start_table},priority=5 "
                             f"actions=drop\n")

            # Table for all devices with no restrictions (no allowHosts/denyHosts)
            flow_file.write(f"  # TABLE {unrestricted_device_table}: Unrestricted device table (no allowHosts/denyHosts)\n")
            flow_file.write (f"  add table={unrestricted_device_table},priority=10,udp,tp_dst=67 "
                             f"actions=LOCAL\n")
            flow_file.write (f"  add table={unrestricted_device_table},priority=5 "
                             f"actions=drop\n")
            flow_file.flush ()

            with flow_file_path.open('r') as infile:
                infile.line_no = 0
                logger.info ("Issuing new flows:")
                logger.info ("------------------------------------------------------------------------")
                for line in infile:
                    logger.info (line[0:-1])
                logger.info ("------------------------------------------------------------------------")

            run_cmd = self.apply_openflow_command.format (target_bridge, flow_file_path)
            try:
                logger.info ("Running: " + run_cmd)
                status_code = call (run_cmd.split ())
                logger.info (f"Flow application command returned status code {status_code}")
            except Exception as e:
                logger.warning (f"ERROR: Flow application command failed: {e}")
