import re, logging, tempfile, netifaces

from pathlib import Path
from .utils import blank_line_re, comment_line_re, unroll_hostportspec_list
from subprocess import call

logger = logging.getLogger ('micronets-gw-service')

class OpenFlowAdapter:
    # iface brmn001 inet dhcp
    #   ovs_type OVSBridge
    #   ovs_ports enp3s0 enxac7f3ee61832 enx00e04c534458
    #   ovs_bridge_uplink_port enp3s0
    interfaces_iface_header_re = re.compile ('^iface\s+(\w+)\s.*$')
    interfaces_ovs_type_re = re.compile ('^\s*ovs_type\s+(\w+)\s*$')
    interfaces_ovs_bridge_uplink_re = re.compile ('^\s*ovs_bridge_uplink_port\s+(\w+)\s*$')
    interfaces_ovs_ports_re = re.compile ('\s*ovs_ports\s+([\w ]+)\s*$')
    interfaces_ovs_ports_req_re = re.compile ('\s*ovs_port_req\s+([\w ]+)\s*$')

    interface_for_port = {}
    port_for_interface = {}
    mac_for_interface = {}
    address_for_interface = {}
    ovs_micronet_interfaces = None
    ovs_uplink_interface = None

    def __init__ (self, config):
        self.interfaces_file_path = Path (config ['FLOW_ADAPTER_NETWORK_INTERFACES_PATH'])
        self.apply_openflow_command = config['FLOW_ADAPTER_APPLY_FLOWS_COMMAND']

        self.get_interface_info()
        with self.interfaces_file_path.open ('r') as infile:
            try:
                infile.line_no = 0
                logger.info (f"OpenFlowAdapter: Loading bridge port {self.interfaces_file_path.absolute ()}")
                self.read_interfaces_file (infile)
            except Exception as e:
                raise Exception ("OpenFlowAdapter: Error on line {} of {}: {}"
                                 .format (infile.line_no, self.interfaces_file_path.absolute (), e))

    def get_interface_info (self):
        self.mac_for_interface = {}
        self.ip_for_interface = {}

        for iface in netifaces.interfaces():
            logger.info(f"OpenFlowAdapter: Found interface {iface}")
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0]['addr']
                logger.info(f"OpenFlowAdapter:   MAC: {mac}")
                self.mac_for_interface[iface] = mac
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]['addr']
                logger.info(f"OpenFlowAdapter:   IP: {ip}")
                self.ip_for_interface[iface] = ip

    def read_interfaces_file (self, infile):
        cur_interface_block = None
        cur_interface_ovs_type = None
        for line in infile:
            infile.line_no += 1
            if (blank_line_re.match (line)):
                continue
            if (comment_line_re.match (line)):
                continue

            interfaces_iface_header_match = self.interfaces_iface_header_re.match(line)
            if interfaces_iface_header_match:
                cur_interface_block = interfaces_iface_header_match.group(1)
                cur_interface_ovs_type = None
                continue

            interfaces_ovs_type_match = self.interfaces_ovs_type_re.match(line)
            if interfaces_ovs_type_match:
                if not cur_interface_block:
                    raise Exception(f"Found ovs_type line outside of interface block")
                cur_interface_ovs_type = interfaces_ovs_type_match.group(1)
                if cur_interface_ovs_type == "OVSBridge":
                    self.bridge_name = cur_interface_block
                    logger.info(f"Found OVS Bridge {self.bridge_name}")

            interfaces_ovs_ports_req_match = self.interfaces_ovs_ports_req_re.match (line)
            if interfaces_ovs_ports_req_match:
                if not cur_interface_block:
                    raise Exception(f"Found ovs_port_req line outside of interface block")
                port = int(interfaces_ovs_ports_req_match.group(1))
                logger.info(f"Found OVS Port {port} for interface {cur_interface_block}")
                self.interface_for_port[port] = cur_interface_block
                self.port_for_interface[cur_interface_block] = port

            interfaces_ovs_ports_match = self.interfaces_ovs_ports_re.match (line)
            if interfaces_ovs_ports_match:
                if not cur_interface_block:
                    raise Exception(f"Found ovs_ports line outside of interface block")
                self.ovs_micronet_interfaces = interfaces_ovs_ports_match.group (1).split ()
                continue

            interfaces_uplink_port = self.interfaces_ovs_bridge_uplink_re.match (line)
            if interfaces_uplink_port:
                if not cur_interface_block:
                    raise Exception(f"Found ovs_bridge_uplink line outside of interface block")
                self.ovs_uplink_interface = interfaces_uplink_port.group (1)
                logger.info(f"Found OVS Uplink Port {self.ovs_uplink_interface} for bridge {cur_interface_block}")
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

    async def update (self, micronet_list, device_lists):
        logger.info (f"OpenFlowAdapter.update ()")
        logger.info (f"OpenFlowAdapter.update: device_lists: {device_lists}")

        # Note: These flows are a work-in-progress

        disabled_interfaces = self.ovs_micronet_interfaces.copy ()
        logger.info (f"OpenFlowAdapter.update: configured interfaces: {disabled_interfaces}")

        with tempfile.NamedTemporaryFile (mode='wt') as flow_file:
            flow_file_path = Path (flow_file.name)
            logger.info(f"created temporary file {flow_file_path}")
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

            # Walk the micronets
            for micronet_id, micronet in micronet_list.items ():
                micronet_int = micronet ['interface']
                micronet_bridge = micronet ['ovsBridge']
                micronet_network = micronet ['ipv4Network']['network']
                cur_micronet_table = cur_table
                cur_table += 1
                logger.info (f"Creating flow rules for micronet {micronet_id} (interface {micronet_int})")
                if micronet_bridge != self.bridge_name:
                    raise Exception(f"micronet {micronet_id} has an unexpected bridge name ('{micronet_bridge}')"
                                    f" - expected {self.bridge_name}")

                if micronet_int not in self.ovs_micronet_interfaces:
                    raise Exception (f"interface {micronet_int} in micronet {micronet_id} not found "
                                     f"in configured micronet interfaces ({self.ovs_micronet_interfaces})")
                disabled_interfaces.remove (micronet_int)
                micronet_port = self.port_for_interface [micronet_int]
                flow_file.write (f"add table={start_table},priority=10,in_port={micronet_port} "
                                 f"actions=resubmit(,{cur_micronet_table})\n")
                # Walk the devices in the interface and create appropriate device filter tables
                flow_file.write (f"  # TABLE {cur_micronet_table}: micronet {micronet_id}"
                                 f" (interface {micronet_int}, micronet {micronet_network})\n")
                for device_id, device in device_lists [micronet_id].items ():
                    device_mac = device ['macAddress']['eui48']
                    if 'allowHosts' in device:
                        hosts = device['allowHosts']
                        hostport_spec_list = await unroll_hostportspec_list (hosts)
                        host_action = "NORMAL"
                        default_host_action = "drop"
                    elif 'denyHosts' in device:
                        hosts = device ['denyHosts']
                        hostport_spec_list = await unroll_hostportspec_list (hosts)
                        host_action = "drop"
                        default_host_action = "NORMAL"

                    if not hostport_spec_list:
                        flow_file.write (f"  add table={cur_micronet_table},priority=20,dl_src={device_mac} "
                                         f"actions=resubmit(,{unrestricted_device_table})\n")
                    else:
                        cur_dev_table = cur_table
                        cur_table += 1
                        flow_file.write (f"  add table={cur_micronet_table},priority=20,dl_src={device_mac} "
                                         f"actions=resubmit(,{cur_dev_table})\n")
                        if default_host_action == "drop":
                            # Add rule to allow EAPoL packets
                            flow_file.write(f"    # Adding rule to allow EAPoL traffic\n")
                            flow_file.write(f"    add table={cur_dev_table},priority=20,dl_type=0x888e "
                                            f"actions=NORMAL\n")
                            hostport_spec_list.append(micronet['ipv4Network']['gateway'])
                            if 'nameservers' in micronet:
                                hostport_spec_list += micronet['nameservers']
                            if 'nameservers' in device:
                                hostport_spec_list += device['nameservers']
                        flow_file.write (f"    # TABLE {cur_dev_table}: hosts allowed/denied for device {device_id} (MAC {device_mac})\n")
                        flow_file.write (f"    add table={cur_dev_table},priority=20,udp,tp_dst=67 "
                                         f"actions=LOCAL\n")
                        flow_file.write (f"    add table={cur_dev_table},priority=20,arp "
                                         f"actions=NORMAL\n")
                        flow_file.write (f"    #   hosts: {hosts}\n")
                        for hostport_spec in hostport_spec_list:
                            # hostport_spec examples: 1.2.3.4, 3.4.5.6/32:22, 1.2.3.4/32:80/tcp,443/tcp,7,39/udp
                            hostport_split = hostport_spec.split(':')
                            hostspec = hostport_split[0]
                            hp_filter_template = f"    add table={cur_dev_table},priority=10,{'{}'},ip_dst={hostspec}{'{}'} " \
                                                 f"actions={host_action}\n"

                            if len(hostport_split) == 1:
                                # Need to create an ip-only filter
                                flow_file.write(hp_filter_template.format("ip", ""))
                            else:
                                # Need to create a ip+port filter(s)
                                portspec = hostport_split[1]
                                portspec_split = portspec.split('/')
                                if len(portspec_split) == 1:
                                    # No protocol designation - block udp and tcp for the port number
                                    flow_file.write(hp_filter_template.format("tcp", f",tcp_dst={portspec}"))
                                    flow_file.write(hp_filter_template.format("udp", f",udp_dst={portspec}"))
                                if len(portspec_split) > 1:
                                    # Only block the port for the designated protocol
                                    protocol = portspec_split[1]
                                    flow_file.write(hp_filter_template.format(protocol, f",{protocol}_dst={portspec}"))
                            # Write the default rule for the device
                        flow_file.write (f"    add table={cur_dev_table},priority=5 "
                                         f"actions={default_host_action}\n")
                # Create the micronet flow entry for non-matching devices
                flow_file.write(f"  add table={cur_micronet_table},priority=5 "
                                f"actions=drop\n")

            for interface in disabled_interfaces:
                logger.info (f"Disabling flow for interface {interface}")
                if interface not in self.port_for_interface:
                    raise Exception(f"interface {interface} referenced in {self.interfaces_file_path} is not "
                                    f"configured on bridge {target_bridge}")
                micronet_port = self.port_for_interface [interface]
                flow_file.write (f"add table={start_table},priority=10,in_port={micronet_port} "
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
                             f"actions=NORMAL\n")
            flow_file.flush ()

            with flow_file_path.open('r') as infile:
                infile.line_no = 0
                logger.info ("Issuing new flows:")
                logger.info ("------------------------------------------------------------------------")
                for line in infile:
                    logger.info (line[0:-1])
                logger.info ("------------------------------------------------------------------------")

            run_cmd = self.apply_openflow_command.format (self.bridge_name, flow_file_path)
            try:
                logger.info ("Running: " + run_cmd)
                status_code = call (run_cmd.split ())
                logger.info (f"Flow application command returned status code {status_code}")
            except Exception as e:
                logger.warning (f"ERROR: Flow application command failed: {e}")
