import re, logging, tempfile, netifaces, asyncio


from pathlib import Path
from .utils import blank_line_re, comment_line_re, get_ipv4_hostports_for_hostportspec, parse_portspec, parse_hostportspec
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

    start_table = 0
    input_from_micronets_table = 100
    output_to_localhost_table = 120
    input_from_localhost_table = 200
    filter_to_micronets_table = 210
    output_to_device_table = 220

    drop_action = "output:42"

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
        cur_interface_port_req = 0
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
                cur_interface_port_req = 0
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
                cur_interface_port_req = port

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
        ovs_micronet_ports = []
        for interface in self.ovs_micronet_interfaces:
            ovs_micronet_ports.append(self.port_for_interface[interface])

        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_uplink_port: {self.ovs_uplink_interface}")
        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_micronet_interfaces: {self.ovs_micronet_interfaces}")
        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_micronet_ports: {ovs_micronet_ports}")

    async def create_flows_for_rules(self, in_port, device_mac, device, micronet, outfile):
        in_rules = device.get('inRules', None)
        out_rules = device.get('outRules', None)

        if not out_rules:
            # Allow all data out if no out rules
            # add table=100, priority=400, in_port=202,dl_src=b8:27:eb:6e:3a:6f, actions=resubmit(,120)
            outfile.write(f" # Device {device['deviceId']} (mac {device_mac}) is not out-restricted\n")
            outfile.write(f"add table={self.input_from_micronets_table},priority=400, "
                            f"in_port={in_port},dl_src={device_mac} "
                            f"actions=resubmit(,{self.output_to_localhost_table})\n\n")
        else:
            outfile.write(f" # Device {device['deviceId']} (mac {device_mac}) is out-restricted\n")
            for rule in out_rules:
                try:
                    logger.info(f"OpenFlowAdapter.create_flows_for_rules: processing out-rule: {rule}")
                    rule_dest = rule.get('dest', None)
                    rule_dest_port = rule.get('destPort', None)
                    rule_action = rule['action']
                    if rule_dest:
                        dest_list = await get_ipv4_hostports_for_hostportspec(rule_dest)
                        for dest in dest_list:
                            logger.info(f"OpenFlowAdapter.create_flows_for_rules:   dest: {dest}")
                            dest_fields = parse_hostportspec(dest)
                            logger.info(f"OpenFlowAdapter.create_flows_for_rules:   dest_fields: {dest_fields}")

                except Exception as ex:
                    logger.warning(f"OpenFlowAdapter.create_flows_for_rules: Error processing rule {rule}: {ex}")

        if not in_rules:
            outfile.write(f" # Device {device['deviceId']} (mac {device_mac}) has no in-rules\n")
            # add table=210,priority=300, dl_dst=b8:27:eb:79:78:28,tcp,tcp_dst=22, actions=resubmit(,220)
        else:
            outfile.write(f" # Device {device['deviceId']} (mac {device_mac}) has in-rules\n")
            for rule in in_rules:
                logger.info(f"OpenFlowAdapter.create_flows_for_rules: processing in-rule: {rule}")

    async def update (self, micronet_list, device_lists):
        logger.info (f"OpenFlowAdapter.update ()")
        logger.info (f"OpenFlowAdapter.update: device_lists: {device_lists}")

        # Note: These flows are a work-in-progress

        disabled_interfaces = self.ovs_micronet_interfaces.copy ()
        logger.info (f"OpenFlowAdapter.update: configured interfaces: {disabled_interfaces}")

        with tempfile.NamedTemporaryFile (mode='wt') as flow_file:
            flow_file_path = Path (flow_file.name)
            logger.info(f"opened temporary file {flow_file_path}")

            flow_file.write ("del\n") # This will clear all flows

            # CLASSIFIER boilerplate rules
            flow_file.write(f"add table={self.start_table},priority=500, dl_dst=01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0, "
                            f"actions=drop\n")
            flow_file.write(f"add table={self.start_table},priority=500, dl_src=01:00:00:00:00:00/01:00:00:00:00:00, "
                            f"actions=drop\n")
              # Drop all ICMP redirects (localhost will send these for wlan adapters - when not disabled)
            flow_file.write(f"add table={self.start_table},priority=500, icmp,icmp_code=1, "
                            f"actions=drop\n\n")
            flow_file.write(f"add table={self.start_table},priority=450, "
                            f"in_port=LOCAL, "
                            f"actions=resubmit(,{self.input_from_localhost_table})\n\n")
            flow_file.write(f"add table={self.start_table},priority=0, "
                            f"actions={self.drop_action}\n")

            # INPUT-FROM-MICRONET boilerplate rules
            flow_file.write(f"add table={self.input_from_micronets_table},priority=450, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={self.input_from_micronets_table})\n")
            flow_file.write(f"add table={self.input_from_micronets_table},priority=450, "
                            f"udp,ct_state=+trk+est, "
                            f"actions=output:LOCAL\n")
            flow_file.write(f"add table={self.input_from_micronets_table},priority=450, "
                            f"udp,ct_state=+trk+rel, "
                            f"actions=output:LOCAL\n\n")
            flow_file.write(f"add table={self.input_from_micronets_table},priority=440, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={self.input_from_micronets_table})\n")
            flow_file.write(f"add table={self.input_from_micronets_table},priority=440, "
                            f"tcp,ct_state=+trk+est, "
                            f"actions=output:LOCAL\n")
            flow_file.write(f"add table={self.input_from_micronets_table},priority=440, "
                            f"tcp,ct_state=+trk+rel, "
                            f"actions=output:LOCAL\n")
            flow_file.write(f"add table={self.input_from_micronets_table},priority=430, "
                            f"dl_type=0x888e, "
                            f"actions=resubmit(,{self.output_to_localhost_table})\n")
              # Device outRules go here
            flow_file.write(f"add table={self.input_from_micronets_table},priority=0, "
                            f"actions={self.drop_action}\n")

            # OUTPUT-TO-LOCALHOST boilerplate rules
            flow_file.write(f"add table={self.output_to_localhost_table},priority=400, "
                            f"tcp,udp,ct_state=-trk, "
                            f"actions=ct(table={self.output_to_localhost_table})\n")
            flow_file.write(f"add table={self.output_to_localhost_table},priority=400, "
                            f"tcp,udp,ct_state=+trk+new, "
                            f"actions=ct(commit),output:LOCAL\n")
            flow_file.write(f"add table={self.output_to_localhost_table},priority=0, "
                            f"actions=output:LOCAL\n")

            # INCOMING-FROM-LOCALHOST boilerplate rules
              # mac-to-micronet-port mappings go here
            flow_file.write(f"add table={self.input_from_localhost_table},priority=0, "
                            f"actions={self.drop_action}\n")

            # FILTER-TO-MICRONETS boilerplate rules
              # Tracked connection passthrough
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=450, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={self.input_from_localhost_table})\n")
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=450, "
                            f"udp,ct_state=+trk+est, "
                            f"actions=output:reg1\n")
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=450, "
                            f"udp,ct_state=+trk+rel, "
                            f"actions=output:reg1\n\n")
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=440, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={self.input_from_localhost_table})\n")
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=440, "
                            f"tcp,ct_state=+trk+est, "
                            f"actions=output:reg1\n")
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=440, "
                            f"tcp,ct_state=+trk+rel, "
                            f"actions=output:reg1\n")
              # Low-level protocol pass-through (ARP, ICMP, EAPoL, DNS, NTP...)
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=300, "
                            f"arp, "
                            f"actions=ct(table={self.output_to_device_table})\n")
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=300, "
                            f"icmp, "
                            f"actions=ct(table={self.output_to_device_table})\n")
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=300, "
                            f"dl_type=0x888e, "
                            f"actions=ct(table={self.output_to_device_table})\n")
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=300, "
                            f"udp,tp_dst=68, "
                            f"actions=ct(table={self.output_to_device_table})\n")
              # Device inRules go here
            flow_file.write(f"add table={self.filter_to_micronets_table},priority=0, "
                            f"actions=resubmit(,{self.output_to_device_table})\n")

            # OUTPUT-TO-DEVICE boilerplate rules
            flow_file.write(f"add table={self.output_to_device_table},priority=400, "
                            f"tcp,udp,ct_state=-trk, "
                            f"actions=ct(table={self.output_to_device_table})\n")
            flow_file.write(f"add table={self.output_to_device_table},priority=400, "
                            f"tcp,udp,ct_state=+trk+new, "
                            f"actions=ct(commit),output:reg1\n")
            flow_file.write(f"add table={self.output_to_device_table},priority=0, "
                            f"actions=output:reg1\n")

            for interface in self.ovs_micronet_interfaces:
                micronet_port = self.port_for_interface[interface]
                flow_file.write(f"add table={self.start_table},priority=400, in_port={micronet_port}, "
                                f"actions=resubmit(,{self.input_from_micronets_table})\n")

            # Walk the micronets
            for micronet_id, micronet in micronet_list.items ():
                micronet_int = micronet ['interface']
                micronet_bridge = micronet ['ovsBridge']
                micronet_network = micronet ['ipv4Network']['network']
                logger.info (f"Creating flow rules for micronet {micronet_id} (interface {micronet_int})")
                if micronet_bridge != self.bridge_name:
                    raise Exception(f"micronet {micronet_id} has an unexpected bridge name ('{micronet_bridge}')"
                                    f" - expected {self.bridge_name}")

                if micronet_int not in self.ovs_micronet_interfaces:
                    raise Exception (f"interface {micronet_int} in micronet {micronet_id} not found "
                                     f"in configured micronet interfaces ({self.ovs_micronet_interfaces})")
                disabled_interfaces.remove (micronet_int)
                flow_file.write (f"  # Rules for micronet {micronet_id}"
                                 f" (interface {micronet_int}, micronet {micronet_network})\n")
                micronet_vlan = micronet.get('vlan', None)
                if micronet_vlan:
                    # The gateway will always have port numbers == vlan IDs
                    flow_file.write(f"add table={self.start_table},priority=400, "
                                    f"in_port={micronet_vlan}, "
                                    f"actions=resubmit(,{self.input_from_micronets_table})\n")

                # Walk the devices in the interface and create rules
                for device_id, device in device_lists [micronet_id].items ():
                    device_mac = device['macAddress']['eui48']
                    device_port = micronet_vlan if micronet_vlan else self.port_for_interface[micronet_int]
                    flow_file.write(f"add table={self.input_from_localhost_table},priority=200, "
                                    f"dl_dst={device_mac}, "
                                    f"actions=load:{device_port}->NXM_NX_REG1[],resubmit(,{self.filter_to_micronets_table})\n")
                    logger.info(
                        f"Creating flow rules for device {device_id} in micronet {micronet_id} (interface {micronet_int})")
                    await self.create_flows_for_rules(device_port, device_mac, device, micronet, flow_file)

            flow_file.flush ()

            with flow_file_path.open('r') as infile:
                infile.line_no = 0
                logger.info ("Issuing new flows:")
                logger.info ("------------------------------------------------------------------------")
                for line in infile:
                    logger.info (line[0:-1])
                logger.info ("------------------------------------------------------------------------")

            run_cmd = self.apply_openflow_command.format (**{"ovs_bridge": self.bridge_name,
                                                             "flow_file": flow_file_path})
            try:
                logger.info ("Running: " + run_cmd)
                status_code = call (run_cmd.split ())
                logger.info (f"Flow application command returned status code {status_code}")
            except Exception as e:
                logger.warning (f"ERROR: Flow application command failed: {e}")
