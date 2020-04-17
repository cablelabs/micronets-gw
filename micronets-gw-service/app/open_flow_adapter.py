import re, logging, tempfile, netifaces, asyncio

from pathlib import Path
from .utils import blank_line_re, comment_line_re, get_ipv4_hostports_for_hostportspec, parse_portspec, \
                   parse_hostportspec, unroll_hostportspec_list, mac_addr_re, parse_macportspec

from subprocess import check_output, STDOUT
from .hostapd_adapter import HostapdAdapter

logger = logging.getLogger ('micronets-gw-service')


class OpenFlowAdapter(HostapdAdapter.HostapdCLIEventHandler):
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
    from_micronets_table = 100
    block_to_micronets_table = 110
    to_localhost_table = 120
    from_localhost_table = 200
    to_micronets_table = 210
    to_device_table = 220

    diagnostic_port = 42

    drop_action = f"output:{diagnostic_port}"

    def __init__ (self, config):
        self.interfaces_file_path = Path (config ['FLOW_ADAPTER_NETWORK_INTERFACES_PATH'])
        self.apply_openflow_command = config['FLOW_ADAPTER_APPLY_FLOWS_COMMAND']
        HostapdAdapter.HostapdCLIEventHandler.__init__(self, None)
        self.bss = {}

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

            interfaces_iface_header_match = OpenFlowAdapter.interfaces_iface_header_re.match(line)
            if interfaces_iface_header_match:
                cur_interface_block = interfaces_iface_header_match.group(1)
                cur_interface_ovs_type = None
                cur_interface_port_req = 0
                continue

            interfaces_ovs_type_match = OpenFlowAdapter.interfaces_ovs_type_re.match(line)
            if interfaces_ovs_type_match:
                if not cur_interface_block:
                    raise Exception(f"Found ovs_type line outside of interface block")
                cur_interface_ovs_type = interfaces_ovs_type_match.group(1)
                if cur_interface_ovs_type == "OVSBridge":
                    self.bridge_name = cur_interface_block
                    logger.info(f"Found OVS Bridge {self.bridge_name}")

            interfaces_ovs_ports_req_match = OpenFlowAdapter.interfaces_ovs_ports_req_re.match (line)
            if interfaces_ovs_ports_req_match:
                if not cur_interface_block:
                    raise Exception(f"Found ovs_port_req line outside of interface block")
                port = int(interfaces_ovs_ports_req_match.group(1))
                logger.info(f"Found OVS Port {port} for interface {cur_interface_block}")
                self.interface_for_port[port] = cur_interface_block
                self.port_for_interface[cur_interface_block] = port
                cur_interface_port_req = port

            interfaces_ovs_ports_match = OpenFlowAdapter.interfaces_ovs_ports_re.match (line)
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

        logger.info (f"OpenFlowAdapter.read_interfaces_file: Done reading {infile}")
        if not self.ovs_micronet_interfaces:
            raise Exception (f"Did not find a ovs_ports entry in {infile}")
        if not self.ovs_uplink_interface:
            raise Exception (f"Did not find a ovs_bridge_uplink_port entry in {infile}")
        if self.ovs_uplink_interface in self.ovs_micronet_interfaces:
            self.ovs_micronet_interfaces.remove (self.ovs_uplink_interface)
        ovs_micronet_ports = []
        for interface in self.ovs_micronet_interfaces:
            ovs_micronet_ports.append(self.port_for_interface[interface])

        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_uplink_port: {self.ovs_uplink_interface}")
        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_micronet_interfaces: {self.ovs_micronet_interfaces}")
        logger.info (f"OpenFlowAdapter.read_interfaces_file: ovs_micronet_ports: {ovs_micronet_ports}")

    async def handle_hostapd_ready(self):
        logger.info(f"OpenFlowAdapter.handle_hostapd_ready()")
        self.bss = self.hostapd_adapter.get_status_var('bss')
        logger.info(f"OpenFlowAdapter.handle_hostapd_ready:   BSS: {self.bss}")


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

            #
            # CLASSIFIER boilerplate rules (in priority order)
            #
            flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=500, dl_dst=01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0, "
                            f"actions=drop\n")
            flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=500, dl_src=01:00:00:00:00:00/01:00:00:00:00:00, "
                            f"actions=drop\n")
            # Drop all ICMP redirects (localhost will send these for wlan adapters - when not disabled)
            # Forwarding ICMP redirects will allow hosts to discover and use each other's MAC over the
            #   OVS bridge. (this should be remedied in hostapd)
            flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=500, icmp,icmp_code=1, "
                            f"actions=drop\n\n")
            flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=450, "
                            f"in_port=LOCAL, "
                            f"actions=resubmit(,{OpenFlowAdapter.from_localhost_table})\n")
            # We'll add in_port entries to this table for each active micronet here

            # Drop anything that doesn't come from a port we recognize
            flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=0, "
                            f"actions={OpenFlowAdapter.drop_action}\n")

            #
            # FROM-MICRONETS boilerplate rules
            #

            # Allow already-tracked connections through
            #  UDP
            priority=910
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={priority}, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.from_micronets_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={priority}, "
                            f"udp,ct_state=+trk+est, "
                            f"actions=output:LOCAL\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={priority}, "
                            f"udp,ct_state=+trk+rel, "
                            f"actions=output:LOCAL\n\n")
            #  TCP
            priority=905
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={priority}, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.from_micronets_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={priority}, "
                            f"tcp,ct_state=+trk+est, "
                            f"actions=output:LOCAL\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={priority}, "
                            f"tcp,ct_state=+trk+rel, "
                            f"actions=output:LOCAL\n\n")

            priority=900
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={priority}, "
                            f"dl_type=0x888e, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")

            # Device and Micronet outRules go here (priority 400)

            # Drop everything that isn't redirected by a rule above
            priority=0
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={priority}, "
                            f"actions={OpenFlowAdapter.drop_action}\n")

            #
            # Block TO-MICRONET traffic
            #
            # All packets that haven't been given express permission to go to another micronet go through here
            # The micronet-specific entries will be filled in when we walk the micronets below
            priority=0
            flow_file.write(f"add table={OpenFlowAdapter.block_to_micronets_table},priority={priority}, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")

            #
            # TO-LOCALHOST boilerplate rules
            #
            # All packets that have been "approved" for local delivery go through here
            priority=400
            flow_file.write(f"add table={OpenFlowAdapter.to_localhost_table},priority={priority}, "
                            f"tcp,udp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_localhost_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_localhost_table},priority={priority}, "
                            f"tcp,udp,ct_state=+trk+new, "
                            f"actions=ct(commit),output:LOCAL\n")
            priority=0
            flow_file.write(f"add table={OpenFlowAdapter.to_localhost_table},priority={priority}, "
                            f"actions=output:LOCAL\n")

            #
            # FROM-LOCALHOST boilerplate rules
            #

            #  mac-to-micronet-port mappings go here
            priority=0
            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_table},priority={priority}, "
                            f"actions={OpenFlowAdapter.drop_action}\n")

            #
            # TO-MICRONETS boilerplate rules
            #

            # Tracked connection passthrough
            #  UDP
            priority=950
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_micronets_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"udp,ct_state=+trk+est, "
                            f"actions=output:reg1\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"udp,ct_state=+trk+rel, "
                            f"actions=output:reg1\n\n")
            #  TCP
            priority=940
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_micronets_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"tcp,ct_state=+trk+est, "
                            f"actions=output:reg1\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"tcp,ct_state=+trk+rel, "
                            f"actions=output:reg1\n\n")

            # Allow certain low-level protocols through (ARP, ICMP, EAPoL, DNS, NTP...)
            priority=900
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"arp, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"icmp, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"dl_type=0x888e, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"udp,tp_dst=68, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"udp,tp_dst=53, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"udp,tp_dst=123, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")

            # Device inRules go here

            # Allow packets that aren't expressly denied through
            priority=0
            flow_file.write(f"add table={OpenFlowAdapter.to_micronets_table},priority={priority}, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")

            #
            # TO-DEVICE boilerplate rules
            #

            # All packets approved for delivery to a micronet device go through here
            #  UDP
            priority=400
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority={priority}, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority={priority}, "
                            f"udp,ct_state=+trk+new, "
                            f"actions=ct(commit),output:reg1\n")
            #  TCP
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority={priority}, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority={priority}, "
                            f"tcp,ct_state=+trk+new, "
                            f"actions=ct(commit),output:reg1\n")
            priority=0
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority={priority}, "
                            f"actions=output:reg1\n")

            # Walk the micronets and generate the micronet-specific rules
            for micronet_id, micronet in micronet_list.items ():
                micronet_int = micronet ['interface']
                micronet_network = micronet ['ipv4Network']['network']
                micronet_mask = micronet ['ipv4Network']['mask']
                logger.info (f"Creating flow rules for micronet {micronet_id} (interface {micronet_int})")

                if micronet_int not in self.ovs_micronet_interfaces:
                    raise Exception (f"interface {micronet_int} in micronet {micronet_id} not found "
                                     f"in configured micronet interfaces ({self.ovs_micronet_interfaces})")
                if micronet_int in disabled_interfaces:
                    disabled_interfaces.remove (micronet_int)
                micronet_vlan = micronet.get('vlan', None)
                micronet_port = self.port_for_interface.get(micronet_int, None)
                if not micronet_port:
                    raise Exception(f"Cannot find an ovs port designation for micronet {micronet_id} interface {micronet_int}. "
                                    f"Check the OVSPort entries in the gateway /etc/network/interfaces file")
                # Allow EAPoL traffic to host from wifi port
                if micronet_int in self.bss.values():
                    # For wlan links, EAPoL packets need to be routed to hostapd to allow authentication
                    flow_file.write(f"add table={OpenFlowAdapter.from_micronets_table},priority=460, "
                                    f"in_port={micronet_port},dl_type=0x888e, "
                                    f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")
                if micronet_vlan:
                    # The gateway sets up the ovs port numbers to match the vlan IDs (e.g. vlan 101 -> port 101)
                    flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=400, in_port={micronet_vlan}, "
                                    f"actions=resubmit(,{OpenFlowAdapter.from_micronets_table})\n")
                    port_for_micronet_devices = micronet_vlan
                else:
                    port_for_micronet_devices = micronet_port

                # Add rules to start table for handling traffic coming from Micronets
                flow_file.write (f"  # table={OpenFlowAdapter.start_table},priority=500: Micronet {micronet_id}"
                                 f" (interface {micronet_int}, micronet {micronet_network}/{micronet_mask})\n")
                # Handle traffic coming from Micronets for possible egress
                flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=400, in_port={micronet_port}, "
                                f"actions=resubmit(,{OpenFlowAdapter.from_micronets_table})\n")

                # Add the block rule to prevent micronet-to-micronet traffic without explicit rules
                flow_file.write(f"add table={OpenFlowAdapter.block_to_micronets_table},priority=400, "
                                f"ip,ip_dst={micronet_network}/{micronet_mask}, actions={OpenFlowAdapter.drop_action}\n")

                # Walk the devices in the micronet and create rules
                for device_id, device in device_lists [micronet_id].items ():
                    device_mac = device['macAddress']['eui48']
                    device_id = device['deviceId']
                    device_ip = device['networkAddress']
                    flow_file.write(f"add table={OpenFlowAdapter.from_localhost_table},priority=200, "
                                    f"dl_dst={device_mac}, actions=load:{port_for_micronet_devices}->NXM_NX_REG1[], "
                                                                 f"resubmit(,{OpenFlowAdapter.to_micronets_table})\n")
                    flow_file.write(f"  # table={OpenFlowAdapter.from_localhost_table},priority=200 "
                                    f"Device: {device_id} (MAC {device_mac}, IP address {device_ip})\n")
                    logger.info(
                        f"Creating flow rules for device {device_id} in micronet {micronet_id} (interface {micronet_int})")
                    await self.create_flows_for_device(port_for_micronet_devices, device_mac, device, micronet, flow_file)

            flow_file.flush ()

            with flow_file_path.open('r') as infile:
                infile.line_no = 1
                logger.info ("Issuing new flows:")
                logger.info ("------------------------------------------------------------------------")
                for line in infile:
                    logger.info ("{0:4}: ".format(infile.line_no) + line[0:-1])
                    infile.line_no += 1
                logger.info ("------------------------------------------------------------------------")

            run_cmd = self.apply_openflow_command.format (**{"ovs_bridge": self.bridge_name,
                                                             "flow_file": flow_file_path})
            try:
                logger.info ("Applying flows using: " + run_cmd)
                check_output (run_cmd.split(), stderr=STDOUT)
                logger.info(f"SUCCESSFULLY APPLIED FLOWS")
            except Exception as e:
                logger.warning(f"ERROR APPLYING FLOWS: {e}")

    async def create_flows_for_device(self, in_port, device_mac, device, micronet, outfile):
        try:
            await self.create_allowdenyhosts_rules_for_device(in_port, device_mac, device, micronet, outfile)
            await self.create_out_rules_for_device(in_port, device_mac, device, micronet, outfile)
            await self.create_in_rules_for_device(in_port, device_mac, device, micronet, outfile)
        except Exception as ex:
            logger.warning(f"OpenFlowAdapter.create_flows_for_device: Caught exception {ex}", exc_info=True)

    def flow_fields_for_ip_host(self, direction, ip_addr, port, protocol):
        if not (direction == "src" or direction == "dst"):
            raise Exception(f"flow_fields_for_ip_host direction is {direction} (must be 'src' or 'dst')")
        if not protocol:
            if ip_addr or port:
                protocol = "ip,"
        else:
            protocol = protocol + ","
        ip_rule = f"ip_{direction}={ip_addr}," if ip_addr else ""
        port_rule = f"tcp_{direction}={port}," if port else ""
        combined_rule = protocol + ip_rule + port_rule
        return combined_rule

    def flow_fields_for_mac_host(self, direction, mac_addr, port, protocol):
        if not (direction == "src" or direction == "dst"):
            raise Exception(f"flow_fields_for_ip_host direction is {direction} (must be 'src' or 'dst')")
        if not protocol:
            if port:
                protocol = "ip,"
            else:
                protocol = ""
        else:
            protocol = protocol + ","
        eth_rule = f"eth_{direction}={mac_addr}," if mac_addr else ""
        port_rule = f"tcp_{direction}={port}," if port else ""
        combined_rule = protocol + eth_rule + port_rule
        return combined_rule

    async def create_out_rules_for_device(self, in_port, device_mac, device, micronet, outfile):
        cur_priority = 850
        device_id = device['deviceId']
        micronet_gateway = micronet['ipv4Network']['gateway']
        outfile.write(f"  # table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}: "
                      f"Out-Rules for Device {device['deviceId']} (mac {device_mac})\n")
        # Always allow a micronet device to talk to the gateway (need to avoid the micronet-to-micronet filters)
        outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                      f"in_port={in_port},dl_src={device_mac},ip,ip_dst={micronet_gateway}, "
                      f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n\n")
        cur_priority = 800

        out_rules = device.get('outRules', None)
        if not out_rules:
            # Allow all data out if no out rules
            outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                          f"in_port={in_port},dl_src={device_mac}, "
                          f"actions=resubmit(,{OpenFlowAdapter.block_to_micronets_table})\n\n")
        else:
            allow_action = f"resubmit(,{OpenFlowAdapter.to_localhost_table})"
            deny_action = OpenFlowAdapter.drop_action

            # Allow these through regardless of ACLs
            for pass_filter in ["arp", "dl_type=0x888e", "udp,tp_dst=67", "udp,tp_dst=53", "udp,tp_dst=123"]:
                outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                              f"in_port={in_port},dl_src={device_mac},{pass_filter}, "
                              f"actions={allow_action}\n")
            cur_priority -= 1
            for rule in out_rules:
                try:
                    logger.info(f"OpenFlowAdapter.create_out_rules_for_device: processing {device_id} out-rule: {rule}")
                    if 'sourceIp' in rule:
                        raise Exception("'sourceIp' is not supported in 'outRules' (rule {rule})")
                    rule_dest_ip = rule.get('destIp', None)
                    rule_dest_mac = rule.get('destMac', None)
                    rule_dest_port = rule.get('destPort', None)
                    rule_action = rule['action']
                    logger.info(f"OpenFlowAdapter.create_out_rules_for_device:   action: {rule_action}")
                    action = allow_action if rule_action == "allow" else deny_action
                    if rule_dest_port:
                        destport_list = rule_dest_port.split(",")
                        for destport_spec in destport_list:
                            logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     destPort: {destport_spec}")
                            destport_spec_fields = parse_portspec(destport_spec)
                            logger.info(
                                f"OpenFlowAdapter.create_out_rules_for_device:     destPort fields: {destport_spec_fields}")
                            (port, protocol) = destport_spec_fields.values()
                            field_rules =  self.flow_fields_for_ip_host("dst", None, port, protocol)
                            flowrule = f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, " \
                                       f"in_port={in_port},dl_src={device_mac},{field_rules} actions={action}"
                            logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     flowrule: {flowrule}")
                            outfile.writelines((flowrule, "\n"))
                    elif rule_dest_ip:
                        dest_list = await get_ipv4_hostports_for_hostportspec(rule_dest_ip)
                        for dest_spec in dest_list:
                            logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     dest ip: {dest_spec}")
                            dest_fields = parse_hostportspec(dest_spec)
                            logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     dest_fields: {dest_fields}")
                            (ip_addr, port, protocol) = dest_fields.values()
                            field_rules = self.flow_fields_for_ip_host("dst", ip_addr, port, protocol)
                            flowrule = f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, " \
                                       f"in_port={in_port},dl_src={device_mac},{field_rules} actions={action}"
                            logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     flowrule: {flowrule}")
                            outfile.writelines((flowrule, "\n"))
                    elif rule_dest_mac:
                        dest_list = await get_ipv4_hostports_for_hostportspec(rule_dest_mac)
                        logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     dest_list for {rule_dest_mac}: {dest_list}")
                        for dest_spec in dest_list:
                            logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     dest mac: {dest_spec}")
                            dest_fields = parse_macportspec(dest_spec)
                            logger.info(
                                f"OpenFlowAdapter.create_out_rules_for_device:     dest_fields: {dest_fields}")
                            (mac_addr, port, protocol) = dest_fields.values()
                            field_rules = self.flow_fields_for_mac_host("dst", mac_addr, port, protocol)
                            flowrule = f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, " \
                                       f"in_port={in_port},dl_src={device_mac},{field_rules} actions={action}"
                            logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     flowrule: {flowrule}")
                            outfile.writelines((flowrule, "\n"))
                    else:
                        # Just an action
                        logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     unconditional action: {action}")
                        if rule_action == "allow":
                            # A blank "allow" should not enable access to devices in other Micronets
                            flowrule_action = f"resubmit(,{OpenFlowAdapter.block_to_micronets_table})"
                        else:
                            flowrule_action = deny_action

                        flowrule = f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, " \
                                   f"in_port={in_port},dl_src={device_mac}, actions={flowrule_action}"
                        logger.info(f"OpenFlowAdapter.create_out_rules_for_device:     flowrule: {flowrule}")
                        outfile.writelines((flowrule, "\n"))
                    cur_priority -= 1
                except Exception as ex:
                    logger.warning(f"OpenFlowAdapter.create_out_rules_for_device: Error processing rule {rule}: {ex}",
                                   exc_info=True)

    async def create_in_rules_for_device(self, in_port, device_mac, device, micronet, outfile):
        cur_priority = 800
        device_id = device['deviceId']

        outfile.write(f"  # table={OpenFlowAdapter.to_micronets_table},priority={cur_priority}: "
                      f"In-Rules for Device {device['deviceId']} (mac {device_mac})\n")

        in_rules = device.get('inRules', None)
        if not in_rules:
            # Allow all data in if no in rules
            pass
            # The default rule (priority 0) will forward all traffic to the right port
        else:
            allow_action = f"resubmit(,{OpenFlowAdapter.to_device_table})"
            deny_action = OpenFlowAdapter.drop_action

            cur_priority -= 1
            for rule in in_rules:
                try:
                    logger.info(f"OpenFlowAdapter.create_in_rules_for_device: processing {device_id} in-rule: {rule}")
                    if 'dest' in rule:
                        raise Exception("'dest' is not supported in 'inRules' (rule {rule})")
                    rule_src = rule.get('sourceIp', None)
                    rule_dest_port = rule.get('destPort', None)
                    rule_action = rule['action']
                    logger.info(f"OpenFlowAdapter.create_in_rules_for_device:   action: {rule_action}")
                    action = allow_action if rule_action == "allow" else deny_action
                    if rule_dest_port:
                        destport_list = rule_dest_port.split(",")
                        for destport_spec in destport_list:
                            logger.info(f"OpenFlowAdapter.create_in_rules_for_device:     destPort: {destport_spec}")
                            destport_spec_fields = parse_portspec(destport_spec)
                            logger.info(
                                f"OpenFlowAdapter.create_in_rules_for_device:     destPort fields: {destport_spec_fields}")
                            (port, protocol) = destport_spec_fields.values()
                            field_rules = self.flow_fields_for_ip_host("dst", None, port, protocol)
                            flowrule = f"add table={OpenFlowAdapter.to_micronets_table},priority={cur_priority}, " \
                                       f"dl_dst={device_mac},{field_rules} actions={action}"
                            logger.info(f"OpenFlowAdapter.create_in_rules_for_device:     flowrule: {flowrule}")
                            outfile.writelines((flowrule, "\n"))
                    elif rule_src:
                        src_list = await get_ipv4_hostports_for_hostportspec(rule_src)
                        for src_spec in src_list:
                            logger.info(f"OpenFlowAdapter.create_in_rules_for_device:     src: {src_spec}")
                            src_fields = parse_hostportspec(src_spec)
                            logger.info(f"OpenFlowAdapter.create_in_rules_for_device:     src_fields: {src_fields}")
                            (ip_addr, port, protocol) = src_fields.values()
                            field_rules = self.flow_fields_for_ip_host("src", ip_addr, port, protocol)
                            flowrule = f"add table={OpenFlowAdapter.to_micronets_table},priority={cur_priority}, " \
                                       f"dl_dst={device_mac},{field_rules} actions={action}"
                            logger.info(f"OpenFlowAdapter.create_in_rules_for_device:     flowrule: {flowrule}")
                            outfile.writelines((flowrule, "\n"))
                    else:
                        # Just an action
                        logger.info(f"OpenFlowAdapter.create_in_rules_for_device:     unconditional action: {action}")
                        flowrule = f"add table={OpenFlowAdapter.to_micronets_table},priority={cur_priority}, " \
                                   f"dl_dst={device_mac}, actions={action}"
                        logger.info(f"OpenFlowAdapter.create_in_rules_for_device:     flowrule: {flowrule}")
                        outfile.writelines((flowrule, "\n"))
                    cur_priority -= 1
                except Exception as ex:
                    logger.warning(f"OpenFlowAdapter.create_in_rules_for_device: Error processing rule {rule}: {ex}")

    async def create_allowdenyhosts_rules_for_device(self, in_port, device_mac, device, micronet, outfile):
        cur_priority = 815

        device_id = device['deviceId']
        accept_action = f"resubmit(,{OpenFlowAdapter.to_localhost_table})"
        block_2_micronets = f"resubmit(,{OpenFlowAdapter.block_to_micronets_table})"

        hostport_spec_list = None
        if 'allowHosts' in device:
            hosts = device['allowHosts']
            logger.info(f"OpenFlowAdapter.create_allowdenyhosts_rules_for_device: "
                        f"processing allowHosts: {hosts}")
            hostport_spec_list = await unroll_hostportspec_list(hosts)
            # Add rule to allow EAPoL packets
            outfile.write(f"  # table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}: "
                          f"Adding rule to allow EAPoL traffic for {device_mac}\n")
            outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                          f"in_port={in_port},dl_src={device_mac},dl_type=0x888e, actions={accept_action}\n")
            if 'nameservers' in micronet:
                hostport_spec_list += micronet['nameservers']
            if 'nameservers' in device:
                hostport_spec_list += device['nameservers']
            ipv4Network = micronet.get('ipv4Network')
            if ipv4Network:
                gateway = ipv4Network.get('gateway')
                if gateway:
                    hostport_spec_list.append(gateway)
            match_action = accept_action
            default_action = OpenFlowAdapter.drop_action
        elif 'denyHosts' in device:
            hosts = device['denyHosts']
            logger.info(f"OpenFlowAdapter.create_allowdenyhosts_rules_for_device: "
                        f"processing denyHosts: {hosts}")
            hostport_spec_list = await unroll_hostportspec_list(hosts)
            match_action = OpenFlowAdapter.drop_action
            default_action = block_2_micronets

        if hostport_spec_list:
            outfile.write(f"  # table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}: "
                          f"hosts allowed/denied for device {device_id} (MAC {device_mac})\n")
            outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                          f"in_port={in_port}, dl_src={device_mac},udp,tp_dst=67, actions={accept_action}\n")
            outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                          f"in_port={in_port}, dl_src={device_mac},arp, actions={accept_action}\n")
            cur_priority = 810
            outfile.write(f"  # table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}: "
                          f"{device_mac}: hosts: {hosts}\n")
            for hostport_spec in hostport_spec_list:
                logger.info(f"OpenFlowAdapter.create_allowdenyhosts_rules_for_device: "
                            f"processing {device_id} allow/deny host: {hostport_spec}")
                # hostport_spec examples: 1.2.3.4, 3.4.5.6/32:22, 1.2.3.4/32:80/tcp,443/tcp,7,39/udp
                hostport_split = hostport_spec.split(':')
                mac_addr = None
                ip_addr = None
                portspec = None
                if len(hostport_split) >= 6:
                    # Looks like a 6-byte MAC address
                    mac_addr = hostport_spec[0:17]
                    portspec = hostport_spec[18:]
                    logger.info(f"OpenFlowAdapter.create_allowdenyhosts_rules_for_device: "
                                f"processing mac address {mac_addr} with portspec {portspec}")
                    if not mac_addr_re.match(mac_addr):
                        raise Exception(
                            f"Mac address specification '{mac_addr}' in host specification '{hostport_spec}' is invalid")
                elif len(hostport_split) == 2:
                    ip_addr = hostport_split[0]
                    portspec = hostport_split[1]
                elif len(hostport_split) == 1:
                    ip_addr = hostport_split[0]
                else:
                    raise Exception(
                        f"Host address/port specification '{hostport_spec}' is invalid")

                if mac_addr:
                    dest_spec = f"eth_dst={mac_addr}"
                else:
                    dest_spec = f"ip,ip_dst={ip_addr}"

                if not portspec:
                    # Need to create an address-only filter
                    outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                                  f"in_port={in_port},dl_src={device_mac},{dest_spec}, actions={match_action}\n")
                else:
                    # Need to create a ip+port filter(s)
                    portspec = hostport_split[1]
                    portspec_split = portspec.split('/')
                    if len(portspec_split) == 1:
                        # No protocol designation - apply port filter for udp and tcp
                        filter_tcp = filter_udp = True
                    else:
                        # Only block the port for the designated protocol
                        protocol = portspec_split[1]
                        filter_tcp = protocol == "tcp"
                        filter_udp = protocol == "udp"

                    if filter_tcp:
                        outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                                      f"in_port={in_port},dl_src={device_mac},{dest_spec},tcp,tcp_dst={portspec}, "
                                      f"actions={match_action}\n")
                    if filter_udp:
                        outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                                      f"in_port={in_port},dl_src={device_mac},{dest_spec},udp,udp_dst={portspec}, "
                                      f"actions={match_action}\n")
            # Write the default rule for the device
            cur_priority = 805

            outfile.write(f"add table={OpenFlowAdapter.from_micronets_table},priority={cur_priority}, "
                          f"in_port={in_port},dl_src={device_mac}, action={default_action}\n")
