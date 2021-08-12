import re, logging, tempfile, netifaces, asyncio, subprocess

from pathlib import Path
from .utils import blank_line_re, comment_line_re, get_ipv4_hostports_for_hostportspec, parse_portspec, \
                   parse_hostportspec, unroll_hostportspec_list, mac_addr_re, parse_macportspec

from .hostapd_adapter import HostapdAdapter

logger = logging.getLogger ('micronets-gw-service')


class OpenFlowAdapter(HostapdAdapter.HostapdCLIEventHandler):
    start_table = 0
    from_micronets_ingress = 100
    from_micronets_egress = 110
    to_localhost_table = 120
    from_localhost_ingress = 200
    from_localhost_egress = 210
    to_device_table = 220

    def __init__ (self, config):
        self.apply_openflow_command = config['FLOW_ADAPTER_APPLY_FLOWS_COMMAND']
        self.bridge_name = config['MICRONETS_OVS_BRIDGE']
        self.micronet_trunk_port = config['MICRONETS_OVS_BRIDGE_TRUNK_PORT']
        self.drop_port = config['MICRONETS_OVS_BRIDGE_DROP_PORT']
        self.drop_action = f"output:{self.drop_port}"
        HostapdAdapter.HostapdCLIEventHandler.__init__(self, None)
        self.bss = {}


    async def handle_hostapd_ready(self):
        logger.info(f"OpenFlowAdapter.handle_hostapd_ready()")
        self.bss = self.hostapd_adapter.get_status_var('bss')
        logger.info(f"OpenFlowAdapter.handle_hostapd_ready:   BSS: {self.bss}")


    async def update (self, micronet_list, device_lists):
        logger.info (f"OpenFlowAdapter.update ()")
        logger.info (f"OpenFlowAdapter.update: device_lists: {device_lists}")

        # Note: These flows are a work-in-progress

        with tempfile.NamedTemporaryFile (mode='wt') as flow_file:
            flow_file_path = Path (flow_file.name)
            logger.info(f"opened temporary file {flow_file_path}")

            flow_file.write ("del\n") # This will clear all flows

            # START ------------------------------------------------------------------

            #
            # START TABLE RULES (in priority order)
            #
            flow_file.write("\n")

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
                            f"actions=resubmit(,{OpenFlowAdapter.from_localhost_ingress})\n")
            flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=400, "
                            f"in_port={self.micronet_trunk_port}, "
                            f"actions=resubmit(,{OpenFlowAdapter.from_micronets_ingress})\n")
            # Drop anything that doesn't come from a port we recognize
            flow_file.write(f"add table={OpenFlowAdapter.start_table},priority=0, "
                            f"actions={self.drop_action}\n")

            # FROM LOCALHOST ------------------------------------------------------------------

            #
            # FROM-MICRONETS INGRESS TABLE
            #
            flow_file.write("\n")

            # Allow already-tracked connections through
            #  UDP
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority=910, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.from_micronets_ingress})\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority=910, "
                            f"udp,ct_state=+trk+est, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority=910, "
                            f"udp,ct_state=+trk+rel, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")
            #  TCP
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority=905, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.from_micronets_ingress})\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority=905, "
                            f"tcp,ct_state=+trk+est, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority=905, "
                            f"tcp,ct_state=+trk+rel, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")

            # Create rules to allow unfiltered access to the device's subnet gateway
            #  and rules to enforce any defined ACLs
            for micronet_id, micronet in micronet_list.items():
                micronet_gateway = micronet['ipv4Network']['gateway']
                micronet_vlan = micronet.get('vlan', None)
                if not micronet_vlan:
                    raise Exception(f"Cannot find vlan for micronet {micronet_id}")
                # Walk the devices in the micronet and create rules
                for device_id, device in device_lists [micronet_id].items():
                    device_mac = device['macAddress']['eui48']
                    device_id = device['deviceId']
                    flow_file.write(f"# MICRONET {micronet_id} DEVICE {device_id}\n")
                    flow_file.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority=850, "
                                    f"dl_vlan={micronet_vlan},dl_src={device_mac}, "
                                    f"ip,ip_dst={micronet_gateway}, "
                                    f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")
                    await self.create_out_rules_for_device(OpenFlowAdapter.from_micronets_ingress,
                                                           800, micronet_vlan, device,
                                                           flow_file)

            # Drop everything that isn't redirected by a rule above
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority=0, "
                            f"actions={self.drop_action}\n")

            #
            # FROM-MICRONETS EGRESS TABLE
            #
            flow_file.write("\n")

            # All packets that haven't been given express permission to go to another micronet go through here
            for micronet_id, micronet in micronet_list.items():
                micronet_network = micronet['ipv4Network']['network']
                micronet_mask = micronet['ipv4Network']['mask']
                # Add the block rule to prevent micronet-to-micronet traffic without explicit rules
                flow_file.write(f"add table={OpenFlowAdapter.from_micronets_egress},priority=400, "
                                f"ip,ip_dst={micronet_network}/{micronet_mask}, actions={self.drop_action}\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_micronets_egress},priority=0, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_localhost_table})\n")

            #
            # TO LOCALHOST DELIVERY TABLE
            #
            flow_file.write("\n")

            # All packets that have been "approved" for local delivery go through here
            # Track UDP
            flow_file.write(f"add table={OpenFlowAdapter.to_localhost_table},priority=410, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_localhost_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_localhost_table},priority=410, "
                            f"udp,ct_state=+trk+new, "
                            f"actions=ct(commit),strip_vlan,output:LOCAL\n")
            # Track TCP
            flow_file.write(f"add table={OpenFlowAdapter.to_localhost_table},priority=400, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_localhost_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_localhost_table},priority=400, "
                            f"tcp,ct_state=+trk+new, "
                            f"actions=ct(commit),strip_vlan,output:LOCAL\n")

            # Deliver to the host
            flow_file.write(f"add table={OpenFlowAdapter.to_localhost_table},priority=0, "
                            f"actions=strip_vlan,output:LOCAL\n")

            # FROM LOCALHOST ------------------------------------------------------------------

            #
            # FROM-LOCALHOST INGRESS TABLE
            #
            flow_file.write("\n")

            vlan_list = []
            for micronet_id, micronet in micronet_list.items():
                micronet_vlan = micronet.get('vlan', None)
                vlan_list.append(micronet_vlan)
                if not micronet_vlan:
                    raise Exception(f"Cannot find vlan for micronet {micronet_id}")
                # Walk the devices in the micronet and create rules
                for device_id, device in device_lists [micronet_id].items():
                    device_mac = device['macAddress']['eui48']
                    device_id = device['deviceId']

                    flow_file.write(f"# LOCALHOST INGRESS FOR DEVICE {device_id} (micronet {micronet_id}\n")
                    flow_file.write(f"add table={OpenFlowAdapter.from_localhost_ingress},priority=200, "
                                    f"dl_dst={device_mac}, "
                                    f"actions=mod_vlan_vid:{micronet_vlan},"
                                    f"resubmit(,{OpenFlowAdapter.from_localhost_egress})\n")

            # Special rule to allow UDP broadcast OFFERs through (flood all Micronet ports)
            # TODO: This potentially needs to be sent to all VLANS ("vlan_list"), since we don't know which
            #       VLAN orginated the DHCP. Would hope that CT would take care of this, but it doesn't seem to.
            # flow_file.write(f"add table={OpenFlowAdapter.from_localhost_ingress},priority=100, "
            #                 f"dl_dst=FF:FF:FF:FF:FF:FF,udp,tp_src=67,tp_dst=68, "
            #                 f"resubmit(,{OpenFlowAdapter.from_localhost_egress})\n")

            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_ingress},priority=0, "
                            f"actions={self.drop_action}\n")

            #
            # TO-MICRONETS EGRESS TABLE
            #

            flow_file.write("\n")
            # Tracked connection passthrough
            #  UDP
            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_egress},priority=950, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.from_localhost_egress})\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_egress},priority=950, "
                            f"udp,ct_state=+trk+est, "
                            f"actions=output:{self.micronet_trunk_port}\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_egress},priority=950, "
                            f"udp,ct_state=+trk+rel, "
                            f"actions=output:{self.micronet_trunk_port}\n")
            #  TCP
            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_egress},priority=940, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.from_localhost_egress})\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_egress},priority=940, "
                            f"tcp,ct_state=+trk+est, "
                            f"actions=output:{self.micronet_trunk_port}\n")
            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_egress},priority=940, "
                            f"tcp,ct_state=+trk+rel, "
                            f"actions=output:{self.micronet_trunk_port}\n")

            # Allow certain low-level protocols through (ARP, ICMP, EAPoL, DNS, NTP...)
            for pass_filter in ["arp", "icmp", "dl_type=0x888e", "udp,tp_dst=68",
                                "udp,tp_dst=53", "udp,tp_dst=123"]:
                flow_file.write(f"add table={OpenFlowAdapter.from_localhost_egress},priority=900, "
                                f"{pass_filter}, "
                                f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")

            for micronet_id, micronet in micronet_list.items():
                micronet_vlan = micronet.get('vlan', None)
                if not micronet_vlan:
                    raise Exception(f"Cannot find vlan for micronet {micronet_id}")
                # Walk the devices in the micronet and create rules
                for device_id, device in device_lists[micronet_id].items():
                    device_mac = device['macAddress']['eui48']
                    device_id = device['deviceId']

                    flow_file.write(f"# TO-DEVICE EGRESS RULES FOR DEVICE {device_id} (micronet {micronet_id}\n")
                    await self.create_in_rules_for_device(OpenFlowAdapter.from_localhost_egress,
                                                          800, device, flow_file)

            # Allow packets that aren't expressly denied through
            flow_file.write(f"add table={OpenFlowAdapter.from_localhost_egress},priority=0, "
                            f"actions=resubmit(,{OpenFlowAdapter.to_device_table})\n")

            #
            # TO-DEVICE TABLE
            #

            flow_file.write("\n")
            # All packets approved for delivery to a micronet device go through here
            #  (and are already VLAN-tagged)
            #  UDP
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority=400, "
                            f"udp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority=400, "
                            f"udp,ct_state=+trk+new, "
                            f"actions=ct(commit),output:{self.micronet_trunk_port}\n")
            #  TCP
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority=400, "
                            f"tcp,ct_state=-trk, "
                            f"actions=ct(table={OpenFlowAdapter.to_device_table})\n")
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority=400, "
                            f"tcp,ct_state=+trk+new, "
                            f"actions=ct(commit),output:{self.micronet_trunk_port}\n")

            # OUTPUT to the micronet/device trunk port
            flow_file.write(f"add table={OpenFlowAdapter.to_device_table},priority=400, "
                            f"actions=output:{self.micronet_trunk_port}\n")

            flow_file.flush()

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
                run_out = subprocess.run(run_cmd.split(), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
                if run_out.returncode == 0:
                    logger.info(f"SUCCESSFULLY APPLIED FLOWS")
                else:
                    logger.warning(f"ERROR APPLYING FLOWS (exit code {run_out.returncode}")
                    logger.warning(f"FLOW APPLICATION OUTPUT: {run_out.stdout.decode('utf-8')}")
            except Exception as e:
                logger.warning(f"ERROR APPLYING FLOWS: {e}")

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

    async def create_out_rules_for_device(self, table, priority, in_vlan, device, outfile):
        out_rules = device.get('outRules', None)
        device_mac = device['macAddress']['eui48']
        device_id = device['deviceId']
        if not out_rules:
            # Allow all data out if no out rules
            outfile.write(f"add table={table},priority={priority}, "
                          f"dl_vlan={in_vlan},dl_src={device_mac}, "
                          f"actions=resubmit(,{OpenFlowAdapter.from_micronets_egress})\n\n")
        else:
            allow_action = f"resubmit(,{OpenFlowAdapter.to_localhost_table})"
            deny_action = self.drop_action

            # Allow these through regardless of ACLs
            for pass_filter in ["arp", "dl_type=0x888e", "udp,tp_dst=67", "udp,tp_dst=53", "udp,tp_dst=123"]:
                outfile.write(f"add table={table},priority={priority}, "
                              f"dl_vlan={in_vlan},dl_src={device_mac},{pass_filter}, "
                              f"actions={allow_action}\n")
            priority -= 1
            for rule in out_rules:
                try:
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
                            destport_spec_fields = parse_portspec(destport_spec)
                            (port, protocol) = destport_spec_fields.values()
                            field_rules =  self.flow_fields_for_ip_host("dst", None, port, protocol)
                            flowrule = f"add table={table},priority={priority}, " \
                                       f"dl_vlan={in_vlan},dl_src={device_mac},{field_rules} actions={action}"
                            outfile.writelines((flowrule, "\n"))
                    elif rule_dest_ip:
                        dest_list = await get_ipv4_hostports_for_hostportspec(rule_dest_ip)
                        for dest_spec in dest_list:
                            dest_fields = parse_hostportspec(dest_spec)
                            (ip_addr, port, protocol) = dest_fields.values()
                            field_rules = self.flow_fields_for_ip_host("dst", ip_addr, port, protocol)
                            flowrule = f"add table={table},priority={priority}, " \
                                       f"dl_vlan={in_vlan},dl_src={device_mac},{field_rules} actions={action}"
                            outfile.writelines((flowrule, "\n"))
                    elif rule_dest_mac:
                        dest_list = await get_ipv4_hostports_for_hostportspec(rule_dest_mac)
                        for dest_spec in dest_list:
                            dest_fields = parse_macportspec(dest_spec)
                            (mac_addr, port, protocol) = dest_fields.values()
                            field_rules = self.flow_fields_for_mac_host("dst", mac_addr, port, protocol)
                            flowrule = f"add table={table},priority={priority}, " \
                                       f"dl_vlan={in_vlan},dl_src={device_mac},{field_rules} actions={action}"
                            outfile.writelines((flowrule, "\n"))
                    else:
                        # Just an action
                        if rule_action == "allow":
                            # A blank "allow" should not enable access to devices in other Micronets
                            flowrule_action = f"resubmit(,{OpenFlowAdapter.from_micronets_egress})"
                        else:
                            flowrule_action = deny_action

                        flowrule = f"add table={table},priority={priority}, " \
                                   f"dl_vlan={in_vlan},dl_src={device_mac}, actions={flowrule_action}"
                        outfile.writelines((flowrule, "\n"))
                    priority -= 1
                except Exception as ex:
                    logger.warning(f"OpenFlowAdapter.create_out_rules_for_device: Error processing rule {rule}: {ex}",
                                   exc_info=True)

    async def create_in_rules_for_device(self, table, priority, device, outfile):
        device_id = device['deviceId']
        device_mac = device['macAddress']['eui48']

        outfile.write(f"  # table={table},priority={priority}: "
                      f"In-Rules for Device {device['deviceId']} (mac {device_mac})\n")

        in_rules = device.get('inRules', None)
        if not in_rules:
            # Allow all data in if no in rules
            pass
            # The default rule (priority 0) will forward all traffic to the right port
        else:
            allow_action = f"resubmit(,{OpenFlowAdapter.to_device_table})"
            deny_action = self.drop_action

            priority -= 1
            for rule in in_rules:
                try:
                    logger.debug(f"OpenFlowAdapter.create_in_rules_for_device: processing {device_id} in-rule: {rule}")
                    if 'dest' in rule:
                        raise Exception("'dest' is not supported in 'inRules' (rule {rule})")
                    rule_src = rule.get('sourceIp', None)
                    rule_dest_port = rule.get('destPort', None)
                    rule_action = rule['action']
                    logger.debug(f"OpenFlowAdapter.create_in_rules_for_device:   action: {rule_action}")
                    action = allow_action if rule_action == "allow" else deny_action
                    if rule_dest_port:
                        destport_list = rule_dest_port.split(",")
                        for destport_spec in destport_list:
                            logger.debug(f"OpenFlowAdapter.create_in_rules_for_device:     destPort: {destport_spec}")
                            destport_spec_fields = parse_portspec(destport_spec)
                            logger.debug(
                                f"OpenFlowAdapter.create_in_rules_for_device:     destPort fields: {destport_spec_fields}")
                            (port, protocol) = destport_spec_fields.values()
                            field_rules = self.flow_fields_for_ip_host("dst", None, port, protocol)
                            flowrule = f"add table={OpenFlowAdapter.from_localhost_egress},priority={priority}, " \
                                       f"dl_dst={device_mac},{field_rules} actions={action}"
                            logger.debug(f"OpenFlowAdapter.create_in_rules_for_device:     flowrule: {flowrule}")
                            outfile.writelines((flowrule, "\n"))
                    elif rule_src:
                        src_list = await get_ipv4_hostports_for_hostportspec(rule_src)
                        for src_spec in src_list:
                            logger.debug(f"OpenFlowAdapter.create_in_rules_for_device:     src: {src_spec}")
                            src_fields = parse_hostportspec(src_spec)
                            logger.debug(f"OpenFlowAdapter.create_in_rules_for_device:     src_fields: {src_fields}")
                            (ip_addr, port, protocol) = src_fields.values()
                            field_rules = self.flow_fields_for_ip_host("src", ip_addr, port, protocol)
                            flowrule = f"add table={OpenFlowAdapter.from_localhost_egress},priority={priority}, " \
                                       f"dl_dst={device_mac},{field_rules} actions={action}"
                            logger.debug(f"OpenFlowAdapter.create_in_rules_for_device:     flowrule: {flowrule}")
                            outfile.writelines((flowrule, "\n"))
                    else:
                        # Just an action
                        logger.debug(f"OpenFlowAdapter.create_in_rules_for_device:     unconditional action: {action}")
                        flowrule = f"add table={OpenFlowAdapter.from_localhost_egress},priority={priority}, " \
                                   f"dl_dst={device_mac}, actions={action}"
                        logger.debug(f"OpenFlowAdapter.create_in_rules_for_device:     flowrule: {flowrule}")
                        outfile.writelines((flowrule, "\n"))
                    priority -= 1
                except Exception as ex:
                    logger.warning(f"OpenFlowAdapter.create_in_rules_for_device: Error processing rule {rule}: {ex}")

    async def create_allowdenyhosts_rules_for_device(self, table, priority, vlan, device, micronet, outfile):
        device_id = device['deviceId']
        device_mac = device['']
        accept_action = f"resubmit(,{OpenFlowAdapter.to_localhost_table})"
        block_2_micronets = f"resubmit(,{OpenFlowAdapter.from_micronets_egress})"

        hostport_spec_list = None
        if 'allowHosts' in device:
            hosts = device['allowHosts']
            logger.info(f"OpenFlowAdapter.create_allowdenyhosts_rules_for_device: "
                        f"processing allowHosts: {hosts}")
            hostport_spec_list = await unroll_hostportspec_list(hosts)
            outfile.write(f"add table={table},priority={priority}, "
                          f"dl_vlan={vlan},dl_src={device_mac},dl_type=0x888e, actions={accept_action}\n")
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
            default_action = self.drop_action
        elif 'denyHosts' in device:
            hosts = device['denyHosts']
            logger.info(f"OpenFlowAdapter.create_allowdenyhosts_rules_for_device: "
                        f"processing denyHosts: {hosts}")
            hostport_spec_list = await unroll_hostportspec_list(hosts)
            match_action = self.drop_action
            default_action = block_2_micronets

        if hostport_spec_list:
            outfile.write(f"  # table={table},priority={priority}: "
                          f"hosts allowed/denied for device {device_id} (MAC {device_mac})\n")
            outfile.write(f"add table={table},priority={priority}, "
                          f"dl_vlan={vlan},dl_src={device_mac},udp,tp_dst=67, actions={accept_action}\n")
            outfile.write(f"add table={table},priority={priority}, "
                          f"dl_vlan={vlan},dl_src={device_mac},arp, actions={accept_action}\n")
            priority -= 5
            outfile.write(f"  # table={OpenFlowAdapter.from_micronets_ingress},priority={priority}: "
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
                    outfile.write(f"add table={table},priority={priority}, "
                                  f"dl_vlan={vlan},dl_src={device_mac},{dest_spec}, actions={match_action}\n")
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
                        outfile.write(f"add table={table},priority={priority}, "
                                      f"dl_vlan={vlan},dl_src={device_mac},{dest_spec},tcp,tcp_dst={portspec}, "
                                      f"actions={match_action}\n")
                    if filter_udp:
                        outfile.write(f"add table={table},priority={priority}, "
                                      f"dl_vlan={vlan},dl_src={device_mac},{dest_spec},udp,udp_dst={portspec}, "
                                      f"actions={match_action}\n")
            # Write the default rule for the device
            priority -= 5

            outfile.write(f"add table={OpenFlowAdapter.from_micronets_ingress},priority={priority}, "
                          f"dl_vlan={vlan},dl_src={device_mac}, action={default_action}\n")
