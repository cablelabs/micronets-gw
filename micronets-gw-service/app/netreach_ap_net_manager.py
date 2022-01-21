import logging, json, re, asyncio, httpx, hashlib, subprocess, tempfile
from pathlib import Path

logger = logging.getLogger ('netreach-ap-net-manager')

class NetreachApNetworkManager:
    def __init__(self, config, netreach_adapter):
        logger.info (f"NetreachTunnelManager init({netreach_adapter})")
        self.config = config
        self.vxlan_net_bridge = config['NETREACH_ADAPTER_VXLAN_NET_BRIDGE']
        self.vxlan_net_bridge_micronets_port = config['NETREACH_ADAPTER_VXLAN_NET_MICRONETS_PORT']
        self.vxlan_net_bridge_hostapd_port = config['NETREACH_ADAPTER_VXLAN_NET_HOSTAPD_PORT']
        self.vxlan_net_bridge_drop_port = config['MICRONETS_OVS_BRIDGE_DROP_PORT']
        self.vxlan_net_bridge_drop_action = f"output:{self.vxlan_net_bridge_drop_port}"
        self.vxlan_list_ports_cmd = config['NETREACH_ADAPTER_VXLAN_LIST_PORTS']
        self.vxlan_connect_cmd = config['NETREACH_ADAPTER_VXLAN_CONNECT_CMD']
        self.vxlan_disconnect_cmd = config['NETREACH_ADAPTER_VXLAN_DISCONNECT_CMD']
        self.ovs_flow_apply_cmd = config['NETREACH_ADAPTER_APPLY_FLOWS_COMMAND']
        self.vxlan_port_prefix = config['NETREACH_ADAPTER_VXLAN_PEER_INAME_PREFIX']
        self.netreach_adapter = netreach_adapter
        self.ap_group = None
        self.tunnel_int_list = []
        self.vxlan_key_max = pow(2,24)

    async def init_ap_online(self, ap_uuid, ap_group, service_list, service_device_list):
        self.tunnel_int_list = await self._get_tunnel_int_name_list()
        self.ap_uuid = ap_uuid
        self.ap_group = ap_group
        self.ap_group_uuid = ap_group['uuid']
        await self._setup_ap_network(service_list, service_device_list)

    async def _get_tunnel_int_name_list(self) -> [str]:
        run_cmd = self.vxlan_list_ports_cmd.format (**{"vxlan_net_bridge": self.vxlan_net_bridge})
        logger.info(f"_get_tunnel_int_name_list: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(run_cmd,
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()

        logger.info(f"_get_tunnel_int_name_list: Bridge list command exited "
                    f"with exit code {proc.returncode}")

        output = stdout.decode() if stdout else ""
        if stdout:
            logger.info(f"_get_tunnel_int_name_list: stdout: {output}")
        if stderr:
            logger.info(f"_get_tunnel_int_name_list: stderr: {stderr.decode()}")
        if proc.returncode != 0:
            logger.warning(f"_get_tunnel_int_name_list: Error retrieving interface list "
                           f"for bridge {self.vxlan_net_bridge}")
            return []

        bridge_ints = output.splitlines()
        tunnel_ints = []
        for int_name in bridge_ints:
            if int_name.startswith(self.vxlan_port_prefix):
                tunnel_ints.append(int_name)
        logger.info(f"_get_tunnel_int_name_list: Found interfaces: {tunnel_ints}")
        return tunnel_ints

    async def _setup_tunnel_to_ap_for_vlan(self, ap_addr, vxlan_port_name, vlan, conn_key) -> str:
        run_cmd = self.vxlan_connect_cmd.format (**{"vxlan_net_bridge": self.vxlan_net_bridge,
                                                    "vxlan_port_name": vxlan_port_name,
                                                    "remote_vxlan_host": ap_addr,
                                                    "vxlan_conn_key": conn_key})
        logger.info(f"_setup_tunnel_to_ap_for_vlan: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(
            run_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        stdout, stderr = await proc.communicate()
        logger.info(f"_setup_tunnel_to_ap_for_vlan: Tunnel setup command completed "
                    f"with exit code {proc.returncode}")

    async def close_tunnel_to_ap(self, vxlan_int_name) -> str:
        pass

    def vxlan_key_for_connection(self, uuid_1, uuid_2, vlan) -> int:
        # vxlan keys are 24-bit values. This function should generate a key which is the same even if ap_uuid_1 and
        # ap_uuid_2 are transposed. The key only needs to be unique between 2 hosts
        if uuid_1 < uuid_2:
            lid = uuid_1
            hid = uuid_2
        else:
            lid = uuid_2
            hid = uuid_1

        m = hashlib.blake2b(digest_size=3)
        m.update(lid.bytes)
        m.update(hid.bytes)
        m.update(vlan.to_bytes(2, byteorder='big'))

        return int.from_bytes(m.digest(), 'big')

    async def _apply_flows_to_vxlan_bridge(self, flow_file_path):
        with flow_file_path.open('r') as infile:
            infile.line_no = 1
            logger.info(f"Issuing new flows for OVS bridge {self.vxlan_net_bridge}:")
            logger.info ("------------------------------------------------------------------------")
            for line in infile:
                logger.info ("{0:4}: ".format(infile.line_no) + line[0:-1])
                infile.line_no += 1
            logger.info ("------------------------------------------------------------------------")
        run_cmd = self.ovs_flow_apply_cmd.format(**{"vxlan_net_bridge": self.vxlan_net_bridge,
                                                    "flow_file": flow_file_path})
        try:
            logger.info ("Applying flows using: " + run_cmd)

            proc = await asyncio.create_subprocess_shell(run_cmd,
                                                         stdout=asyncio.subprocess.PIPE,
                                                         stderr=subprocess.STDOUT)
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                logger.info(f"SUCCESSFULLY APPLIED FLOWS TO OVS BRIDGE {self.vxlan_net_bridge}")
            else:
                logger.warning(f"ERROR APPLYING FLOWS TO OVS BRIDGE {self.vxlan_net_bridge} "
                               f"(exit code {proc.returncode}")
                logger.warning(f"FLOW APPLICATION OUTPUT: {stdout.decode()}")
        except Exception as e:
            logger.warning(f"ERROR APPLYING FLOWS: {e}")

    async def _setup_ap_network(self, service_list, service_device_list):
        # Note: this should only be called when the AP is initializaed for an AP Group
        logger.info (f"OpenFlowAdapter._setup_ap_network()")

        with tempfile.NamedTemporaryFile(mode='wt') as flow_file:
            flow_file_path = Path(flow_file.name)
            logger.info(f"opened temporary file {flow_file_path}")

            flow_file.write ("del\n") # This will clear all flows
            flow_file.write(f"add table=0,priority=950, in_port={self.vxlan_net_bridge_micronets_port}, "
                            f"actions=output:{self.vxlan_net_bridge_hostapd_port}\n")
            flow_file.write(f"add table=0,priority=950, in_port={self.vxlan_net_bridge_hostapd_port}, "
                            f"actions=resubmit(,100)\n")
            # Rules will be added here for ingress from vxlan ports
            flow_file.write(f"add table=0,priority=0, actions={self.vxlan_net_bridge_drop_action}\n")
            flow_file.write("\n")

            # Rules for traffic coming from hostapd
            flow_file.write(f"add table=100,priority=950, udp,tp_src=67, "
                            f"actions=output:{self.vxlan_net_bridge_micronets_port}\n")
            flow_file.write(f"add table=100,priority=950, udp,tp_src=68, "
                            f"actions=output:{self.vxlan_net_bridge_micronets_port}\n")
            # Add gateway-bound traffic rules here (one per service/subnet) - to ensure no traffic destined for the
            #  subnet gateway is handled locally
            # e.g. table=100, priority=900, ip,ip_dst=10.0.6.1, actions=output:{self.vxlan_net_bridge_micronets_port}
            # TODO: Determine if we need rules to ensure ARPs for gateway addresses are handled locally (not flooded)
            # TODO: Determine if we can do service-level flooding (copying packets to a subset of ports)
            flow_file.write(f"add table=100,priority=800, dl_dst=FF:FF:FF:FF:FF:FF,"
                            f"actions=output:flood\n")
            # TODO: Add rule for flooding multicast traffic
            # Rules will be added here for each MAC address to direct traffic from hostapd to the appropriate vxlan port
            # e.g. table=100, priority=700,  dl_dst=b8:27:eb:6e:3a:6f,     actions=strip_vlan,output:gw-4-vlan-6

            # Any traffic not destined for a vxlan should be handled locally (via micronets)
            flow_file.write(f"add table=100,priority=0, actions=output:{self.vxlan_net_bridge_micronets_port}\n")
            flow_file.flush()

            await self._apply_flows_to_vxlan_bridge(flow_file_path)

        await self.update_ap_network(service_list, service_device_list)

    async def update_ap_network(self, service_list, service_device_list):
        logger.info (f"OpenFlowAdapter.update_ap_network()")
        needed_connections = await self._determine_all_network_connections(service_list, service_device_list)
        missing_connections = await self._determine_missing_connections(needed_connections)
        unneeded_connections = await self._determine_unneeded_connections(needed_connections)
        added_connection = await self._setup_network_connections(missing_connections)

        with tempfile.NamedTemporaryFile(mode='wt') as flow_file:
            flow_file_path = Path(flow_file.name)
            logger.info(f"opened temporary file {flow_file_path}")
            # ovs-vsctl add-port brhapd gw-4-vlan-6 -- set interface gw-4-vlan-6 type=vxlan options:remote_ip=10.10.1.62  options:key=030406
            # ovs-vsctl add-port brhapd gw-5-vlan-6 -- set interface gw-5-vlan-6 type=vxlan options:remote_ip=10.10.1.218 options:key=030506

            # table=0,   priority=940,  in_port=gw-4-vlan-6,          actions=mod_vlan_vid:6,output:haport-sw
            # table=0,   priority=940,  in_port=gw-5-vlan-6,          actions=mod_vlan_vid:6,output:haport-sw
            #
            # table=100, priority=700,  dl_dst=b8:27:eb:6e:3a:6f,     actions=strip_vlan,output:gw-4-vlan-6
            # table=100, priority=700,  dl_dst=00:12:7b:21:6c:b6,     actions=strip_vlan,output:gw-5-vlan-6

    async def update_ap_network_for_device(self, device_id, service_id, connected, associated_ap_id):
        logger.info(f"update_tunnels_for_device(device {device_id}, service {service_id}, "
                    f"connected {connected}, associated_ap_id {associated_ap_id})")

    async def _determine_all_network_connections(self, service_list, service_device_list) -> []:
        # Return a list of needed network connections
        logger.info(f"_determine_all_network_connections()")
        # TODO: REMOVE ME
        logger.info(f"_determine_all_network_connections: Connected devices:")
        logger.info(self.netreach_adapter.dump_connected_devices(prefix="       "))
        needed_connection_list = []
        ap_list = None
        for service in service_list:
            service_enabled = service['enabled']
            service_uuid = service['uuid']
            service_name = service['name']
            if not service_enabled:
                logger.info(f"_determine_all_network_connections: "
                            f"Service  \"{service_name}\" ({service_uuid}) is disabled - skipping")
                continue
            local_devices_in_service = self.netreach_adapter.get_connected_devices(service_uuid)
            if len(local_devices_in_service) == 0:
                logger.info(f"_determine_all_network_connections: no local devices "
                            f"in Service \"{service_name}\" ({service_uuid}) - skipping")
                continue
            logger.info(f"_determine_all_network_connections: AP has "
                        f"{len(local_devices_in_service)} connected devices "
                        f"in Service \"{service_name}\" ({service_uuid}) - Setting up connections")
            # Assert: This AP has at least one Device from the service directly connected
            # Determine if there are Devices connected to other APs
            nr_device_list = service_device_list[service_uuid]
            for device in nr_device_list:
                device_id = device['uuid']
                device_name = device['name']
                device_connected = device['connected']
                if not device_connected:
                    logger.info(f"_determine_all_network_connections:   Device "
                                f"\"{device_name}\" ({device_id}) isn't connected - skipping")
                    continue
                associated_ap_uuid = device['associatedApUuid']
                if not associated_ap_uuid:
                    logger.warning(f"_determine_all_network_connections:   Device "
                                   f"\"{device_name}\" ({device_id}) connected but doesn't have an associated AP field")
                    continue
                if associated_ap_uuid == self.ap_uuid:
                    logger.info(f"_determine_all_network_connections:   "
                                f"Device \"{device_name}\" ({device_id}) is connected locally - skipping")
                logger.info(f"_determine_all_network_connections:   "
                            f"Device \"{device_name}\" ({device_id}) is on AP {associated_ap_uuid} "
                            "- connection required")
                if not ap_list:  # Only get the ap list if/when needed
                    ap_list = await self._get_ap_list_for_apgroup(self.ap_group_uuid)
                connection_entry = {"device": device, "service": service, "accessPoint": ap_list[associated_ap_uuid]}
                logger.info(f"_determine_all_network_connections:   "
                            f"Need network connection for:  Device \"{device_name}\" ({device_id}):")
                logger.info(f"_determine_all_network_connections:     {json.dumps(connection_entry, indent=4)}")
                needed_connection_list.append(connection_entry)
        return needed_connection_list

    async def _determine_missing_connections(self, connections):
        pass

    async def _determine_unneeded_connections(self, connections):
        pass

    async def _get_ap_list_for_apgroup(self, apgroup_uuid) -> dict:
        # Returns a dict of APs keyed by AP UUID
        logger.info (f"NetreachTunnelManager._get_ap_list_for_apgroup()")
        async with httpx.AsyncClient() as httpx_client:
            response = await httpx_client.get(f"{self.netreach_adapter.controller_base_url}"
                                              f"/v1/ap-groups/{apgroup_uuid}/access-points",
                                              headers={"x-api-token": self.netreach_adapter.api_token})
            if response.status_code != 200:
                logger.warning(f"NetreachTunnelManager._get_ap_list_for_apgroup: FAILED retrieving AP list for "
                               f"AP group {apgroup_uuid} ({response.status_code}): {response.text}")
                raise ValueError(response.status_code)
            ap_list = response.json()
            aps = {}
            for ap in ap_list['results']:
                aps[ap['uuid']] = ap
            return aps

    async def _setup_network_connections(self, connections):
        pass

    async def _setup_ap_network_for_device(self, device, service):
        logger.info(f"_setup_ap_network_for_device(device: {device},service:...")

        device_id = device['uuid']
        device_name = device['name']
        device_enabled = device['enabled']
        device_mac = device['macAddress']
        device_ip = device['ipAddress']
        associated_ap_uuid = device['associatedApUuid']
        logger.info(f"_setup_ap_network_for_device: Setting up network for Device \"{device_name}\" "
                    f"mac {device_mac} ip {device_ip}")
        if not device_enabled or not device_mac:
            pass