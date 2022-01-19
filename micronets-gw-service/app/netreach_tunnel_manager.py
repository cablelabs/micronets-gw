import logging, json, re, asyncio, httpx, hashlib, subprocess, tempfile
from pathlib import Path

logger = logging.getLogger ('netreach-tunnel')

class NetreachTunnelManager:
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

    async def init_ap_online(self, ap_uuid, ap_group_uuid, service_list, service_device_list):
        self.tunnel_int_list = await self._get_tunnel_int_name_list()
        self.ap_uuid = ap_uuid
        self.ap_group_uuid = ap_group_uuid
        # await self._setup_tunnel_network()

    async def _get_aps_for_group(self, apgroup_uuid) -> dict:
        logger.info (f"NetreachTunnelManager.get_aps_for_group()")
        async with httpx.AsyncClient() as httpx_client:
            response = await httpx_client.get(f"{self.netreach_adapter.controller_base_url}"
                                              f"/v1/ap-groups/{apgroup_uuid}/access-points",
                                              headers={"x-api-token": self.netreach_adapter.api_token})
            if response.status_code != 200:
                logger.warning(f"NetreachTunnelManager.get_aps_for_group: FAILED retrieving AP list for "
                               f"AP group {apgroup_uuid} ({response.status_code}): {response.text}")
                raise ValueError(response.status_code)
            ap_list = response.json()
            aps = {}
            for ap in ap_list['results']:
                aps[ap['uuid']] = ap
            logger.info(f"NetreachAdapter:get_aps_for_group: Got AP list for AP Group {apgroup_uuid}: "
                        f"{json.dumps(aps, indent=4)}")
            return aps

    async def _get_tunnel_int_name_list(self) -> [str]:
        run_cmd = self.vxlan_list_ports_cmd.format (**{"vxlan_net_bridge": self.vxlan_net_bridge})
        logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(run_cmd,
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()

        logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: Bridge list command exited "
                    f"with exit code {proc.returncode}")

        output = stdout.decode() if stdout else ""
        if stdout:
            logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: stdout: {output}")
        if stderr:
            logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: stderr: {stderr.decode()}")
        if proc.returncode != 0:
            logger.warning(f"NetreachAdapter:_get_tunnel_int_name_list: Error retrieving interface list "
                           f"for bridge {self.vxlan_net_bridge}")
            return []

        bridge_ints = output.splitlines()
        tunnel_ints = []
        for int_name in bridge_ints:
            if int_name.startswith(self.vxlan_port_prefix):
                tunnel_ints.append(int_name)
        logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: Found interfaces: {tunnel_ints}")
        return tunnel_ints

    async def _setup_tunnel_to_ap_for_vlan(self, ap_addr, vxlan_port_name, vlan, conn_key) -> str:
        run_cmd = self.vxlan_connect_cmd.format (**{"vxlan_net_bridge": self.vxlan_net_bridge,
                                                    "vxlan_port_name": vxlan_port_name,
                                                    "remote_vxlan_host": ap_addr,
                                                    "vxlan_conn_key": conn_key})
        logger.info(f"NetreachAdapter:_setup_tunnel_to_ap_for_vlan: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(
            run_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        stdout = await proc.communicate()
        logger.info(f"NetreachAdapter:_setup_tunnel_to_ap_for_vlan: Tunnel setup command completed "
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

    async def setup_tunnel_network(self):
        logger.info (f"OpenFlowAdapter.setup_tunnel_network()")
        with tempfile.NamedTemporaryFile(mode='wt') as flow_file:
            flow_file_path = Path(flow_file.name)
            logger.info(f"opened temporary file {flow_file_path}")

            flow_file.write ("del\n") # This will clear all flows
            flow_file.write(f"add table=0,priority=950, in_port={self.vxlan_net_bridge_micronets_port}, "
                            f"actions=output:{self.vxlan_net_bridge_hostapd_port}")
            flow_file.write(f"add table=0,priority=950, in_port={self.vxlan_net_bridge_hostapd_port}, "
                            f"actions=resubmit(,100)")
            # Rules will be added here for ingress from vxlan ports
            flow_file.write(f"add table=0,priority=0, actions={self.vxlan_net_bridge_drop_action}")
            flow_file.write("\n")

            # Rules for traffic coming from hostapd
            flow_file.write(f"add table=100,priority=950, udp,tp_src=67, "
                            f"actions=output:{self.vxlan_net_bridge_micronets_port}")
            flow_file.write(f"add table=100,priority=950, udp,tp_src=68, "
                            f"actions=output:{self.vxlan_net_bridge_micronets_port}")
            # Add gateway-bound traffic rules here (one per service/subnet) - to ensure no traffic destined for the
            #  subnet gateway is handled locally
            # e.g. table=100, priority=900, ip,ip_dst=10.0.6.1, actions=output:{self.vxlan_net_bridge_micronets_port}
            # TODO: Determine if we need rules to ensure ARPs for gateway addresses are handled locally (not flooded)
            flow_file.write(f"add table=100,priority=800, dl_dst=FF:FF:FF:FF:FF:FF,"
                            f"actions=output:flood")
            # TODO: Add rule for flooding multicast traffic
            # Rules will be added here for each MAC address to direct traffic from hostapd to the appropriate vxlan port
            # e.g. table=100, priority=700,  dl_dst=b8:27:eb:6e:3a:6f,     actions=strip_vlan,output:gw-4-vlan-6

            # Any traffic not destined for a vxlan should be handled locally (via micronets)
            flow_file.write(f"add table=100,priority=0, actions=output:{self.vxlan_net_bridge_micronets_port}")

            flow_file.flush()

            with flow_file_path.open('r') as infile:
                infile.line_no = 1
                logger.info ("Issuing new flows:")
                logger.info ("------------------------------------------------------------------------")
                for line in infile:
                    logger.info ("{0:4}: ".format(infile.line_no) + line[0:-1])
                    infile.line_no += 1
                logger.info ("------------------------------------------------------------------------")
            # {vxlan_net_bridge} {flow_file}
            run_cmd = self.ovs_flow_apply_cmd.format(**{"vxlan_net_bridge": self.vxlan_net_bridge,
                                                        "flow_file": flow_file_path})
            try:
                logger.info ("Applying flows using: " + run_cmd)

                proc = await asyncio.create_subprocess_shell(run_cmd,
                                                             stdout=asyncio.subprocess.PIPE,
                                                             stderr=subprocess.STDOUT)
                stdout = await proc.communicate()

                if proc.returncode == 0:
                    logger.info(f"SUCCESSFULLY APPLIED FLOWS")
                else:
                    logger.warning(f"ERROR APPLYING FLOWS (exit code {proc.returncode}")
                    logger.warning(f"FLOW APPLICATION OUTPUT: {stdout.decode('utf-8')}")
            except Exception as e:
                logger.warning(f"ERROR APPLYING FLOWS: {e}")

    async def update_tunnels_for_device(self, device_id, service_id, connected, associatedApUuid):
        logger.info(f"NetreachAdapter:update_tunnels_for_device(device: {device_id},service: {service_id},"
                    f"connected: {connected},associatedApUuid: {associatedApUuid}")
        connected_devs_for_service = self.netreach_adapter.get_connected_devices(service_uuid=service_id)
        logger.info(f"NetreachAdapter:update_tunnels_for_device: connected devices for service: "
                    + connected_devs_for_service)

