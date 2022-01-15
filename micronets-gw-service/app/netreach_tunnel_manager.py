import logging, base64, json, httpx, re, asyncio, time, random, netifaces, hashlib, subprocess

logger = logging.getLogger ('netreach-tunnel')

class NetreachTunnelManager:
    def __init__(self, config, netreach_adapter):
        logger.info (f"NetreachTunnelManager init({netreach_adapter})")
        self.config = config
        self.ap_net_bridge = config['NETREACH_ADAPTER_VXLAN_NET_BRIDGE']
        self.vxlan_list_ports_cmd = config['NETREACH_ADAPTER_VXLAN_LIST_PORTS']
        self.vxlan_connect_cmd = config['NETREACH_ADAPTER_VXLAN_CONNECT_CMD']
        self.vxlan_disconnect_cmd = config['NETREACH_ADAPTER_VXLAN_DISCONNECT_CMD']
        self.ovs_flow_apply_cmd = config['NETREACH_ADAPTER_APPLY_FLOWS_COMMAND']
        self.vxlan_port_prefix = config['NETREACH_ADAPTER_VXLAN_PEER_INAME_PREFIX']
        self.netreach_adapter = netreach_adapter
        self.ap_group = None
        self.tunnel_int_list = []
        self.vxlan_key_max = pow(2,24)

    async def init_ap_online(self, ap_uuid):
        self.tunnel_int_list = await self._get_tunnel_int_name_list()
        self.ap_uuid = ap_uuid
        # await self.refresh_tunnel_network()

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
        run_cmd = self.vxlan_list_ports_cmd.format (**{"vxlan_net_bridge": self.ap_net_bridge})
        logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(run_cmd,
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()

        logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: Bridge list command exited "
                    f"with code {proc.returncode}")
        output = stdout.decode() if stdout else ""
        if stdout:
            logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: stdout: {output}")
        if stderr:
            logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: stderr: {stderr.decode()}")
        bridge_ints = output.splitlines()
        tunnel_ints = []
        for int_name in bridge_ints:
            if int_name.startswith(self.vxlan_port_prefix):
                tunnel_ints.append(int_name)
        logger.info(f"NetreachAdapter:_get_tunnel_int_name_list: Found interfaces: {tunnel_ints}")
        return tunnel_ints

    async def _setup_tunnel_to_ap_for_vlan(self, ap_addr, vxlan_port_name, vlan, conn_key) -> str:
        run_cmd = self.apply_openflow_command.format (**{"vxlan_net_bridge": self.ap_net_bridge,
                                                         "vxlan_port_name": vxlan_port_name,
                                                         "remote_vxlan_host": ap_addr,
                                                         "vxlan_conn_key": conn_key})
        logger.info(f"NetreachAdapter:_setup_tunnel_to_ap_for_vlan: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(
            run_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        stdout, stderr = await proc.communicate()

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

    async def refresh_tunnel_network(self):
        pass


