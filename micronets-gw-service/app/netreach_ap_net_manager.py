# Copyright (c) 2022 Cable Television Laboratories, Inc. ("CableLabs")
#                    and others.  All rights reserved.
#
# Licensed in accordance of the accompanied LICENSE.txt or LICENSE.md
# file in the base directory for this project. If none is supplied contact
# CableLabs for licensing terms of this software.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging, json, re, asyncio, httpx, hashlib, subprocess, tempfile
from pathlib import Path
from uuid import UUID
from .utils import short_uuid, mac_for_interface, apply_commands_to_ovs_bridge

logger = logging.getLogger ('netreach-ap-net-manager')


class NetreachApNetworkManager:
    def __init__(self, config, netreach_adapter):
        logger.info (f"NetreachTunnelManager init({netreach_adapter})")
        self.vxlan_net_bridge = config['NETREACH_ADAPTER_VXLAN_NET_BRIDGE']
        self.vxlan_net_bridge_micronets_port = config['NETREACH_ADAPTER_VXLAN_NET_MICRONETS_PORT']
        self.vxlan_net_bridge_hostapd_port = config['NETREACH_ADAPTER_VXLAN_NET_HOSTAPD_PORT']
        self.micronets_bridge = config.get('MICRONETS_OVS_BRIDGE')
        self.micronets_gateways_netmask = config['MICRONETS_GATEWAY_NETMASK']
        self.micronets_gateway_macaddr = config.get('MICRONETS_GATEWAY_MAC_ADDR',
                                                    mac_for_interface(self.micronets_bridge))
        self.vxlan_net_bridge_drop_port = config['MICRONETS_OVS_BRIDGE_DROP_PORT']
        self.vxlan_net_bridge_drop_action = f"output:{self.vxlan_net_bridge_drop_port}"
        self.vxlan_list_ports_cmd = config['NETREACH_ADAPTER_VXLAN_LIST_PORTS']
        self.vxlan_connect_cmd = config['NETREACH_ADAPTER_VXLAN_CONNECT_CMD']
        self.vxlan_disconnect_cmd = config['NETREACH_ADAPTER_VXLAN_DISCONNECT_CMD']
        self.ovs_flow_apply_cmd = config['FLOW_ADAPTER_APPLY_FLOWS_COMMAND']
        self.ovs_group_apply_cmd = config['FLOW_ADAPTER_APPLY_RULES_COMMAND']
        self.vxlan_port_prefix = config['NETREACH_ADAPTER_VXLAN_PEER_INAME_PREFIX']
        self.vxlan_port_format = config['NETREACH_ADAPTER_VXLAN_PEER_INAME_FORMAT']
        self.netreach_adapter = netreach_adapter
        self.ap_group = None
        self.vxlan_key_max = pow(2,24)
        for (name, val) in vars(self).items():
            if val is not None and val != [] and val != {}:
                logger.info(f"NetreachApNetworkManager: {name} = {val}")

    async def init_ap_online(self, ap_uuid, ap_group, service_list, service_device_list):
        self.ap_uuid = ap_uuid
        self.ap_group = ap_group
        self.ap_group_uuid = ap_group['uuid']
        await self.update_ap_network(service_list, service_device_list)
        await self._apply_flow_rules_for_connections([])

    async def update_ap_network(self, service_list, service_device_list):
        logger.info(f"update_ap_network()")

        needed_connections = await self._determine_needed_network_connections(service_list, service_device_list)
        existing_tun_names = await self._get_open_tunnel_names()

        logger.info(f"update_ap_network(): {len(needed_connections)} connections NEEDED:")
        # TODO: Enable via diagnostics
        for connection in needed_connections:
            dev = connection['device']
            serv = connection['service']
            ap = connection['accessPoint']
            tun_name = self._tunnel_name_for_connection(connection)
            logger.info(f"update_ap_network():  {tun_name} to {ap['name']} ({ap['managementAddress']}) "
                        f"for Dev {dev['name']} ({short_uuid(dev['uuid'])}) in Service {serv['name']} "
                        f"({short_uuid(serv['uuid'])}) with vlan {serv['vlan']}")

        missing_connections = await self._determine_missing_connections(needed_connections, existing_tun_names)
        logger.info(f"update_ap_network(): {len(missing_connections)} MISSING connections:")
        added_connections = await self._setup_network_connections(missing_connections)

        await self._apply_flow_rules_for_connections(needed_connections)

        # No need to do this immediately - so do it last
        # TODO: Consider doing this lazily - after some time has passed
        unneeded_tunnels = await self._determine_unneeded_tunnel_names(needed_connections, existing_tun_names)
        logger.info (f"update_ap_network(): {len(unneeded_tunnels)} UNNEEDED tunnel connections:")
        for tun_name in unneeded_tunnels:
            logger.info (f"update_ap_network():   Tunnel {tun_name} can be closed")
        await self._close_tunnels(unneeded_tunnels)

    async def update_ap_network_for_device(self, device_id, service_id, connected, associated_ap_id):
        logger.info(f"update_tunnels_for_device(device {device_id}, service {service_id}, "
                    f"connected {connected}, associated_ap_id {associated_ap_id})")
        # TODO

    async def _determine_needed_network_connections(self, service_list, service_device_list) -> []:
        # Return a list of needed network connections
        # logger.info(f"_determine_needed_network_connections: Connected devices:")
        # logger.info(self.netreach_adapter.dump_connected_devices(prefix="       "))
        needed_connection_list = []
        ap_list = None
        for service in service_list:
            service_enabled = service['enabled']
            service_uuid = service['uuid']
            service_name = service['name']
            if not service_enabled:
                logger.info(f"_determine_needed_network_connections: "
                            f"Service  \"{service_name}\" ({service_uuid}) is disabled - skipping it")
                continue
            local_devices_in_service = self.netreach_adapter.get_connected_devices(service_uuid)
            if len(local_devices_in_service) == 0:
                logger.info(f"_determine_needed_network_connections: no local devices "
                            f"in Service \"{service_name}\" ({service_uuid}) - skipping it")
                continue
            logger.info(f"_determine_needed_network_connections: AP has "
                        f"{len(local_devices_in_service)} connected devices "
                        f"in Service \"{service_name}\" ({service_uuid}) - Setting up inter-AP connections")
            # Assert: This AP has at least one Device from the service directly connected
            # Determine if there are Devices connected to other APs
            nr_device_list = service_device_list[service_uuid]
            for device in nr_device_list:
                device_id = device['uuid']
                device_name = device['name']
                device_connected = device['connected']
                if not device_connected:
                    logger.debug(f"_determine_needed_network_connections:   Device "
                                 f"\"{device_name}\" ({device_id}) isn't connected - skipping it")
                    continue
                associated_ap_uuid = device['associatedApUuid']
                if not associated_ap_uuid:
                    logger.warning(f"_determine_needed_network_connections:   Device "
                                   f"\"{device_name}\" ({device_id}) connected but doesn't have an associated AP field")
                    continue
                if associated_ap_uuid == self.ap_uuid:
                    logger.debug(f"_determine_needed_network_connections:   "
                                 f"Device \"{device_name}\" ({device_id}) is connected locally - skipping it")
                    continue
                logger.info(f"_determine_needed_network_connections:   "
                            f"Connection required for Device \"{device_name}\" ({device_id}) "
                            f"on AP {associated_ap_uuid}")
                if not ap_list:  # Only get the ap list if/when needed
                    ap_list = await self._get_ap_list_for_apgroup(self.ap_group_uuid)
                connection_entry = {"device": device, "service": service, "accessPoint": ap_list[associated_ap_uuid]}
                # logger.info(f"_determine_needed_network_connections:     {json.dumps(connection_entry, indent=4)}")
                needed_connection_list.append(connection_entry)
        return needed_connection_list

    async def _get_open_tunnel_names(self) -> {str}:
        run_cmd = self.vxlan_list_ports_cmd.format (**{"vxlan_net_bridge": self.vxlan_net_bridge})
        logger.info(f"_get_open_tunnel_names: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(run_cmd, stdout=asyncio.subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = await proc.communicate()

        logger.info(f"_get_open_tunnel_names: Bridge list command exited "
                    f"with exit code {proc.returncode}")

        output = stdout.decode() if stdout else ""
        if stdout:
            logger.info(f"_get_open_tunnel_names: stdout: {output}")
        if proc.returncode != 0:
            logger.error(f"_get_open_tunnel_names: Error retrieving interface list "
                         f"for bridge {self.vxlan_net_bridge}")
            return set()

        bridge_ints = output.splitlines()
        tunnel_ints = set()
        for int_name in bridge_ints:
            if int_name.startswith(self.vxlan_port_prefix):
                tunnel_ints.add(int_name)
        logger.info(f"_get_open_tunnel_names: Found interfaces: {tunnel_ints}")
        return tunnel_ints

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

    async def _determine_missing_connections(self, needed_connections, existing_tun_names) -> []:
        missing_connections = []
        for connection in needed_connections:
            tun_name = self._tunnel_name_for_connection(connection)
            if tun_name not in existing_tun_names:
                missing_connections.append(connection)
        return missing_connections

    async def _setup_network_connections(self, connections):
        tunnels_added = set()
        for connection in connections:
            tun_name = self._tunnel_name_for_connection(connection)
            if tun_name in tunnels_added:
                continue
            dev = connection['device']
            serv = connection['service']
            ap = connection['accessPoint']
            logger.info (f"_setup_network_connections():  Connecting {tun_name} to {ap['name']} "
                         f"({ap['managementAddress']}) "
                         f"for Dev {dev['name']} ({short_uuid(dev['uuid'])}) in Service {serv['name']} "
                         f"({short_uuid(serv['uuid'])}) with vlan {serv['vlan']}")
            await self._setup_tunnel_for_connection(connection)
            tunnels_added.add(tun_name)

    async def _setup_tunnel_for_connection(self, connection) -> str:
        vxlan_port_name = self._tunnel_name_for_connection(connection)
        ap_addr = connection['accessPoint']['managementAddress']
        conn_key = self._vxlan_key_for_connection(connection)
        run_cmd = self.vxlan_connect_cmd.format (**{"vxlan_net_bridge": self.vxlan_net_bridge,
                                                    "vxlan_port_name": vxlan_port_name,
                                                    "remote_vxlan_host": ap_addr,
                                                    "vxlan_conn_key": conn_key})
        logger.info(f"_setup_tunnel_to_ap_for_vlan: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(run_cmd, stdout=asyncio.subprocess.PIPE, stderr=subprocess.STDOUT)

        stdout, stderr = await proc.communicate()
        logger.info(f"_setup_tunnel_to_ap_for_vlan: Tunnel setup command completed "
                    f"with exit code {proc.returncode} (\"{stdout.decode()}\")")
        if proc.returncode != 0:
            ap_name = connection['accessPoint']['name']
            logger.error(f"_setup_tunnel_to_ap_for_vlan: Error connecting {vxlan_port_name} to {ap_name} "
                         f"({ap_addr}) with connection key {conn_key}")

    async def _apply_flow_rules_for_connections(self, connections):
        with tempfile.NamedTemporaryFile(mode='wt') as flow_file:
            flow_file_path = Path(flow_file.name)
            logger.info(f"_apply_flow_rules_for_connections: opened temporary flowrule file {flow_file_path}")

            flow_file.write ("del\n") # This will clear all flows
            flow_file.write(f"add table=0,priority=950, in_port={self.vxlan_net_bridge_micronets_port}, "
                            f"actions=output:{self.vxlan_net_bridge_hostapd_port}\n")
            flow_file.write(f"add table=0,priority=950, in_port={self.vxlan_net_bridge_hostapd_port}, "
                            f"actions=resubmit(,100)\n")
            # Rules will be added here for ingress from vxlan ports
            flow_file.write(f"add table=0,priority=0, actions={self.vxlan_net_bridge_drop_action}\n")
            flow_file.write("\n")

            # Rules for traffic coming from hostapd
            flow_file.write(f"add table=100,priority=700, dl_dst={self.micronets_gateway_macaddr}, "
                            f"actions=output:{self.vxlan_net_bridge_micronets_port}\n")
            flow_file.write(f"add table=100,priority=600, arp,arp_tpa={self.micronets_gateways_netmask}, "
                            f"actions=output:{self.vxlan_net_bridge_micronets_port}\n")
            flow_file.write(f"add table=100,priority=500, udp,tp_dst=67, "
                            f"actions=output:{self.vxlan_net_bridge_micronets_port}\n")
            # TODO: Add rule for flooding multicast traffic
            # Add gateway-bound traffic rules here (one per service/subnet) - to ensure no traffic destined for the
            #  subnet gateway is handled locally
            # Rules will be added here for each MAC address to direct traffic from hostapd to the appropriate vxlan port
            # e.g. table=100, priority=700,  dl_dst=b8:27:eb:6e:3a:6f,     actions=strip_vlan,output:gw-4-vlan-6

            # Any traffic not destined for a vxlan should be handled locally (via micronets)
            flow_file.write(f"add table=100,priority=0, actions=output:{self.vxlan_net_bridge_micronets_port}\n")

            vlan_map = {}
            for connection in connections:
                dev_mac = connection['device']['macAddress']
                vlan = connection['service']['vlan']
                tun_name = self._tunnel_name_for_connection(connection)
                if vlan not in vlan_map:
                    # We only need one of these rules per VLAN
                    flow_file.write(f"add table=100,priority=300, dl_vlan={vlan},dl_dst=FF:FF:FF:FF:FF:FF,"
                                    f"actions=strip_vlan,group:{vlan}\n")
                    vlan_map[vlan] = []
                tunnel_list = vlan_map[vlan]
                if tun_name not in tunnel_list:
                    # Ingress rule for Service traffic from AP
                    # We only need one of these per tunnel
                    flow_file.write(f"add table=0,priority=940, in_port={tun_name}, "
                                    f"actions=mod_vlan_vid:{vlan},output:{self.vxlan_net_bridge_hostapd_port}\n")
                    tunnel_list.append(tun_name)

                # Every remote device needs one rule
                flow_file.write(f"add table=100,priority=200, dl_dst={dev_mac}, "
                                f"actions=strip_vlan,output:{tun_name}\n")
            flow_file.flush()

            with tempfile.NamedTemporaryFile(mode='wt') as group_file:
                group_file_path = Path(group_file.name)
                logger.info(f"_apply_flow_rules_for_connections: opened temporary group file {group_file}")

                group_file.write("del\n") # This will clear all groups
                # Create one group for each vlan
                for (vlan, tunnels) in vlan_map.items():
                    # eg: add group_id=6,type=all,bucket=output:nap.023270.6,bucket=output:nap.5ef22e.6,bucket=output:nap.73cc5b.6
                    group_file.write(f"add group_id={vlan},type=all")
                    # Create one bucket for each tunnel. This will cause a packet sent to the group to go to all tunnels
                    for tunnel in tunnels:
                        group_file.write(f",bucket=output:{tunnel}")
                    group_file.write("\n")
                group_file.flush()
                # Note that the groups need to be established before rules can refer to them. Hence the order..
                await apply_commands_to_ovs_bridge(logger, self.ovs_group_apply_cmd, self.vxlan_net_bridge, group_file_path)
            await apply_commands_to_ovs_bridge(logger, self.ovs_flow_apply_cmd, self.vxlan_net_bridge, flow_file_path)

    async def _determine_unneeded_tunnel_names(self, needed_connections, existing_tun_names) -> set:
        needed_tun_names = set()
        for connection in needed_connections:
            needed_tun_names.add(self._tunnel_name_for_connection(connection))
        return existing_tun_names.difference(needed_tun_names)

    async def _close_tunnels(self, tunnel_connection_names) -> set:
        for tunnel_name in tunnel_connection_names:
            await self._close_tunnel(tunnel_name)

    async def _close_tunnel(self, vxlan_port_name):
        run_cmd = self.vxlan_disconnect_cmd.format (**{"vxlan_net_bridge": self.vxlan_net_bridge,
                                                       "vxlan_port_name": vxlan_port_name})
        logger.info(f"_setup_tunnel_to_ap_for_vlan: Running: {run_cmd}")
        proc = await asyncio.create_subprocess_shell(run_cmd, stdout=asyncio.subprocess.PIPE, stderr=subprocess.STDOUT)

        stdout, stderr = await proc.communicate()
        logger.info(f"_setup_tunnel_to_ap_for_vlan: Tunnel close command completed "
                    f"with exit code {proc.returncode} (\"{stdout.decode()}\")")

    def _tunnel_name_for_connection(self, connection) -> str:
        ap_uuid = connection['accessPoint']['uuid']
        vlan = connection['service']['vlan']
        return self.vxlan_port_format.format(**{"ap_uuid": ap_uuid, "short_ap_id": ap_uuid[-6:], "vlan": vlan})

    def _vxlan_key_for_connection(self, connection) -> int:
        # vxlan keys are 24-bit values. This function should generate a key which is the same even if ap_uuid_1 and
        # ap_uuid_2 are transposed. The key only needs to be unique between 2 hosts
        uuid_1 = UUID(self.ap_uuid)
        uuid_2 = UUID(connection['accessPoint']['uuid'])
        vlan = connection['service']['vlan']

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
