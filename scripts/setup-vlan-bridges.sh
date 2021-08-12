#!/bin/bash

debug_log() {
    logger -t "$0" -- "$@"
    echo "$@"
}
ovs_vsctl() {
    debug_log "running: ovs-vsctl $@"
    ovs-vsctl "$@"
}

ovs_ofctl() {
    debug_log "running: ovs-ofctl $@"
    ovs-ofctl "$@"
}

clear_iptables() {
    iptables --table filter --flush
    iptables --table nat --flush
    sysctl -w net.ipv4.ip_forward=0
}

reset_ovsdb() {
  OVS_DB_CONF=/etc/openvswitch/conf.db
  OVS_DB_SCHEMA=/usr/share/openvswitch/vswitch.ovsschema
  /etc/init.d/openvswitch-switch stop
  sleep 1
  debug_log "Deleting ovs db at ${OVS_DB_CONF}"
  rm -fv "${OVS_DB_CONF}"
  ovsdb-tool create "${OVS_DB_CONF}" "${OVS_DB_SCHEMA}"
  /etc/init.d/openvswitch-switch start
}

reset_ovsdb

# Setep veth pair for HostAPD to connect the VLAN tagged interface ("haport" -> "HostAPD port")
#  This will create interfaces/ports haport and haport-sw
ip link add dev haport type veth peer name haport-sw
ip link set haport up

# Creates the primary Micronets OVS routing bridge (where the Micronets OVS rules will be applied)
ovs_vsctl --may-exist add-br brmn001 -- set bridge brmn001 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
ip link set brmn001 up

# Creates a diagnostic port on the Micronets bridge (dropped traffic can go here when configured)
ovs_vsctl --may-exist add-port brmn001 diagout1 -- set Interface diagout1 ofport_request=42 type=internal
ip link set diagout1 up

# Creates a Layer-2 HostAP OVS bridge for creating an inter-AP mesh
#  vxlan links will be added to this bridge to create the inter-AP mesh
ovs_vsctl --may-exist add-br brhapd -- set bridge brhapd protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
ip link set brhapd up

# Add one side of the HostAP veth pair to send the HostAPD tagged traffic to the Layer-2 bridge
#  The traffic from this port will be VLAN tagged by HostAPD locally
#  The trattic traffic going to this port will be VLAN tagged and can originate locally or from the mesh
ovs_vsctl --may-exist add-port brhapd haport-sw -- set Interface haport-sw ofport_request=3
ip link set haport-sw up

# Add a patch port between the OVS HostAPD Layer-2 bridge and the Micronets OVS routing bridge
#  This traffic going across this patch port should only be local (no inter-AP mesh traffic) 
ovs_vsctl --may-exist add-port brhapd hapd-trunk-patch -- set interface hapd-trunk-patch type=patch options:peer=brmn-trunk-patch
ovs_vsctl --may-exist add-port brmn001 brmn-trunk-patch -- set interface brmn-trunk-patch type=patch options:peer=hapd-trunk-patch

# Add Micronet-ready subnet defintions
#  TODO: Make the Micronets agent perform these steps dynamically
ip a add 10.135.1.1/24 dev brmn001
route add -net 10.135.1.0/24 gw 10.135.1.1 dev brmn001

ip a add 10.135.2.1/24 dev brmn001
route add -net 10.135.2.0/24 gw 10.135.2.1 dev brmn001

ip a add 10.135.3.1/24 dev brmn001
route add -net 10.135.3.0/24 gw 10.135.3.1 dev brmn001

