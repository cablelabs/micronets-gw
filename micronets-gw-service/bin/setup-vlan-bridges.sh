#!/bin/bash

fqdir_for_file() {
   fqd="$( cd "$( dirname "$1" )" >/dev/null 2>&1 && pwd )"
   echo $fqd
}

script_dir="$(fqdir_for_file ${BASH_SOURCE[0]})"
conf_file="$(fqdir_for_file $script_dir/../lib/blah)/gateway.conf"

if [ -e $conf_file ]; then
    echo "Reading settings from conf file: $conf_file"
    source $conf_file
fi

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

config_iptables_bridge_uplink() {
    BRIDGE_INTERFACE=$1
    UPLINK_INTERFACE=$2
    debug_log "Configuring NAT with uplink interface ${UPLINK_INTERFACE}, bridge interface ${BRIDGE_INTERFACE}..."
    iptables --table nat --append POSTROUTING --out-interface ${UPLINK_INTERFACE} \
        -j MASQUERADE
    iptables --table filter --append FORWARD --in-interface ${UPLINK_INTERFACE} --out-interface  ${BRIDGE_INTERFACE} \
        -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables --table filter --append FORWARD --in-interface ${UPLINK_INTERFACE} \
        -m state --state NEW,INVALID -j LOG $LOG_OPTS --log-prefix 'FW-DROP (NEW/INVALID-FWD):'
    iptables --table filter --append FORWARD --in-interface ${UPLINK_INTERFACE} \
        -m state --state NEW,INVALID -j DROP
    iptables --table filter --append FORWARD --out-interface ${UPLINK_INTERFACE} \
        -j ACCEPT
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

# TODO: Make bridge names, etc config variables

# Setup veth pair for HostAPD to connect the VLAN tagged interface ("haport" -> "HostAPD port")
#  This will create interfaces/ports haport and haport-sw
if ! ip link show haport; then
  debug_log "Creating veth haport/haport-sw pair"
  ip link add dev haport type veth peer name haport-sw
  ip link set haport up
  ip link set haport-sw up
fi

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

# Add a patch port between the OVS HostAPD Layer-2 bridge and the Micronets OVS routing bridge
#  This traffic going across this patch port should only be local (no inter-AP mesh traffic) 
ovs_vsctl --may-exist add-port brhapd hapd-tr-patch -- set interface hapd-tr-patch type=patch options:peer=brmn-tr-patch ofport_request=1
ovs_vsctl --may-exist add-port brmn001 brmn-tr-patch -- set interface brmn-tr-patch type=patch options:peer=hapd-tr-patch ofport_request=1

# Add some short-circuit flow rules for brhapd that sends all downward traffic directly to hostap tagged interface
ovs-ofctl add-flow brhapd "table=0, priority=200, in_port=1, actions=output:haport-sw"

# Add Micronet-ready subnet defintions
#  TODO: Make the Micronets agent perform these steps dynamically
ip a add 10.0.5.1/24 dev brmn001
route add -net 10.0.5.0/24 gw 10.0.5.1 dev brmn001

ip a add 10.0.6.1/24 dev brmn001
route add -net 10.0.6.0/24 gw 10.0.6.1 dev brmn001

ip a add 10.0.7.1/24 dev brmn001
route add -net 10.0.7.0/24 gw 10.0.7.1 dev brmn001

ip a add 10.0.8.1/24 dev brmn001
route add -net 10.0.8.0/24 gw 10.0.8.1 dev brmn001

ip a add 10.0.9.1/24 dev brmn001
route add -net 10.0.9.0/24 gw 10.0.9.1 dev brmn001

ip a add 10.0.10.1/24 dev brmn001
route add -net 10.0.10.0/24 gw 10.0.10.1 dev brmn001

ip a add 10.0.11.1/24 dev brmn001
route add -net 10.0.11.0/24 gw 10.0.11.1 dev brmn001

ip a add 10.0.12.1/24 dev brmn001
route add -net 10.0.12.0/24 gw 10.0.12.1 dev brmn001

# Enable firewall rules
clear_iptables
config_iptables_bridge_uplink $MICRONETS_BRIDGE $UPLINK_INTERFACE

# Enable packet routing/forwarding
sysctl -w net.ipv4.ip_forward=1
