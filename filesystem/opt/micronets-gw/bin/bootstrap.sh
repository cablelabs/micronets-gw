#!/bin/bash -x

source /etc/openvswitch/ovs.conf

CWD=/opt/micronets-gw/bin # 

TS=`date +%j'T'%H%M%S`
TAG=ovsboot-${TS}

function hr {
  echo "------------------------------------------------------------------------------------------------------"
}

function show {
  hr
  ip addr
  ip link
  ip route
  hr
  ovs-vsctl show
  ovs-appctl bridge/dump-flows ${OVS_BRIDGE_INTERFACE}
  ovs-dpctl -m dump-flows
  ovs-dpctl show
  hr
}

function set_manager_connect {
 ovs-vsctl set-manager ${OVSDB_MANAGER_CONNECT_SOCKET}
}

function main {
  {
    # DEBUG: Uncomment to clear OVSDB on bootstrap.
    # ${CWD}/resetdb.sh

    show
    ${CWD}/normal.sh ${OVS_BRIDGE_INTERFACE}
    show

    iptables --flush
    iptables --table nat --flush
    iptables --delete-chain
    iptables --table nat --delete-chain
    iptables --table nat --append POSTROUTING --out-interface ${OVS_BRIDGE_INTERFACE} -j MASQUERADE
    iptables --append FORWARD --in-interface ${OVS_TRUNK_INTERFACE} -j ACCEPT
    
    iptables -S
    iptables -S --table nat
 
    sysctl -w net.ipv4.ip_forward=1

    set_manager_connect # TODO: Remove when manager connection is dynamically initiated.

    echo "END bootstrap.sh -------------------------------------------------------------"
  } 2>&1 | logger -t ${TAG}
}

main
exit 0

