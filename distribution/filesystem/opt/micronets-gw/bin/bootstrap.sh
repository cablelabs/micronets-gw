#!/bin/bash -x

TS=`date +%j'T'%H%M%S`

CWD=/opt/micronets-gw/bin

source /etc/openvswitch/ovs.conf
source ${CONFDIR}/bootstrap.conf

TAG=${LOGGER_TAG}-${TS}


function hr {
  echo "------------------------------------------------------------------------------------------------------"
}

function show {
  hr
  ip addr
  ip link
  ip route
  hr
  $OVS_BIN_DIR/ovs-vsctl --db=$OVSDB_CONNECT_SOCKET show
  $OVS_BIN_DIR/ovs-appctl bridge/dump-flows $BRIDGE
  $OVS_BIN_DIR/ovs-dpctl -m dump-flows
  $OVS_BIN_DIR/ovs-dpctl show
  hr
}

function set_manager_connect {
 $OVS_BIN_DIR/ovs-vsctl --db=$OVSDB_CONNECT_SOCKET set-manager $OVSDB_MANAGER_CONNECT_SOCKET
}

function main {
  {
    # $CWD/resetdb.sh

    show

    $CWD/normal.sh $BRIDGE
    show

    iptables --flush
    iptables --table nat --flush
    iptables --delete-chain
    iptables --table nat --delete-chain
    iptables --table nat --append POSTROUTING --out-interface ${BRIDGE} -j MASQUERADE
    iptables --append FORWARD --in-interface ${TRUNK_INTERFACE} -j ACCEPT
    
    iptables -S
    iptables -S --table nat
 
    sysctl -w net.ipv4.ip_forward=1

    set_manager_connect

    echo "END bootstrap.sh -------------------------------------------------------------"
  } 2>&1 | logger -t ${TAG}
}

echo "BOOTSTRAP LOGGER TAG: ${TAG}"
echo "alias lastboot=\"grep '${TAG}' /var/log/syslog | less\""
main
exit 0

