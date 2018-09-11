#!/bin/bash -x

TS=`date +%j'T'%H%M%S`

CWD=/opt/ovs-bootstrap/bin

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

function kill_dhclient {
# $1 = <trunk interface>
perl << 'EOF' - $1
use strict;
use diagnostics;

my $interface = $ARGV[0];
my $dhclient_bin = `which dhclient`;
chomp $dhclient_bin;
if (defined($interface) && length($interface) > 0) {
  print "Searching for dhclient executable \"$dhclient_bin\" handling interface \"$interface\".\n";
  my $ifh;
  open($ifh, "ps aux |") or die("Unable to open grepping pipe!");
  wloop: while (my $line = <$ifh>) {
    chomp $line;
    if ($line =~ m|$dhclient_bin| && $line =~ m|$interface|) {
      if ($line =~ m|\S+\s+(\d+)\s+.+|) {
        my $pid = $1;
        print "Killing dhclient process PID:$pid\n";
        kill 'SIGINT', ($pid);
        exit 0;
      } else {
        die("Located line in ps output, but Unable to parse PID!\nLINE: $line\n");
      }
    }
  }
} else {
  die("Interface name required as first parameter");
}
EOF
}

function trunk_port {
# $1 = <bridge>
# $2 = <trunk interface>
# $3 = <ofport request>
  kill_dhclient $2
  ip address flush dev $2
  $OVS_BIN_DIR/ovs-vsctl --db=$OVSDB_CONNECT_SOCKET --may-exist add-br   $1 -- set bridge $1 protocols=OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13
  $OVS_BIN_DIR/ovs-vsctl --db=$OVSDB_CONNECT_SOCKET --may-exist add-port $1 ${2}   -- set Interface ${2}   ofport_request=$3
  ip link set dev ${1} up
  ip link set dev ${2} up
}

function trunk_dhclient {
# $1 = <trunk interface>
   /sbin/dhclient -1 -v -pf /run/dhclient.${1}.pid -lf /var/lib/dhcp/dhclient.${1}.leases -I -df /var/lib/dhcp/dhclient6.${1}.leases ${1}
#  dhclient ${1} 	# Get IP address assignment on aliased trunk interface via DHCP, not on trunk interface>!
}

function access_port {
# $1 = <bridge>
# $2 = <interface>
# $3 = <ofport_request>
# $4 = <subnet #>
  ip address flush dev ${2}
  $OVS_BIN_DIR/ovs-vsctl --db=$OVSDB_CONNECT_SOCKET --may-exist add-port ${1} ${2}   -- set Interface ${2}   ofport_request=${3}
  ip link set dev ${2} up
  ip address add 192.168.${4}.1/24 dev ${1}
}

function set_manager_connect {
 $OVS_BIN_DIR/ovs-vsctl --db=$OVSDB_CONNECT_SOCKET set-manager $OVSDB_MANAGER_CONNECT_SOCKET
}

function main {
  {
    echo "BEGIN bootstrap.sh -------------------------------------------------------------"

#    systemctl stop isc-dhcp-server.service
#    systemctl status isc-dhcp-server.service
 #   systemctl status hostapd.service

    $CWD/resetdb.sh

    show
    trunk_port $BRIDGE $TRUNK_INTERFACE 1 

    ACOUNT=`echo ${ACCESS_IFACES[@]} | wc -w`

    for (( i=0; i<$ACOUNT; i++ )); do
      echo "I=$i"
      AIFACE=${ACCESS_IFACES[i]}
      APORT=${ACCESS_PORTS[i]}
      ASUBNET=${ACCESS_SUBNETS[i]}
      access_port $BRIDGE $AIFACE $APORT $ASUBNET
    done
    show
    $OVS_BIN_DIR/ovs-vsctl --db=$OVSDB_CONNECT_SOCKET set bridge $BRIDGE other-config:hwaddr=02:AD:DE:AD:BE:EF
    show

    /opt/ifrest/ovsinit/genports | tee ports.conf

    $CWD/normal.sh $BRIDGE
    show

    trunk_dhclient $TRUNK_INTERFACE

    iptables --flush
    iptables --table nat --flush
    iptables --delete-chain
    iptables --table nat --delete-chain
    iptables --table nat --append POSTROUTING --out-interface ${BRIDGE} -j MASQUERADE
    iptables --append FORWARD --in-interface ${TRUNK_INTERFACE} -j ACCEPT
    
    iptables -S
    iptables -S --table nat
 
    sysctl -w net.ipv4.ip_forward=1

#    systemctl restart isc-dhcp-server.service
#    systemctl status isc-dhcp-server.service
#    systemctl status hostapd.service

    set_manager_connect

    echo "END bootstrap.sh -------------------------------------------------------------"
  } 2>&1 | logger -t ${TAG}
}

echo "BOOTSTRAP LOGGER TAG: ${TAG}"
echo "alias lastboot=\"grep '${TAG}' /var/log/syslog | less\""
main
exit 0

