#!/bin/bash -x

if [ "xx${OVSDB_CONNECT_SOCKET}yy" == "xxyy" ]; then
  source /etc/openvswitch/ovs.conf
fi

systemctl stop ovs-vswitchd.service
systemctl stop ovs-ovsdb.service

rm $OVS_DB_CONF
$OVS_BIN_DIR/ovsdb-tool create $OVS_DB_CONF $OVS_INSTALL_DIR/share/openvswitch/vswitch.ovsschema

systemctl start ovs-ovsdb.service
systemctl start ovs-vswitchd.service

