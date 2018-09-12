#!/bin/bash

source /etc/openvswitch/ovs.conf

OVS_BRIDGE=$1

#===============================================================================
# Clear All Existing Flows

$OVS_BIN_DIR/ovs-ofctl del-flows $OVS_BRIDGE

$OVS_BIN_DIR/ovs-ofctl add-flow $OVS_BRIDGE "table=0 priority=0 actions=normal"

