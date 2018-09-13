#!/bin/bash

source /etc/openvswitch/ovs.conf

#===============================================================================
# Clear All Existing Flows

ovs-ofctl del-flows ${OVS_BRIDGE_INTERFACE}

# TODO: Add DHCP <F7>Isolation Flows Here, priority>0
# TODO: Add "other" Flows Here, priority>0

ovs-ofctl add-flow ${OVS_BRIDGE_INTERFACE} "table=0 priority=0 actions=normal"

