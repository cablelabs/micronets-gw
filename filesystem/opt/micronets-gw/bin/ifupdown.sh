#! /bin/sh

# Copyright (c) 2012, 2013 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Have a look at /usr/share/doc/openvswitch-switch/README.Debian
# for more information about configuring the /etc/network/interfaces.

debug_log() {
    logger -t "micronets-ovs-ifupdown" -- "$@"
}

if [ -z "${IF_OVS_TYPE}" ]; then
    exit 0
fi

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
  debug_log "Deleting ovs db at ${OVS_DB_CONF}"
  rm -fv "${OVS_DB_CONF}"
  ovsdb-tool create "${OVS_DB_CONF}" "${OVS_DB_SCHEMA}"
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
    /sbin/sysctl -w net.ipv4.ip_forward=1
}

# This is a temporary work-around to enable the forwarding of DPP Presence Announcements
#  from the wifi driver into hostapd. The driver-level commands to enable the forwarding of
#  these wifi broadcast packets (NL80211_EXT_FEATURE_MULTICAST_REGISTRATIONS) in the 
#  ATH9K driver isn't currently included in a lot of kernel distros (for Rasp Pi, kernel 
#  version 5.10+ is required)
enable_wifi_monitor_mode() {
    WIPHY_DEV=phy0
    WIPHY_MON_DEV=wifimon0
    if ifconfig $WIPHY_MON_DEV > /dev/null; then
        debug_log "Monitor mode already enabled on $WIPHY_DEV (monitor device $WIPHY_MON_DEV)"
    else
        debug_log "Enabling monitor mode on $WIPHY_DEV (monitor device $WIPHY_MON_DEV)"
        iw phy $WIPHY_DEV interface add $WIPHY_MON_DEV type monitor
        ifconfig $WIPHY_MON_DEV up
    fi
}

dump_iptables() {
    iptables -L -v
    iptables -L -v --table nat
}

is_mac_addr() {
    [ $(echo "$@" | sed -E 's/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/foundamac/g') = "foundamac" ]
}

debug_log "running micronets $0 (${MODE})"

if (ovs_vsctl --version) > /dev/null 2>&1; then :; else
    exit 0
fi

if /etc/init.d/openvswitch-switch status > /dev/null 2>&1; then
    debug_log "openvswitch-switch service already started"
else
    # NOTE: This assumes that this script will start OVS (and start it only once)
    #       It would probably be more correct to reset the DB via the OVS startup script.
    #       Also make sure that READ_INTERFACES=no is set in /etc/default/openvswitch-switch
    reset_ovsdb
    debug_log "starting openvswitch-switch service..."
    /etc/init.d/openvswitch-switch start
    debug_log "completed /etc/init.d/openvswitch-switch start."
fi

enable_wifi_monitor_mode

if [ "${MODE}" = "start" ]; then
    eval OVS_EXTRA=\"${IF_OVS_EXTRA}\"

    case "${IF_OVS_TYPE}" in
        OVSBridge)
                clear_iptables ${IFACE}
                ovs_vsctl -- --may-exist add-br ${IFACE} ${IF_OVS_OPTIONS} \
                    ${IF_OVS_MANAGER+-- set-manager $IF_OVS_MANAGER} \
                    ${IF_OVS_PROTOCOLS+-- set bridge ${IFACE} protocols=$IF_OVS_PROTOCOLS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                # Delete any/all flows for the bridge
                ovs_ofctl del-flows ${IFACE}

                if [ ! -z "${IF_OVS_BRIDGE_MAC}" ]; then
                    if is_mac_addr ${IF_OVS_BRIDGE_MAC}; then
                        ovs_vsctl set bridge ${IFACE} other-config:hwaddr="${IF_OVS_BRIDGE_MAC}"
                    else
                        debug_log "ERROR: Invalid MAC address found for ovs_bridge_mac of OVSBridge ${IFACE} declaration (\"${IF_OVS_BRIDGE_MAC}\")"
                    fi
                fi

                if [ -z "${IF_OVS_BRIDGE_UPLINK_PORT}" ]; then
                    debug_log "Warning: ovs_bridge_uplink_port entry missing for OVSBridge ${IFACE} declaration"
                else
                    clear_iptables
                    config_iptables_bridge_uplink ${IFACE} ${IF_OVS_BRIDGE_UPLINK_PORT}
                fi

                if [ ! -z "${IF_OVS_PORTS}" ]; then
                    ifup --allow=${IFACE} ${IF_OVS_PORTS}
                fi

                # Disable ICMP redirects on the bridge interface (so hosts aren't directed to find each other)
                /sbin/sysctl -w net.ipv4.conf.${IFACE}.send_redirects=0
                # /sbin/sysctl -w net.ipv6.conf.${IFACE}.send_redirects=0

                # NORMAL flow .aka L2 Learning switch mode.
                ovs_ofctl add-flow ${IFACE} "table=0 priority=0 actions=NORMAL"
                ;;

        OVSPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    ${IFACE} ${IF_OVS_OPTIONS} \
                    ${IF_OVS_PORT_REQ+-- set Interface ${IFACE} ofport_request=${IF_OVS_PORT_REQ}} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                if [ "${IF_OVS_PORT_INITIAL_STATE}" = "blocked" ]; then
                    if [ -z "${IF_OVS_PORT_REQ}" ]; then
                        debug_log "Error: ovs_port_initial_state entry requires a ovs_port_req entry"
                    else
                        # Setup a flow to block all traffic to the port (until a controller is connected)
                        debug_log "Setting initial state of ${IFACE} (port ${IF_OVS_PORT_REQ}) to blocked"
                        ovs_ofctl add-flow "${IF_OVS_BRIDGE}" "table=0 priority=10 in_port=${IF_OVS_PORT_REQ} actions=drop"
                    fi
                fi

                if [ "${IF_OVS_PORT_INITIAL_STATE}" = "bridged" ]; then
                    if [ -z "${IF_OVS_PORT_REQ}" ]; then
                        debug_log "Error: ovs_port_initial_state entry requires a ovs_port_req entry"
                    else
                        # Setup a flow to allow all traffic to the port (until a controller is connected)
                        debug_log "Setting initial state of ${IFACE} (port ${IF_OVS_PORT_REQ}) to bridged"
                        ovs_ofctl add-flow "${IF_OVS_BRIDGE}" "table=0 priority=10 in_port=${IF_OVS_PORT_REQ} actions=NORMAL"
                    fi
                fi

                ip link set ${IFACE} up
                ;;
        OVSIntPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    ${IFACE} ${IF_OVS_OPTIONS} \
                    -- set Interface ${IFACE} ${IF_OVS_PORT_REQ+ ofport_request=${IF_OVS_PORT_REQ}} type=internal \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                if [ "${IF_OVS_PORT_INITIAL_STATE}" = "blocked" ]; then
                    if [ -z "${IF_OVS_PORT_REQ}" ]; then
                        debug_log "Error: ovs_port_initial_state entry requires a ovs_port_req entry"
                    else
                        # Setup a flow to block all traffic to the port (until a controller is connected)
                        debug_log "Setting initial state of ${IFACE} (port ${IF_OVS_PORT_REQ}) to blocked"
                        ovs_ofctl add-flow "${IF_OVS_BRIDGE}" "table=0 priority=10 in_port=${IF_OVS_PORT_REQ} actions=drop"
                    fi
                fi

                if [ "${IF_OVS_PORT_INITIAL_STATE}" = "bridged" ]; then
                    if [ -z "${IF_OVS_PORT_REQ}" ]; then
                        debug_log "Error: ovs_port_initial_state entry requires a ovs_port_req entry"
                    else
                        # Setup a flow to block all traffic to the port (until a controller is connected)
                        debug_log "Setting initial state of ${IFACE} (port ${IF_OVS_PORT_REQ}) to bridged"
                        ovs_ofctl add-flow "${IF_OVS_BRIDGE}" "table=0 priority=10 in_port=${IF_OVS_PORT_REQ} actions=NORMAL"
                    fi
                fi

                ip link set ${IFACE} up
                ;;
        OVSBond)
                ovs_vsctl -- --fake-iface add-bond "${IF_OVS_BRIDGE}"\
                    ${IFACE} ${IF_OVS_BONDS} ${IF_OVS_OPTIONS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                ip link set ${IFACE} up
                for slave in ${IF_OVS_BONDS}
                do
                    ip link set ${IFACE} up
                done
                ;;
        OVSPatchPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    ${IFACE} ${IF_OVS_OPTIONS} -- set Interface ${IFACE} \
                    type=patch options:peer="${IF_OVS_PATCH_PEER}" \
                    ${OVS_EXTRA+-- $OVS_EXTRA}
                ;;
        OVSTunnel)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    ${IFACE} ${IF_OVS_OPTIONS} -- set Interface ${IFACE} \
                    type=${IF_OVS_TUNNEL_TYPE} ${IF_OVS_TUNNEL_OPTIONS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}
                ;;
        *)
                exit 0
                ;;
    esac
elif [ "${MODE}" = "stop" ]; then
    case "${IF_OVS_TYPE}" in
        OVSBridge)
                if [ ! -z "${IF_OVS_PORTS}" ]; then
                    ifdown --allow=${IFACE} ${IF_OVS_PORTS}
                fi

                ovs_vsctl -- --if-exists del-br ${IFACE}
                ;;
        OVSPort|OVSIntPort|OVSBond|OVSPatchPort|OVSTunnel)
                ovs_vsctl -- --if-exists del-port ${IF_OVS_BRIDGE} ${IFACE}
                ;;
        *)
                exit 0
                ;;
    esac
fi

exit 0
