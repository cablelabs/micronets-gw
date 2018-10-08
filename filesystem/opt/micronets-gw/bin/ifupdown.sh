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
    ovs-vsctl --timeout=5 "$@"
}

ovs_ofctl() {
    debug_log "running: ovs-ofctl $@"
    ovs-ofctl --timeout=5 "$@"
}

clear_iptables() {
    iptables --flush
    iptables --delete-chain
    iptables --table nat --flush
    iptables --table nat --delete-chain
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
    iptables --append FORWARD --in-interface ${UPLINK_INTERFACE} -j ACCEPT
    iptables --table nat --append POSTROUTING --out-interface ${BRIDGE_INTERFACE} -j MASQUERADE
    sysctl -w net.ipv4.ip_forward=1
}

dump_iptables() {
    iptables -L -v
    iptables -L -v --table nat
}

is_mac_addr() {
    [ $(echo "$@" | sed -E 's/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/foundamac/g') = "foundamac" ]
}

if (ovs_vsctl --version) > /dev/null 2>&1; then :; else
    exit 0
fi

if /etc/init.d/openvswitch-switch status > /dev/null 2>&1; then
    debug_log "openvswitch-switch service already started"
else
    debug_log "starting openvswitch-switch service"
    # NOTE: This assumes that this script will start OVS (and start it only once)
    #       It would probably be more correct to reset the DB via the OVS startup script
    reset_ovsdb
    /etc/init.d/openvswitch-switch start
fi

if [ "${MODE}" = "start" ]; then
    eval OVS_EXTRA=\"${IF_OVS_EXTRA}\"

    case "${IF_OVS_TYPE}" in
        OVSBridge)
                clear_iptables ${IFACE}
                ovs_vsctl -- --may-exist add-br ${IFACE} ${IF_OVS_OPTIONS}\
                    ${IF_OVS_MANAGER+-- set-manager $IF_OVS_MANAGER} \
                    ${IF_OVS_PROTOCOLS+-- set bridge ${IFACE} protocols=$IF_OVS_PROTOCOLS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                if [ -z "${IF_OVS_BRIDGE_UPLINK_PORT}" ]; then
                    debug_log "Error: ovs_bridge_uplink_port entry missing for OVSBridge ${IFACE} declaration!"
                else
                    mac_addr=$(/sbin/ethtool -P "${IF_OVS_BRIDGE_UPLINK_PORT}" | cut -b 20-37)
                    if is_mac_addr $mac_addr; then
                        ovs_vsctl set bridge ${IFACE} other-config:hwaddr="${mac_addr}"
                        clear_iptables
                        config_iptables_bridge_uplink ${IFACE} ${IF_OVS_BRIDGE_UPLINK_PORT}
                    else
                        debug_log "Invalid MAC address found for ${IF_OVS_BRIDGE_UPLINK_PORT} in ovs_bridge_uplink_port entry of OVSBridge ${IFACE} declaration (\"$mac_addr\")"
                    fi
                fi

                if [ ! -z "${IF_OVS_PORTS}" ]; then
                    ifup --allow=${IFACE} ${IF_OVS_PORTS}
                fi

                # Clear ALL Flows and set NORMAL .aka L2 Learning switch mode.
                ovs_ofctl del-flows ${IFACE}
                ovs_ofctl add-flow ${IFACE} "table=0 priority=0 actions=normal"
                ;;

        OVSPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    ${IFACE} ${IF_OVS_OPTIONS} \
                    ${IF_OVS_PORT_REQ+-- set Interface ${IFACE} ofport_request=${IF_OVS_PORT_REQ}} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                ip link set ${IFACE} up
                ;;
        OVSIntPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    ${IFACE} ${IF_OVS_OPTIONS} -- set Interface ${IFACE}\
                    type=internal ${OVS_EXTRA+-- $OVS_EXTRA}

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
