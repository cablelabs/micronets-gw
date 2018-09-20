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

is_mac_addr() {
    [ $(echo "$@" | sed -E 's/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/foundamac/g') = "foundamac" ]
}

if (ovs_vsctl --version) > /dev/null 2>&1; then :; else
    exit 0
fi

if /etc/init.d/openvswitch-switch status > /dev/null 2>&1; then :; else
    debug_log "starting openvswitch-switch service"
    /etc/init.d/openvswitch-switch start
fi

if [ "${MODE}" = "start" ]; then
    eval OVS_EXTRA=\"${IF_OVS_EXTRA}\"

    case "${IF_OVS_TYPE}" in
        OVSBridge)
                ovs_vsctl -- --may-exist add-br "${IFACE}" ${IF_OVS_OPTIONS}\
                    ${IF_OVS_MANAGER+-- set-manager $IF_OVS_MANAGER} \
                    ${IF_OVS_PROTOCOLS+-- set bridge ${IFACE} protocols=$IF_OVS_PROTOCOLS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                if [ ! -z "${IF_OVS_BRIDGE_ASSUME_MAC}" ]; then
                    # TODO: Consider allowing either an interface name or explicit MAC addr
                    mac_addr=$(/sbin/ethtool -P "${IF_OVS_BRIDGE_ASSUME_MAC}" | cut -b 20-37)
                    if is_mac_addr $mac_addr; then
                        ovs_vsctl set bridge "${IFACE}" other-config:hwaddr="${mac_addr}"
                    else
                        debug_log "Invalid MAC address found for ${IF_OVS_BRIDGE_ASSUME_MAC} in ovs_bridge_assume_mac entry of OVSBridge declaration (\"$mac_addr\")"
                    fi
                fi

                if [ ! -z "${IF_OVS_PORTS}" ]; then
                    ifup --allow="${IFACE}" ${IF_OVS_PORTS}
                fi
                ;;
        OVSPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_OPTIONS} \
                    ${IF_OVS_PORT_REQ+-- set Interface ${IFACE} ofport_request=$IF_OVS_PORT_REQ} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}
                if [ "T${IF_OVS_BRIDGE_ASSUME_MAC}" = "Ttrue" ]; then
                    mac_addr=$(/sbin/ethtool -P "${IFACE}" | cut -b 20-37)
                    if is_mac_addr $mac_addr; then
                        ovs_vsctl set bridge "${IF_OVS_BRIDGE}" other-config:hwaddr="${mac_addr}"
                    else
                        debug_log "Found invalid MAC address (\"$mac_addr\") in ovs_bridge_assume_mac entry of OVSBridge declaration"
                    fi
                else
                    debug_log "unrecognized ovs_bridge_assume_mac value for ${IFACE}: \"${IF_OVS_BRIDGE_ASSUME_MAC}\""
                fi

                ip link set "${IFACE}" up
                ;;
        OVSIntPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_OPTIONS} -- set Interface "${IFACE}"\
                    type=internal ${OVS_EXTRA+-- $OVS_EXTRA}

                ip link set "${IFACE}" up
                ;;
        OVSBond)
                ovs_vsctl -- --fake-iface add-bond "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_BONDS} ${IF_OVS_OPTIONS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                ip link set "${IFACE}" up
                for slave in ${IF_OVS_BONDS}
                do
                    ip link set "${IFACE}" up
                done
                ;;
        OVSPatchPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_OPTIONS} -- set Interface "${IFACE}" \
                    type=patch options:peer="${IF_OVS_PATCH_PEER}" \
                    ${OVS_EXTRA+-- $OVS_EXTRA}
                ;;
        OVSTunnel)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_OPTIONS} -- set Interface "${IFACE}" \
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
                    ifdown --allow="${IFACE}" ${IF_OVS_PORTS}
                fi

                ovs_vsctl -- --if-exists del-br "${IFACE}"
                ;;
        OVSPort|OVSIntPort|OVSBond|OVSPatchPort|OVSTunnel)
                ovs_vsctl -- --if-exists del-port "${IF_OVS_BRIDGE}" "${IFACE}"
                ;;
        *)
                exit 0
                ;;
    esac
fi

exit 0
