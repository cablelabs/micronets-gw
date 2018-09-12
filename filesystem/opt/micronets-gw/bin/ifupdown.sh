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

export PATH=/opt/openvswitch/bin:$PATH

debug_log() {
     logger -t "ovs-ifupdown" -- "$@"
}

if [ -z "${IF_OVS_TYPE}" ]; then
    exit 0
fi

ovs_vsctl() {
    debug_log "running: ovs-vsctl $@"
    /opt/openvswitch/bin/ovs-vsctl --timeout=5 "$@"
}

if (ovs_vsctl --version) > /dev/null 2>&1; then :; else
    exit 0
fi

SERVICE_UNIT=/usr/lib/systemd/system/openvswitch-nonetwork.service
if [ -f $SERVICE_UNIT ] && [ -x /usr/bin/systemctl ]; then
    if ! systemctl --quiet is-active openvswitch-nonetwork.service; then
        debug_log "starting openvswitch-nonetwork.service"
        systemctl start openvswitch-nonetwork.service
    fi
else
    if service openvswitch-switch status > /dev/null 2>&1; then
        debug_log "starting service openvswitch-switch"
        service openvswitch-switch start
    fi
fi

debug_log "MODE: ${MODE}"
if [ "${MODE}" = "start" ]; then
    eval OVS_EXTRA=\"${IF_OVS_EXTRA}\"

    debug_log "IF_OVS_TYPE: ${IF_OVS_TYPE}"
    debug_log "IFACE: ${IFACE}"
    debug_log "IF_OVS_EXTRA: ${IF_OVS_EXTRA}"
    debug_log "IF_OVS_BRIDGE: ${IF_OVS_BRIDGE}"
    debug_log "IF_OVS_PORTS: ${IF_OVS_PORTS}"
    debug_log "IF_OVS_MANAGER: ${IF_OVS_MANAGER}"
    debug_log "IF_OVS_PROTOCOLS: ${IF_OVS_PROTOCOLS}"
    debug_log "IF_OVS_PORT_REQ: ${IF_OVS_PORT_REQ}"
    case "${IF_OVS_TYPE}" in
        OVSBridge)
                ovs_vsctl -- --may-exist add-br "${IFACE}" ${IF_OVS_OPTIONS}\
                         ${IF_OVS_MANAGER+-- set-manager $IF_OVS_MANAGER} \
                         ${IF_OVS_PROTOCOLS+-- set bridge ${IFACE} protocols=$IF_OVS_PROTOCOLS} \
                         ${OVS_EXTRA+-- $OVS_EXTRA}

                if [ ! -z "${IF_OVS_PORTS}" ]; then
                    ifup --allow="${IFACE}" ${IF_OVS_PORTS}
                fi
                ;;
        OVSPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_OPTIONS} \
                    ${IF_OVS_PORT_REQ+-- set Interface ${IFACE} ofport_request=$IF_OVS_PORT_REQ} \
                    ${OVS_EXTRA+-- $OVS_EXTRA} 

                ifconfig "${IFACE}" up
                ;;
        OVSIntPort)
                ovs_vsctl -- --may-exist add-port "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_OPTIONS} -- set Interface "${IFACE}"\
                    type=internal ${OVS_EXTRA+-- $OVS_EXTRA}

                ifconfig "${IFACE}" up
                ;;
        OVSBond)
                ovs_vsctl -- --fake-iface add-bond "${IF_OVS_BRIDGE}"\
                    "${IFACE}" ${IF_OVS_BONDS} ${IF_OVS_OPTIONS} \
                    ${OVS_EXTRA+-- $OVS_EXTRA}

                ifconfig "${IFACE}" up
                for slave in ${IF_OVS_BONDS}
                do
                    ifconfig "${slave}" up
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
