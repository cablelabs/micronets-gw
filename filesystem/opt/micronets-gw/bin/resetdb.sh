#!/bin/bash -x

OVS_DB_CONF=/etc/openvswitch/conf.db
OVS_DB_SCHEMA=/usr/share/openvswitch/vswitch.ovsschema

systemctl stop openvswitch-switch.service

rm $OVS_DB_CONF
ovsdb-tool create $OVS_DB_CONF $OVS_DB_SCHEMA

systemctl start openvswitch-switch.service

