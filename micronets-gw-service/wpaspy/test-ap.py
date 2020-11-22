#!/usr/bin/python
#
# Test script for wpaspy
# Copyright (c) 2013, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import os
import sys
import time
import wpaspy

hostapd_ctrl = '/var/run/hostapd'

def wpas_connect(host=None, port=9877):
    ifaces = []

    if host != None:
        try:
            wpas = wpaspy.Ctrl(host, port)
            return wpas
        except:
            print("Could not connect to host: ", host)
            return None

    if os.path.isdir(hostapd_ctrl):
        try:
            ifaces = [os.path.join(hostapd_ctrl, i) for i in os.listdir(hostapd_ctrl)]
        except OSError as error:
            print("Could not find hostapd", error)
            return None

    if len(ifaces) < 1:
        print("No hostapd control interface found")
        return None

    for ctrl in ifaces:
        try:
            wpas = wpaspy.Ctrl(ctrl)
            return wpas
        except Exception as e:
            pass
    return None


def main(host=None, port=9877):
    print("Testing hostapd control interface connection")
    wpas = wpas_connect(host, port)
    if wpas is None:
        return
    wpas.attach()
    print("Connected to hostapd")
    print(wpas.send_cmd_wait('PING'))

    # mon = wpas_connect(host, port)
    # if mon is None:
    #     print("Could not open event monitor connection")
    #     return
    # mon.attach()

    print("status")
    print(wpas.send_cmd_wait('STATUS'))
    time.sleep(1)
    print("dpp_configurator_add")
    print(wpas.send_cmd_wait('DPP_CONFIGURATOR_ADD'))
    time.sleep(1)
    print("dpp_configurator_sign")
    wpas.send_cmd('DPP_CONFIGURATOR_SIGN conf=ap-dpp configurator=1')

    count = 0
    while count < 1000:
        count += 1
        time.sleep(1)
        while wpas.pending():
            ev = wpas.recv()
            print("RECEIVED:")
            print(ev)

if __name__ == "__main__":
    if len(sys.argv) > 2:
        main(host=sys.argv[1], port=int(sys.argv[2]))
    else:
        main()
