#!/usr/bin/env python3

import os
import sys
import http.client, urllib.parse
import json

from pathlib import Path

def get_env (var_name):
    env = os.environ
    if not var_name in env:
        return None
    else:
        return env [var_name]

def post_lease_event (event_json):
    conn = http.client.HTTPConnection ("localhost:5000")
    headers = {"Content-Type": "application/json"}
    conn.request ("PUT", "/micronets/v1/dhcp/leases", event_json, headers)
    return conn.getresponse ()

if __name__ == '__main__':
    print ("Running dnsmasq_lease_notify: ", sys.argv)
    logfile_path = Path ("/tmp/micronets_dnsmasq_lease_notify.log")
    program = sys.argv [0]
    action = sys.argv [1]
    mac_address = sys.argv [2]
    ip_address = sys.argv [3]
    hostname = sys.argv [4]
    with logfile_path.open ('a') as logfile:
        logfile.write ("{}: action: {}, mac_address: {}, ip_address {}, hostname {}\n"
                       .format (program, action, mac_address, ip_address, hostname))
        logfile.write ("PWD: {}\n".format (get_env ('PWD')))
        logfile.write ("DNSMASQ_LEASE_LENGTH: {}\n".format (get_env ('DNSMASQ_LEASE_LENGTH')))
        logfile.write ("DNSMASQ_LEASE_EXPIRES: {}\n".format (get_env ('DNSMASQ_LEASE_EXPIRES')))
        logfile.write ("DNSMASQ_TIME_REMAINING: {}\n".format (get_env ('DNSMASQ_TIME_REMAINING')))
        logfile.write ("DNSMASQ_SUPPLIED_HOSTNAME: {}\n".format (get_env ('DNSMASQ_SUPPLIED_HOSTNAME')))
        logfile.write ("DNSMASQ_INTERFACE: {}\n".format (get_env ('DNSMASQ_INTERFACE')))
        logfile.write ("DNSMASQ_TAGS: {}\n".format (get_env ('DNSMASQ_TAGS')))
        if (action == "old"):
            exit (0)
        lease_change_event = {"macAddress": {"eui48": mac_address},
                              "networkAddress": {"ipv4": ip_address},
                              "hostname": hostname}
        if (action == "add"):
            lease_change_event ['event'] = "leaseAcquired"
        if (action == "del"):
            lease_change_event ['event'] = "leaseExpired"
        lease_change_event_json = json.dumps (lease_change_event)
        logfile.write ("Sending event: {}\n".format (lease_change_event_json))

        response = post_lease_event (lease_change_event_json)
        logfile.write ("Received response: {}\n".format (response.read ()))
