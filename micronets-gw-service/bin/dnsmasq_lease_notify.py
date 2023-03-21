#!/usr/bin/env python3

import os
import sys
import http.client, urllib.parse
import json
import logging
import pathlib

# See the documentation for the "--dhcp-script" option for details on how this script is invoked
#  buy dnsmasq (see http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)

lease_notifiction_host = "localhost:5000"
lease_notification_method = "PUT"
lease_notification_path = "/gateway/v1/dhcp-leases"
# Define the path to the named pipe
fifo_path = "/var/run/diplomat/leases"

bindir = os.path.dirname (os.path.abspath (sys.argv [0]))
logging_filename = pathlib.Path(bindir).parent.joinpath("micronets-gw.log")
print (f"logging output to {logging_filename}")

logging_filemode = 'a'
logging_level = logging.DEBUG
logging.basicConfig (level=logging_level, filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')

logger = logging.getLogger ('dnsmasq-lease-notify')

def get_env (var_name):
    env = os.environ
    if not var_name in env:
        return None
    else:
        return env [var_name]

def post_lease_event (event_json):
    conn = http.client.HTTPConnection (lease_notifiction_host)
    headers = {"Content-Type": "application/json"}
    conn.request (lease_notification_method, lease_notification_path, event_json, headers)
    return conn.getresponse ()

if __name__ == '__main__':
    logger.info (f"{__file__} invoked with arguments: {sys.argv}")
    program = sys.argv [0]
    action = sys.argv [1]
    mac_address = sys.argv [2]
    ip_address = sys.argv [3]
    hostname = sys.argv [4]
    logger.debug ("{}: action: {}, mac_address: {}, ip_address {}, hostname {}"
                       .format (program, action, mac_address, ip_address, hostname))
    logger.debug ("PWD: {}".format (get_env ('PWD')))
    logger.debug ("DNSMASQ_LEASE_LENGTH: {}".format (get_env ('DNSMASQ_LEASE_LENGTH')))
    logger.debug ("DNSMASQ_LEASE_EXPIRES: {}".format (get_env ('DNSMASQ_LEASE_EXPIRES')))
    logger.debug ("DNSMASQ_TIME_REMAINING: {}".format (get_env ('DNSMASQ_TIME_REMAINING')))
    logger.debug ("DNSMASQ_SUPPLIED_HOSTNAME: {}".format (get_env ('DNSMASQ_SUPPLIED_HOSTNAME')))
    logger.debug ("DNSMASQ_INTERFACE: {}".format (get_env ('DNSMASQ_INTERFACE')))
    logger.debug ("DNSMASQ_TAGS: {}".format (get_env ('DNSMASQ_TAGS')))
    if action == "old":
        logger.debug(f"Ignoring action {action}")
        exit (0)
    if action == "add":
        lease_change_type = 'leaseAcquired'
        # Open the named pipe for writing
        with open(fifo_path, 'w') as fifo:
            fifo.write(mac_address)
    elif action == "del":
        lease_change_type = "leaseExpired"
    lease_change_event = {"leaseChangeEvent": {
                              "action": lease_change_type,
                              "macAddress": mac_address,
                              "networkAddress": {"ipv4": ip_address},
                              "hostname": hostname}
                         }
    lease_change_event_json = json.dumps (lease_change_event)
    logger.debug ("Sending event: {}".format (lease_change_event_json))

    response = post_lease_event (lease_change_event_json)
    logger.debug ("Received response: {}".format (response.read ()))
