# Micronets Gateway Service README

The Micronets Gateway incorporates a number of components necessary for creating and managing Micronets on the gateway, on-boarding devices, and for enforcing Micronets policy. 

In particular, this repository includes:

* Plug-in logic for the ifup/down subsystem - which allows the `/etc/network/interfaces` file to be annotated with Micronets-specific keywords. This mostly includes directives for configuring interfaces and bridges with OpenVSwitch at boot-up.
* The Micronets Gateway Service - which is used to manage the connection with the Micronets Manager, provide REST endpoints for direct or websocket-based invocation, configure the DHCP server (dnsmasq or ISC DHCP), configure network resources for the hostapd service, and issue openVSwitch/OpenFlow commands to enforce Micronet- and device-level policy.
* Logic for creating a Debian installer files

## Development Setup

To setup a dev environment for the Micronets gateway service, run the following steps:

```
cd ~/projects/micronets
git clone git@github.com:cablelabs/micronets-gw.git
cd micronets-gw/micronets-gw-service
mkvirtualenv -r requirements.txt -a $PWD -p $(which python3) micronets-gw-service
workon micronets-gw-service
```

## Dependencies

Note that this package requires Python 3.6 and the virtualenv wrapper packages to be installed.

For Ubuntu Linux, the virtualenvwrapper can be installed using:
```
sudo apt-get install virtualenvwrapper
source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
```

and Python 3.6 can be installed by running `sudo apt-get install python3.6` on Ubuntu 16.10+. For Ubuntu 16.04, follow the instructions here:

```
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install python3.6
```

For the Mac, the virtualenvwrapper can be installed by installing macports (see https://www.macports.org/install.php) and then running:

```
sudo port install py-virtualenvwrapper
sudo port select --set python python27
sudo port select --set python3 python36
```
and adding these to your ~/.bash_profile:

```
export VIRTUALENVWRAPPER_PYTHON='/opt/local/bin/python2.7'
export VIRTUALENVWRAPPER_VIRTUALENV='/opt/local/bin/virtualenv-2.7'
export VIRTUALENVWRAPPER_VIRTUALENV_CLONE='/opt/local/bin/virtualenv-clone-2.7'
source /opt/local/bin/virtualenvwrapper.sh-2.7
```

## Development Testing

If you want to access the REST API directly - running against the mock gateway adapter, use:

```
MICRONETS_GW_SERVICE_CONFIG=config.MockDevelopmentConfig python ./runner.py
```

If you want to have the DHCP service connect to a websocket for access to the REST API and to receive notifications,
configure the WEBSOCKET_SERVER_ADDRESS, WEBSOCKET_SERVER_PORT, and WEBSOCKET_SERVER_PATH to point to the websocket
endpoint. Note that currently only wss is supported (TLS). So the WEBSOCKET_TLS_CERTKEY_FILE must refer to a cert
and corresponding private key that the server trusts - and WEBSOCKET_TLS_CA_CERT_FILE must refer to the certificate
that can be used to verify the authenticity of the websocket server.

In this case, you can start the Micronets gateway service using:

```
MICRONETS_DHCP_CONFIG=config.MockDevelopmentConfigWithWebsocket python ./runner.py
```

To exit the virtual envonment use `deactivate`. You can continue working with the Micronets gateway service by running `workon micronets-gw-service`.

## Micronets Gateway REST Interface

This section contains the general REST API definitions for the Micronets gateway.

All request URIs are prefixed by **/micronets/v1/gateway** unless otherwise noted

See the `testcases.md` document in the `test` directory for examples.

### Micronet API

Micronet device definitions must be made in the context of a Micronet.
The operations defined in this section allow for the management of these Micronets.

#### Gateway Micronet Representation

Note: Currently only data type _application/json_ is supported.

**Micronet Network:**
```json
{
    "micronetId": string,
    "ipv4Network": {
        "network": string,
        "mask": string,
        "gateway": string,
        "broadcast": string
    },
    "nameservers": [
        string
    ],
    "interface": string,
    "vlan": integer,
    "ovsBridge": string
}
```

| Property name            | Value           | Required | Description                           | Example      |
| ------------------------ | --------------- | -------- | ------------------------------------- | ------------- 
| micronetId               | string          | Y        | Unique ID for the Micronet | "192.168.0" |
| ipv4Network              | nested object   | Y        | The definition of a IPv4 network ||
| ipv4Network.network      | string          | Y        | The IPv4 network definition (dotted IP) | "192.168.1.0" |
| ipv4Network.mask         | string          | Y        | The netmask for the network (dotted IP) | "255.255.255.0" |
| ipv4Network.gateway      | string          | N        | The IPv4 address of the network gateway | "192.168.1.1" |
| ipv4Network.broadcast    | string          | N        | The IPv4 address for broadcast | "192.168.1.255" |
| nameservers              | list (string)   | N        | The IP addresses of nameservers for the subnet | ["8.8.8.8", "4.4.4.4"] |
| interface                | string          | Y        | The network interface on the gateway the subnet is associated with | "wlp2s0"
| vlan                     | integer         | N        | The network interface on the gateway the subnet is associated with | "wlp2s0"
| ovsBridge                | string          | Y        | The OpenVSwitch bridge the interface is connected to on the gateway | "brmn001"
| outRules                 | list (object)   | N        | Micronet-Rules for outbound connections for devices in the micronet | “outRules": [{“action": “allow", “dest": “api.acme.com:443/tcp"}]|
| inRules                  | list (object)   | N        | Micronet-Rules for inbound connections for devices in the micronet | “inRules": [{“action": “allow", “source": “20.30.40.0/24", “destPort": “22/tcp"} ]|

##### Notes:
* **inRules** and **outRules** are processed in the order they are defined.
* If **inRules** or **outRules** is non-empty, the default action is "deny"
* If no **outRules** are defined, all outgoing device connections/packets are allowed. 
* If no **inRules** are defined, no inbound connections are allowed other than data related to allowed outgoing connections.

#### Micronet Network Endpoints/Operations

| Method | HTTP request                                     | Description                           |
| ------ | ------------------------------------------------ | ------------------------------------- |
| insert | POST /micronets                | Add a micronet or micronets (if an array of micronets are provided). This will return a status code of 405 (Method Not Allowed) if any of the provided micronet IDs already exist. (no micronets will be added in this case) |
| list   | GET /micronets                   | Return an array of all the defined micronets on the gateway |
| delete | DELETE /micronets                | Deletes all micronet definitions. The operation will return a status code of 405 (Method Not Allowed) if any of the micronets still contain device reservations (no micronets will be deleted in this case). |
| get    | GET /micronets/**_micronetId_**    | Return the specified micronet for **_micronetId_**. This will return 404 (Not Found) if the /**_micronetId_** doesn't exist. |
| update | PUT /micronets/**_micronetId_**    | Update a micronet definition. This will return 400 if the message body contains a **_micronetId_** that doesn't match the **_micronetId_** in the URI path or if the network conflicts with an already-existing network and will return 404 (Not Found) if the **_micronetId_** doesn't exist. |
| delete | DELETE /micronets/**_micronetId_** | Delete a micronet definition. The operation will return a status code of 405 (Method Not Allowed) if the micronet still contains device reservations and will return 404 (Not Found) if the **_micronetId_** doesn't exist. |

### DEVICE ADDRESS RESERVATION

These definitions allow for the management of micronet network devices.
Devices must be defined and exist within the context of a micronet network.

#### Micronet Device Representation

Note: Currently only data type _application/json_ is supported.

**Micronet Device:**
```json
{
    "deviceId": string,
    "macAddress": {
       "eui48": string
    },
    "networkAddress": {
       "ipv4": string,
       "ipv6": string
    },
    "restrictions": [
       object
    ]
}
```

| Property name            | Value         | Required | Description                           | Example      |
| ------------------------ | ------------- | -------- | ------------------------------------- | ------------- 
| deviceId                 | string        | Y        | An alphanumeric device identifier (max 64 characters) | "device-1234"|
| macAddress               | nested object | Y        | The device MAC address
| macAddress.eui48         | string        | Y        | An EUI-48 format MAC address | "00:23:12:0f:b0:26" |
| networkAddress           | nested object | Y        | The network address definition. Either **_ipv4_** or **_ipv6_** must be specified ||
| networkAddress.ipv4      | string        | N        | The IPv4 network definition (dotted IP) | "192.168.1.42" |
| networkAddress.ipv6      | string        | N        | The IPv6 network definition | "fe80::104c:20b6:f71a:4e55" |
| outRules                 | list (object) | N        | Micronet-Rules for outbound connections | “outRules": [{“action": “allow", “dest": “api.acme.com:443/tcp"}]|
| inRules                  | list (object) | N        | Micronet-Rules for inbound connections | “inRules": [{“action": “allow", “source": “20.30.40.0/24", “destPort": “22/tcp"} ]|

##### Notes:
* **inRules** and **outRules** are processed in the order they are defined.
* If **inRules** or **outRules** is non-empty, the default action is "deny"
* If no **outRules** are defined, all outgoing device connections/packets are allowed. 
* If no **inRules** are defined, no inbound connections are allowed other than data related to allowed outgoing connections.
* If **inRules** or **outRules** is defined, it overrides the corresponding definition in the contained micronet 

#### Micronet Device Reservation Endpoints/Operations

All request URIs are prefixed by **/micronets/v1/dhcp** unless otherwise noted

| Method | HTTP request                                     | Description                           |
| ------ | ------------------------------------------------ | ------------------------------------- |
| insert | POST /micronets/**_micronetId_**/devices   | Add a device definition or definitions (if an array of devices are provided) under **_micronetId_**. This will return a status code of 400 if any of the provided **_deviceId_**, **_macAddress_**, or **_networkAddress_** specified in the request body conflicts with an already-defined device reservation (no device reservations will be added in this case). A 404 (Not Found) will be returned if the **_micronetId_** doesn't exist. | |
| list   | GET /micronets/**_micronetId_**/devices    | Return the device definitions for **_micronetId_**. The optional query parameter **_mac_** can be set to return devices with the mac address (list of 0 or 1). The optional query parameter **_ipv4addr_** can be set to return devices with the dotted. IPv4 address. **_ipv6addr_** can be set to a IPv6 address and will return 404 (Not Found) if the **_micronetId_** doesn't exist.|
| delete | DELETE /micronets/**_micronetId_**/devices | Delete all device reservations for **_micronetId_**.  |
| get    | GET /micronets/**_micronetId_**/devices/**_deviceId_**    | Return a particular device definition. This will return 404 (Not Found) if the **_micronetId_** or **_deviceId_** doesn't exist. |
| update | PUT /micronets/**_micronetId_**/devices/**_deviceId_**    | Update a device definition |
| delete | DELETE /micronets/**_micronetId_**/devices/**_deviceId_** | Delete a device definition.  |

### MICRONET DEVICE LEASE CHANGE NOTIFICATIONS

Device lease changes can be communicated by sending a properly formatted json message to the /micronets/v1/dhcp/leases endpoint. 

#### DHCP Lease Change Representation

Note: Currently only data type _application/json_ is supported.

**DHCP Lease Notification:**
```json
{
    "leaseChangeEvent": {
        "action": string, 
        "macAddress": {
            "eui48": string
        }, 
        "networkAddress": {
            "ipv4": string,
            "ipv6": string
        }, 
        "hostname": string
    }
}
```

| Property name            | Value         | Required | Description                           | Example      |
| ------------------------ | ------------- | -------- | ------------------------------------- | ------------- 
| action                   | string        | Y        | One of "leaseAcquired" or "leaseExpired" | "leaseAcquired"|
| macAddress               | nested object | Y        | The device MAC address
| macAddress.eui48         | string        | Y        | An EUI-48 format MAC address |          "00:23:12:0f:b0:26" |
| networkAddress           | nested object | Y        | The network address definition. Either **_ipv4_** or **_ipv6_** must be specified ||
| networkAddress.ipv4      | string        | N        | The IPv4 network definition (dotted IP) | "192.168.1.42" |
| networkAddress.ipv6      | string        | N        | The IPv6 network definition | "fe80::104c:20b6:f71a:4e55" |

#### Device Endpoints/Operations

All request URIs are prefixed by **/micronets/v1/dhcp** unless otherwise noted

| Method | HTTP request                                     | Description                           |
| ------ | ------------------------------------------------ | ------------------------------------- |
| update | PUT /micronets/v1/dhcp/leases                   | Perform a lease change notification. This will return a status code of 500 if the server doesn't have a channel to post the event into. Otherwise an appropriate error code will be returned based on the validity of the post body.

### COMMON DEFINITIONS

**Micronets-Rule:**
```json
{
    "action": string,
    "source": [
        string
    ],
    "sourcePort": string,
    "dest": [
        string
    ],
    "destPort": string
}
```

| Property name            | Value          | Required | Description                             | Example      |
| ------------------------ | -------------- | -------- | --------------------------------------- | ------------- 
| action                   | string         | Y        | One of "deny" or "allow"                | "allow"      |
| source                   | array (string) | N        | Source hosts/address(es)/network(s). DNS hostname, Dotted IPs, CIDR notation, and port/protocol notation support. A port with no protocol will match both TCP and UDP.  | ["8.8.8.8", "12.34.56.0/24", "www.cablelabs.com"] |
| sourcePort               | string         | N        | Source port(s)                          | "22/tcp", "1234-1244/udp", "1111/tcp,2222/udp" |
| dest                     | array (string) | N        | Destination hosts/address(es)/network(s). Dotted IPs, CIDR notation, and port/protocol notation support. A port with no protocol will match both TCP and UDP.  | ["12.34.56.0/24", "www.ietf.org:80/tcp,443/tcp"] |
| destPort                 | string         | N        | Destination port(s)                     | "2112/tcp", "1300-1400/udp", "1111/udp,2222/tcp"| 

#### Notes:

* hostnames will be expanded to one or more IP addresses via DNS
* port designations may include "/tcp" or "/udp" to specify the protocol. If omitted, the rule will apply to both tcp and udp ports.
* If no ports are specified in a rule, the rule applies to all ports on the host(s)

Examples of Micronets-Rule lists:

```json
[
   {"action": "allow", "destIp": "api.acme.com:443/tcp"},
   {"action": "allow", "destIp": "1.2.3.0/24"},
   {"action": "deny"}
]
```
```json
[
   {"action": "allow", "sourceIp": "20.30.40.0/24", "destPort": "22/tcp"},
   {"action": "deny"}
]
```
```json
[
   {"action": "deny", "destPort": "1-1000"},
   {"action": "allow"}
]
```

```
**Micronet-Error:**
```json
{
    "errorCode": integer,
    "errorMessage": string,
    "logEvents": [
        string
    ]
}
```

#### Micronet Operation Status Codes

These status codes apply to all operations described above unless otherwise noted.

| Status Code | Name               | Response Format | Description                           |
| ----------- | ------------------ | --------------- | ------------------------------------- |
| 200 201     | Success            | Micronet or Device | The representation(s) effective at the time of the operation (single or array)    |
| 204         | No Content         | NA              | The target(s) was/were successfully deleted |
| 400         | Bad Request        | Error      | The request was invalid. Details of the error are sent in the response. |
| 401         | Unauthorized       | NA  | The caller is not authorized to perform the operation |
| 403         | Forbidden          | NA  | The caller is not authorized to access the resource |
| 404         | Not Found          | Error | The URI is syntactically correct, but the resource doesn't exist at the time of the operation |
| 405         | Method Not Allowed | NA  | The URI is syntactically correct, but the designated operation is not allowed. The "Allow" header indicates what operations are allowed (e.g. "GET, HEAD") |
| 406         | Not Acceptable     | NA  | The URI is syntactically correct, but none of the requested media types designated in the Accept header are supported by the endpoint. e.g. The request Accept header specifies _application/xml_ but the endpoint doesn't support xml.  |
| 415         | Unsupported Media Type | NA  | The URI is syntactically correct, but the Media-Type requested by the client is not supported by the endpoint. e.g. The request Content-Type header specifies _application/xml_ but the endpoint doesn't support xml.  |
| 500         | Internal Server Error | Error | The server encountered an error processing the request. Details of the error are sent in the response  |
