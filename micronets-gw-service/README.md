# Micronets Gateway Service README

## Running

To setup a dev environment for the Micronets DHCP service, run the following steps:

```
cd ~/projects/micronets
git clone git@github.com:cablelabs/micronets-gw.git
cd micronets-gw/micronets-gw-service
mkvirtualenv -r requirements.txt -a $PWD -p $(which python3) micronets-gw-service
workon micronets-gw-service
```

If you want to access the REST API directly - running against the mock DHCP reservation adapter, use:

```
MICRONETS_DHCP_CONFIG=config.MockDevelopmentConfig python ./runner.py
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

## Micronets DHCP REST/CRUD Interface

This section contains the general REST API definitions for the Micronets DHCP reservation service.

All request URIs are prefixed by **/micronets/v1/dhcp** unless otherwise noted

See the `testcases.md` document in the `test` directory for examples.

### DHCP SUBNETS

Micronet device DHCP reservations must be made in the context of a IP subnet.
These operations defined in this section allow for the management of these subnets.

#### DHCP Subnet Representation

Currently only data type _application/json_ is supported.

**DHCP-Subnet:**
```json
{
    "subnetId": string,
    "ipv4Network": {
        "network": string,
        "mask": string,
        "gateway": string,
        "broadcast": string
    },
    "nameservers": [
        string
    ]
}
```

| Property name            | Value           | Required | Description                           | Example      |
| ------------------------ | --------------- | -------- | ------------------------------------- | ------------- 
| subnetId                 | string          | Y        | Unique ID for the subnet | 192.168.0 |
| ipv4Network              | nested object   | Y        | The definition of a IPv4 network ||
| ipv4Network.network      | string          | Y        | The IPv4 network definition (dotted IP) | 192.168.1.0 |
| ipv4Network.mask         | string          | Y        | The netmask for the network (dotted IP) | 255.255.255.0 |
| ipv4Network.gateway      | string          | N        | The IPv4 address of the network gateway | 192.168.1.1 |
| ipv4Network.broadcast    | string          | N        | The IPv4 address for broadcast | 192.168.1.255 |
| nameservers              | list            | N        | The IP addresses of nameservers for the subnet | 8.8.8.8, 4.4.4.4|

#### DHCP Subnet Endpoints/Operations

| Method | HTTP request                                     | Description                           |
| ------ | ------------------------------------------------ | ------------------------------------- |
| insert | POST /subnets                  | Add a DHCP subnet or subnets (if an array of subnets are provided). This will return a status code of 405 (Method Not Allowed) if any of the provided subnet IDs already exist. (no subnets will be added in this case) |
| list   | GET /subnets                   | Return an array of all the DHCP-defined subnets on this DHCP server |
| delete | DELETE /subnets                | Deletes all DHCP subnet definitions. The operation will return a status code of 405 (Method Not Allowed) if any of the subnets still contain device reservations (no subnets will be deleted in this case). |
| get    | GET /subnets/**_subnetId_**    | Return the DHCP-defined subnet for **_subnetId_**. This will return 404 (Not Found) if the /**_subnetId_** doesn't exist. |
| update | PUT /subnets/**_subnetId_**    | Update a DHCP subnet definition. This will return 400 if the message body contains a **_subnetId_** that doesn't match the **_subnetId_** in the URI path or if the network conflicts with an already-existing network and will return 404 (Not Found) if the **_subnetId_** doesn't exist. |
| delete | DELETE /subnets/**_subnetId_** | Delete a DHCP subnet definition. The operation will return a status code of 405 (Method Not Allowed) if the subnet still contains device reservations and will return 404 (Not Found) if the **_subnetId_** doesn't exist. |

### DEVICE ADDRESSES RESERVATION

These definitions allow for the management of micronet device DHCP reservations.
Devices must be defined and exist within the context of a subnet.

#### DHCP Device Representation

Currently only data type _application/json_ is supported.

**DHCP Device:**
```json
{
    "deviceId": string,
    "macAddress": {
       "eui48": string
    },
    "networkAddress": {
       "ipv4": string,
       "ipv6": string
    }
}
```

| Property name            | Value         | Required | Description                           | Example      |
| ------------------------ | ------------- | -------- | ------------------------------------- | ------------- 
| deviceId                 | string        | Y        | An alphanumeric device identifier (max 64 characters) ||
| macAddress               | nested object | Y        | The device MAC address
| macAddress.eui48         | string        | Y        | An EUI-48 format MAC address |          00:23:12:0f:b0:26 |
| networkAddress           | nested object | Y        | The network address definition. Either **_ipv4_** or **_ipv6_** must be specified ||
| networkAddress.ipv4      | string        | N        | The IPv4 network definition (dotted IP) | 192.168.1.42 |
| networkAddress.ipv6      | string        | N        | The IPv6 network definition | fe80::104c:20b6:f71a:4e55 |

#### DHCP Device Reservation Endpoints/Operations

All request URIs are prefixed by **/micronets/v1/dhcp** unless otherwise noted

| Method | HTTP request                                     | Description                           |
| ------ | ------------------------------------------------ | ------------------------------------- |
| insert | POST /subnets/**_subnetId_**/devices   | Add a DHCP device address reservation or reservarions (if an array of devices are provided) under **_subnetId_**. This will return a status code of 400 if any of the provided **_deviceId_**, **_macAddress_**, or **_networkAddress_** specified in the request body conflicts with an already-defined device reservation (no device reservations will be added in this case). A 404 (Not Found) will be returned if the **_subnetId_** doesn't exist. | |
| list   | GET /subnets/**_subnetId_**/devices    | Return the DHCP address reservations for **_subnetId_**. The optional query parameter **_mac_** can be set to return devices with the mac address (list of 0 or 1). The optional query parameter **_ipv4addr_** can be set to return devices with the dotted. IPv4 address. **_ipv6addr_** can be set to a IPv6 address and will return 404 (Not Found) if the **_subnetId_** doesn't exist.|
| delete | DELETE /subnets/**_subnetId_**/devices | Delete all device reservations for **_subnetId_**.  |
| get    | GET /subnets/**_subnetId_**/devices/**_deviceId_**    | Return a particular device definition. This will return 404 (Not Found) if the **_subnetId_** or **_deviceId_** doesn't exist. |
| update | PUT /subnets/**_subnetId_**/devices/**_deviceId_**    | Update a DHCP device definition |
| delete | DELETE /subnets/**_subnetId_**/devices/**_deviceId_** | Delete a DHCP device definition.  |

### COMMON DEFINITIONS

**DHCP-Error:**
```json
{
    "errorCode": integer,
    "errorMessage": string,
    "logEvents": [
        string
    ]
}
```

#### Micronets DHCP Subnet Operation Status Codes

These status codes apply to all operations described above unless otherwise noted.

| Status Code | Name               | Response Format | Description                           |
| ----------- | ------------------ | --------------- | ------------------------------------- |
| 200 201    | Success            | DHCP-Subnet or DHCP_Device | The representation(s) effective at the time of the operation (single or array)    |
| 204         | No Content         | NA              | The target(s) was/were successfully deleted |
| 400         | Bad Request        | DHCP-Error      | The request was invalid. Details of the error are sent in the response. |
| 401         | Unauthorized       | NA  | The caller is not authorized to perform the operation |
| 403         | Forbidden          | NA  | The caller is not authorized to access the resource |
| 404         | Not Found          | DHCP-Error | The URI is syntactically correct, but the resource doesn't exist at the time of the operation |
| 405         | Method Not Allowed | NA  | The URI is syntactically correct, but the designated operation is not allowed. The "Allow" header indicates what operations are allowed (e.g. "GET, HEAD") |
| 406         | Not Acceptable     | NA  | The URI is syntactically correct, but none of the requested media types designated in the Accept header are supported by the endpoint. e.g. The request Accept header specifies _application/xml_ but the endpoint doesn't support xml.  |
| 415         | Unsupported Media Type | NA  | The URI is syntactically correct, but the Media-Type requested by the client is not supported by the endpoint. e.g. The request Content-Type header specifies _application/xml_ but the endpoint doesn't support xml.  |
| 500         | Internal Server Error | DHCP-Error | The server encountered an error processing the request. Details of the error are sent in the response  |
