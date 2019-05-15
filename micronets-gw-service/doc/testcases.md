# Micronets Gateway Service Test Cases

### MICRONET ENDPOINT TEST CASES:

Note: JSON request/response object fields should not be assumed to be in any particular order (JSON object fields have no ordering requirements). e.g. `{"a":1, "b":2, "c":{"d":4, "e":5}}` is equivalent to `{"b":2, "c":{"e":5, "d":4}, "a":1}`.

Note: For the sake of brevity, many of these test cases require consecutive execution. i.e. One test case depends on the execution of a previous one.

#### Positive Endpoint Test Cases:

* Creating a micronet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
            "micronet": {
                "micronetId": "mockmicronet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 101,
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 201)

    ```json
    {
        "micronet": {
            "micronetId": "mockmicronet007",
            "interface": "wlp2s0",
            "ovsBridge": "brmn001",
            "vlan": 101,
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.1.1"
            },
            "nameservers": [
                "1.2.3.4",
                "1.2.3.5"
            ]
        }
    }
    ```

* Creating another micronet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
            "micronet": {
                "micronetId": "mockmicronet008",
                "ipv4Network": {
                    "network": "192.168.2.0",
                    "mask": "255.255.255.0"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 102
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 201)

    ```json
    {
        "micronet": {
            "micronetId": "mockmicronet008",
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0"
            },
            "interface": "wlp2s0",
            "ovsBridge": "brmn001",
            "vlan": 102
        }
    }
    ```

* Creating multiple micronets via one POST:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
        "micronets": [
            {
                "micronetId": "mockmicronet008",
                "ipv4Network": {
                    "network": "192.168.8.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.8.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 108,
                "nameservers": [
                    "4.4.4.4",
                    "8.8.8.8"
                ]
            },
            {
                "micronetId": "mockmicronet009",
                "ipv4Network": {
                    "network": "192.168.9.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.9.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 109
            }
        ] }
        ' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 201)

    ```json
    {
        "micronets": [
            {
                "micronetId": "mockmicronet008",
                "ipv4Network": {
                    "network": "192.168.8.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.8.1",
                    "broadcast": "192.168.8.255"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 108,
                "nameservers": [
                    "4.4.4.4",
                    "8.8.8.8"
                ]
            },
            {
                "micronetId": "mockmicronet009",
                "ipv4Network": {
                    "network": "192.168.9.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.9.1",
                    "broadcast": "192.168.9.255"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 109
            }
        ]
    }
    ```


* Retrieve all micronets:

    ```
    curl http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 200)

    ```json
    {
        "micronets": [
            {
                "micronetId": "mockmicronet008",
                "ipv4Network": {
                    "network": "192.168.8.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.8.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 108,
                "nameservers": [
                    "4.4.4.4",
                    "8.8.8.8"
                ]
            },
            {
                "micronetId": "mockmicronet009",
                "ipv4Network": {
                    "network": "192.168.9.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.9.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 109
            }
        ]
    }
    ```

* Updating a micronet:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
            "micronet": {
                "micronetId": "mockmicronet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.2"
                }
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007
    ```

    Expected output: (status code 200)

    ```json
    {
        "micronet": {
            "micronetId": "mockmicronet007",
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.1.2"
            },
            "interface": "wlp2s0",
            "ovsBridge": "brmn001",
            "vlan": 101,
            "nameservers": [
                "1.2.3.4",
                "1.2.3.5"
            ]
        }
    }
    ```

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
            "micronet": {
                "nameservers": ["1.2.3.4", "1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007
    ```

    Expected output: (status code 200)

    ```json
    {
        "micronet": {
            "micronetId": "mockmicronet007",
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.1.2"
            },
            "interface": "wlp2s0",
            "ovsBridge": "brmn001",
            "vlan": 101,
            "nameservers": [
                "1.2.3.4",
                "1.2.3.5"
            ]
        }
    }
    ```

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
            "micronet": {
                "ipv4Network": {
                    "gateway": "192.168.1.3"
                }
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007
    ```

    Expected output: (status code 200)

    ```json
    {
        "micronet": {
            "micronetId": "mockmicronet007",
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.1.3"
            },
            "interface": "wlp2s0",
            "ovsBridge": "brmn001",
            "vlan": 101,
            "nameservers": [
                "1.2.3.4",
                "1.2.3.5"
            ]
        }
    }
    ```

* Deleting a micronet:

    ```
    curl -X DELETE http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007
    ```

    Expected output: (status code 204)

    None

* Deleting all micronets:

    ```
    curl -X DELETE http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 204)

    None

#### Negative Subnet Test Cases:

* Create a second micronet with the same name:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
            "micronet": {
                "micronetId": "mockmicronet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 101,
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 409)

    ```json
    {
        "message": "Supplied micronet ID 'mockmicronet007' already exists"
    }
    ```

* Create a micronet with an invalid name:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
                "micronetId": "bad micronet name",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 101,
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied micronet ID 'bad micronet name' in '{'micronetId': 'bad micronet name', 'ipv4Network': {'network': '192.168.1.0', 'mask': '255.255.255.0'}, 'nameservers': ['1.2.3.4', '1.2.3.5']}' is not alpha-numeric"
    }
    ```

* Create a micronet with a missing micronetId field:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Required field 'micronetId' missing from {'ipv4Network': {'network': '192.168.1.0', 'mask': '255.255.255.0'}, 'nameservers': ['1.2.3.4', '1.2.3.5']}"
    }
    ```

* Create a micronet with a missing network mask field:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
                "micronetId": "MySubnet",
                "ipv4Network": {
                    "network": "192.168.1.0"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001"
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Required field 'mask' missing from {'network': '192.168.1.0'}"
    }
    ```

* Create a micronet with an invalid gateway address:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
                "micronetId": "mockmicronet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.2.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001"
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Gateway address 192.168.2.1 isn't in the 'mockmicronet019' micronet (192.168.1.0/24)"
    }
    ```

* Create a micronet that overlaps another micronet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
                "micronetId": "mockmicronet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001"
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```
    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
                "micronetId": "mockmicronet008",
                "ipv4Network": {
                    "network": "192.168.0.0",
                    "mask": "255.255.0.0",
                    "gateway":"192.168.2.1"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001"
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Subnet 'mockmicronet008' network 192.168.0.0/16 overlaps existing micronet 'mockmicronet007' (network 192.168.1.0/24)"
    }
    ```

* Update a micronet with a mismatched name:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "micronet": {
                "micronetId": "mockmicronet008",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.2"
                },
                "interface": "wlp2s0",
                "ovsBridge": "brmn001",
                "vlan": 101
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007
    ```

    Expected output: (status code 409)

    ```json
    {
        "message": "Update can only update micronet 'mockmicronet007' ('mockmicronet008' provided)"
    }
    ```

* Update a micronet with a bad IP address:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "micronet": {
                "ipv4Network": {
                    "network": "192.168.1.1234"
                }
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied IP address value '192.168.1.1234' for 'network' field in '{'network': '192.168.1.1234'}' is not valid"
    }
    ```

* Update a micronet with a bad IP address:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "micronet": {
                "ipv4Network": {
                    "network": "127.0.0.1"
                }
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied IP address value '127.0.0.1' for 'network' field in '{'network': '127.0.0.1'}' is not valid: Address is a loopback or broadcast address"
    }
    ```

* Deleting a non-empty micronet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
                "micronetId": "mockmicronet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0"
                }
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```
    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:26"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               }
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Subnet 'mockmicronet007' still has active devices"
    }
    ```

### MICRONET DEVICE ENDPOINT TEST CASES:

#### Positive Device Test Cases:

* Creating a device:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:26"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               }
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 201)

    ```json
    {
        "device": {
            "deviceId": "MyDevice01",
            "macAddress": {
               "eui48": "00:23:12:0f:b0:26"
            },
            "networkAddress": {
                "ipv4": "192.168.1.42"
            }
        }
    }
    ```

* Creating multiple devices in a micronet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "devices": [
                {
                    "deviceId": "MyDevice01",
                    "macAddress": {
                       "eui48": "00:23:12:0f:b0:26"
                    },
                    "networkAddress": {
                        "ipv4": "192.168.1.42"
                    }
                },
                {
                    "deviceId": "MyDevice02",
                    "macAddress": {
                        "eui48": "00:23:12:0f:b0:27"
                    },
                    "networkAddress": {
                        "ipv4": "192.168.1.43"
                    }
                }
            ]
    }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 201)

    ```json
    {
        "devices": [
            {
                "deviceId": "MyDevice01",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:26"
                },
                "networkAddress": {
                    "ipv4": "192.168.1.42"
                }
            },
            {
                "deviceId": "MyDevice02",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:27",
                },
                "networkAddress": {
                    "ipv4": "192.168.1.43"
                }
            }
        ]
    }
    ```

* Retrieving all devices defined for a micronet:

    ```
    curl http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 200)

    ```json
    {
        "devices": [
            {
                "deviceId": "MyDevice02",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:27"
                },
                "networkAddress": {
                    "ipv4": "192.168.42.43"
                }
            },
            {
                "deviceId": "MyDevice01",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:26"
                },
                "networkAddress": {
                    "ipv4": "192.168.1.42"
                }
            }
        ]
    }
    ```

* Creating another device:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
                "deviceId" :"MyDevice02",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:27"
                },
                "networkAddress": {
                    "ipv4": "192.168.42.43"
                }
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 200)

    ```json
    {
        "device": {
            "deviceId": "MyDevice02",
            "macAddress": {
                "eui48": "00:23:12:0f:b0:27"
            },
            "networkAddress": {
                "ipv4": "192.168.42.43"
            }
        }
    }
    ```

* Creating a device with a PSK:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:26"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               },
               "psk": "736b697070657220697320612076657279207665727920676f6f642063617421"
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 201)

    ```json
    {
        "device": {
            "deviceId": "MyDevice01",
            "macAddress": {
               "eui48": "00:23:12:0f:b0:26"
            },
            "networkAddress": {
                "ipv4": "192.168.1.42"
            }
        }
    }
    ```

* Updating a device:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "device": {
                "networkAddress": {
                    "ipv4": "192.168.1.143"
                }
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices/MyDevice01
    ```

    Expected output: (status code 200)

    ```json
    {
        "device": {
            "deviceId": "MyDevice01",
            "macAddress": {
               "eui48": "00:23:12:0f:b0:26"
            },
            "networkAddress": {
                "ipv4": "192.168.42.43"
            }
        }
    }
    ```

* Deleting a device:

    ```
    curl -X DELETE http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices/mydevice01
    ```

    Expected output: (status code 204)

    None

* Creating a device restricted to communicating with certain hosts:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice03",
               "macAddress": {
                   "eui48": "b8:27:eb:75:a4:8a"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               },
               "outRules": [
                  {"action": "allow", "dest": "8.8.8.8"},
                  {"action": "allow", "dest": "12.34.56.0/24"},
                  {"action": "allow", "dest": "www.ietf.org:443/tcp"},
                  {"action": "deny"} ]
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 201)

    ```json
    {
        "device": {
            "deviceId": "MyDevice01",
            "macAddress": {
               "eui48": "00:23:12:0f:b0:26"
            },
            "networkAddress": {
                "ipv4": "192.168.1.42"
            },
            "outRules": [
                {"action": "deny", "dest": "8.8.8.8"},
                {"action": "deny", "dest": "12.34.56.0/24"},
                {"action": "deny", "dest": "www.ietf.org"},
                {"action": "deny", "destPort": "1024-20000"},
                {"action": "allow"} ]
        }
    }
    ```

* Creating a device which is prevented from communicating with certain hosts or certain ports:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice03",
               "macAddress": {
                   "eui48": "b8:27:eb:75:a4:8a"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               },
               "outRules": [
                  {"action": "deny", "dest": "8.8.8.8"},
                  {"action": "deny", "dest": "12.34.56.0/24"},
                  {"action": "deny", "dest": "www.ietf.org"},
                  {"action": "deny", "destPort": "1024-20000"},
                  {"action": "allow"} ]
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 201)

    ```json
    {
        "device": {
            "deviceId": "MyDevice01",
            "macAddress": {
               "eui48": "00:23:12:0f:b0:26"
            },
            "networkAddress": {
                "ipv4": "192.168.1.42"
            },
            "outRules": [
                {"action": "deny", "dest": "8.8.8.8"},
                {"action": "deny", "dest": "12.34.56.0/24"},
                {"action": "deny", "dest": "www.ietf.org"},
                {"action": "allow"} ]
        }
    }
    ```

* Initiating DPP onboarding:

    DPP onboarding can be initiated by providing a 

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "akms": ["psk"],
           "dpp": {
               "uri": "DPP:C:81/1;M:2c:d0:5a:6e:ca:3c;I:KYZRQ;K:MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgAC/nFQKV1+CErzr6QCUT0jFIno3CaTRr3BW2n0ThU4mAw=;;"
           }
       }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices/MyDevice03/onboard
    ```

    Expected events: (when the onboard is initiated successfully/returns 200)
    ```json
    {
        "message" : {
            "messageId" : 1234,
            "messageType" : "EVENT:DPP:DPPOnboardingStartedEvent",
            "requiresResponse" : false,
            "dataFormat" : "application/json",
            "messageBody" : {
                "DPPOnboardingStartedEvent" : {
                    "deviceId" : "MyDevice03",
                    "micronetId" : "mockmicronet007",
                    "macAddress" : "00:23:12:0f:b0:26"
                 }
            }
        }
    }
    ```

    ```json
    {
        "message" : {
            "messageId" : 1234,
            "messageType" : "EVENT:DPP:DPPOnboardingProgressEvent",
            "requiresResponse" : false,
            "dataFormat" : "application/json",
            "messageBody" : {
                "DPPOnboardingProgressEvent" : {
                    "deviceId" : "MyDevice03",
                    "micronetId" : "mockmicronet007",
                    "macAddress" : "00:23:12:0f:b0:26",
                    "reason": "DPP-CONF-SENT"
                 }
            }
        }
    }
    ```

    ```json
    {
        "message" : {
            "messageId" : 1234,
            "messageType" : "EVENT:DPP:DPPOnboardingCompleteEvent",
            "requiresResponse" : false,
            "dataFormat" : "application/json",
            "messageBody" : {
                "DPPOnboardingCompleteEvent" : {
                    "deviceId" : "MyDevice03",
                    "micronetId" : "mockmicronet007",
                    "macAddress" : "00:23:12:0f:b0:26"
                 }
            }
        }
    }
    ```

#### Negative Device Test Cases:

* Creating a device with a bad IP address:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
                "deviceId": "MyDevice01",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:26"
                },
                "networkAddress": {
                    "ipv4": "192.168.1.4222"
                }
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
      "message": "Supplied IP address value '192.168.1.4222' for 'ipv4' field in '{'ipv4': '192.168.1.4222'}' is not valid"
    }
    ```

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
                "deviceId": "MyDevice01",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:26"
                },
                "networkAddress": "blah"
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
      "message": "Supplied field value 'blah' for 'networkAddress' field in '{'deviceId': 'MyDevice01', 'macAddress': '00:23:12:0f:b0:26', 'networkAddress': 'blah'}' is not a (<class 'dict'>, <class 'list'>)"
    }
    ```

* Creating a device with no IP address:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
                "deviceId": "MyDevice01",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:26"
                },
                "networkAddress": {}
            }
          }'  http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Network address missing from device description {'deviceId': 'MyDevice01', 'macAddress': '00:23:12:0f:b0:26', 'networkAddress': {}}"
    }
    ```

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
                "deviceId": "MyDevice01",
                "macAddress": {
                    "eui48": "00:23:12:0f:b0:26"
                }
            }
        }'  http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Required field 'networkAddress' missing from {'deviceId': 'MyDevice01', 'macAddress': '00:23:12:0f:b0:26'}"
    }
    ```

* Creating a device with a bad mac address:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               }
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied MAC '00:23:12:0f:b0:' in 'macAddress' is not valid"
    }
    ```

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:26:00"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               }
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied MAC '00:23:12:0f:b0:26:00' in 'eui48' is not valid"
    }
    ```

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "0023120fb02600"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices/MyDevice01
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied MAC '0023120fb02600' in 'eui48' is not valid"
    }
    ```

* Creating a device with an address that's not part of the containing micronet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "micronet": {
                "micronetId": "mockmicronet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.1"
                },
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```
    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:26"
               },
               "networkAddress": {
                   "ipv4": "192.168.2.42"
               }
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Device 'MyDevice01' address 192.168.2.42 isn't compatible with micronet 'mockmicronet007' (192.168.1.0/24)"
    }
    ```

* Creating a device with a duplicate MAC address:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "micronetId": "mockmicronet007",
               "ipv4Network": {
                   "network": "192.168.1.0",
                   "mask": "255.255.255.0",
                   "gateway":"192.168.1.1"
               },
               "nameservers": ["1.2.3.4","1.2.3.5"]
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets
    ```
    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:26"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               }
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```
    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "deviceId": "MyDevice02",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:26"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.43"
               }
           }
        }' http://localhost:5000/micronets/v1/gateway/micronets/mockmicronet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "MAC address of device 'MyDevice02' is not unique (MAC address 00:23:12:0f:b0:26 found in micronet 'mockmicronet007' device 'mydevice01')"
    }
    ```

### LEASE NOTIFICATION TEST CASES:

Lease change notifications can be performed by posting to the `/micronets/v1/gateway/leases` endpoint.

```json
curl -X PUT -H "Content-Type: application/json" -d '{
    "leaseChangeEvent": {
        "action": "leaseExpired", 
        "macAddress": {
            "eui48": "00:23:12:0f:b0:26"
        }, 
        "networkAddress": {
            "ipv4": "192.168.1.42"
        }, 
        "hostname": "myhost"}
    }' http://localhost:5000/micronets/v1/gateway/leases
```

Expected output: (status code 200)

None
