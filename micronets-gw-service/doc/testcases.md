# Micronets DHCP Controller Test Cases

* To start the server with the mock DHCP conf file, ensure that `USE_MOCK_DHCP_CONFIG = True` is set in the `BaseConfig` section of `config.py` and start the server using:

    `python runner.py runserver`

### SUBNET TEST CASES:

Note: For the sake of brevity, many of these test cases require consecutive execution. i.e. One test case depends on the execution of a previous one.

#### Positive Subnet Test Cases:

* Creating a subnet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
            "subnet": {
                "subnetId": "mocksubnet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.1"
                },
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 201)

    ```json
    {
        "subnet": {
            "subnetId": "mocksubnet007",
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

* Creating another subnet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
            "subnet": {
                "subnetId": "mocksubnet008",
                "ipv4Network": {
                    "network": "192.168.2.0",
                    "mask": "255.255.255.0"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 201)

    ```json
    {
        "subnet": {
            "subnetId": "mocksubnet008",
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0"
            }
        }
    }
    ```

* Creating multiple subnets via one POST:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
        "subnets": [
            {
                "subnetId": "mocksubnet008",
                "ipv4Network": {
                    "network": "192.168.8.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.8.1"
                },
                "nameservers": [
                    "4.4.4.4",
                    "8.8.8.8"
                ]
            },
            {
                "subnetId": "mocksubnet009",
                "ipv4Network": {
                    "network": "192.168.9.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.9.1"
                }
            }
        ] }
        ' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 201)

    ```json
{
    "subnets": [
        {
            "subnetId": "mocksubnet008",
            "ipv4Network": {
                "network": "192.168.8.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.8.1",
                "broadcast": "192.168.8.255"
            },
            "nameservers": [
                "4.4.4.4",
                "8.8.8.8"
            ]
        },
        {
            "subnetId": "mocksubnet009",
            "ipv4Network": {
                "network": "192.168.9.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.9.1",
                "broadcast": "192.168.9.255"
            }
        }
    ]
}

* Retrieve all subnets:

    ```
    curl http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 200)

    ```json
    {
        "subnets": [
            {
                "subnetId": "mocksubnet008",
                "ipv4Network": {
                    "network": "192.168.8.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.8.1"
                },
                "nameservers": [
                    "4.4.4.4",
                    "8.8.8.8"
                ]
            },
            {
                "subnetId": "mocksubnet009",
                "ipv4Network": {
                    "network": "192.168.9.0",
                    "mask": "255.255.255.0",
                    "gateway": "192.168.9.1"
                }
            }
        ]
    }
    ```

* Updating a subnet:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
            "subnet": {
                "subnetId": "mocksubnet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.2"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007
    ```

    Expected output: (status code 200)

    ```json
    {
        "subnet": {
            "subnetId": "mocksubnet007",
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.1.2"
            },
            "nameservers": [
                "1.2.3.4",
                "1.2.3.5"
            ]
        }
    }
    ```

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
            "subnet": {
                "nameservers": ["1.2.3.4", "1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007
    ```json

    Expected output: (status code 200)

    ```json
    {
        "subnet": {
            "subnetId": "mocksubnet007",
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.1.2"
            },
            "nameservers": [
                "1.2.3.4",
                "1.2.3.5"
            ]
        }
    }
    ```

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
            "subnet": {
                "ipv4Network": {
                    "gateway": "192.168.1.3"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007
    ```

    Expected output: (status code 200)

    ```json
    {
        "subnet": {
            "subnetId": "mocksubnet007",
            "ipv4Network": {
                "network": "192.168.1.0",
                "mask": "255.255.255.0",
                "gateway": "192.168.1.3"
            },
            "nameservers": [
                "1.2.3.4",
                "1.2.3.5"
            ]
        }
    }
    ```

* Deleting a subnet:

    ```
    curl -X DELETE http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007
    ```

    Expected output: (status code 204)

    None

* Deleting all subnets:

    ```
    curl -X DELETE http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 204)

    None

#### Negative Subnet Test Cases:

* Create a second subnet with the same name:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
            "subnet": {
                "subnetId": "mocksubnet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.1"
                },
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 409)

    ```json
    {
        "message": "Supplied subnet ID 'mocksubnet007' already exists"
    }
    ```

* Create a subnet with an invalid name:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "subnet": {
                "subnetId": "bad subnet name",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0"
                },
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied subnet ID 'bad subnet name' in '{'subnetId': 'bad subnet name', 'ipv4Network': {'network': '192.168.1.0', 'mask': '255.255.255.0'}, 'nameservers': ['1.2.3.4', '1.2.3.5']}' is not alpha-numeric"
    }
    ```

* Create a subnet with a missing required field:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "subnet": {
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0"
                },
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Required field 'subnetId' missing from {'ipv4Network': {'network': '192.168.1.0', 'mask': '255.255.255.0'}, 'nameservers': ['1.2.3.4', '1.2.3.5']}"
    }
    ```

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "subnet": {
                "subnetId": "MySubnet",
                "ipv4Network": {
                    "network": "192.168.1.0"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Required field 'mask' missing from {'network': '192.168.1.0'}"
    }
    ```

* Create a subnet with an invalid gateway address:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "subnet": {
                "subnetId": "mocksubnet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.2.1"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Gateway address 192.168.2.1 isn't in the 'mocksubnet019' subnet (192.168.1.0/24)"
    }
    ```

* Create a subnet that overlaps another subnet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "subnet": {
                "subnetId": "mocksubnet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.1"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```
    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "subnet": {
                "subnetId": "mocksubnet008",
                "ipv4Network": {
                    "network": "192.168.0.0",
                    "mask": "255.255.0.0",
                    "gateway":"192.168.2.1"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Subnet 'mocksubnet008' network 192.168.0.0/16 overlaps existing subnet 'mocksubnet007' (network 192.168.1.0/24)"
    }
    ```

* Update a subnet with a mismatched name:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "subnet": {
                "subnetId": "mocksubnet008",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.2"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007
    ```

    Expected output: (status code 409)

    ```json
    {
        "message": "Update can only update subnet 'mocksubnet007' ('mocksubnet008' provided)"
    }
    ```

* Update a subnet with a bad IP address:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "subnet": {
                "ipv4Network": {
                    "network": "192.168.1.1234"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied IP address value '192.168.1.1234' for 'network' field in '{'network': '192.168.1.1234'}' is not valid"
    }
    ```

* Update a subnet with a bad IP address:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "subnet": {
                "ipv4Network": {
                    "network": "127.0.0.1"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied IP address value '127.0.0.1' for 'network' field in '{'network': '127.0.0.1'}' is not valid: Address is a loopback or broadcast address"
    }
    ```

* Deleting a non-empty subnet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "subnet": {
                "subnetId": "mocksubnet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
    ```
    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "subnet": {
               "deviceId": "MyDevice01",
               "macAddress": {
                   "eui48": "00:23:12:0f:b0:26"
               },
               "networkAddress": {
                   "ipv4": "192.168.1.42"
               }
           }
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Subnet 'mocksubnet007' still has active devices"
    }
    ```

### DEVICE TEST CASES:

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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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

* Creating multiple devices in a subnet:

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
    }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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
                "networkAddress": {
                    "ipv4": "192.168.1.43"
                }
            }
        ]
    }
    ```


* Retrieving all devices defined for a subnet:

    ```
    curl http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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

* Creating a device:

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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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

* Updating a device:

    ```
    curl -X PUT -H "Content-Type: application/json" -d '{
           "device": {
                "networkAddress": {
                    "ipv4": "192.168.1.143"
                }
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices/MyDevice01
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
    curl -X DELETE http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices/mydevice01
    ```

    Expected output: (status code 204)

    None

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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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
          }'  http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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
        }'  http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices/MyDevice01
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Supplied MAC '0023120fb02600' in 'eui48' is not valid"
    }
    ```

* Creating a device with an address that's not part of the containing subnet:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
                "subnetId": "mocksubnet007",
                "ipv4Network": {
                    "network": "192.168.1.0",
                    "mask": "255.255.255.0",
                    "gateway":"192.168.1.1"
                },
                "nameservers": ["1.2.3.4","1.2.3.5"]
            }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "Device 'MyDevice01' address 192.168.2.42 isn't compatible with subnet 'mocksubnet007' (192.168.1.0/24)"
    }
    ```

* Creating a device with a duplicate MAC address:

    ```
    curl -X POST -H "Content-Type: application/json" -d '{
           "device": {
               "subnetId": "mocksubnet007",
               "ipv4Network": {
                   "network": "192.168.1.0",
                   "mask": "255.255.255.0",
                   "gateway":"192.168.1.1"
               },
               "nameservers": ["1.2.3.4","1.2.3.5"]
           }
        }' http://localhost:5000/micronets/v1/dhcp/subnets
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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
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
        }' http://localhost:5000/micronets/v1/dhcp/subnets/mocksubnet007/devices
    ```

    Expected output: (status code 400)

    ```json
    {
        "message": "MAC address of device 'MyDevice02' is not unique (MAC address 00:23:12:0f:b0:26 found in subnet 'mocksubnet007' device 'mydevice01')"
    }
    ```
