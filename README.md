# CableLabs Micronets Gateway Repository

This repository is for development of the micronets-gw.service.

More documentation can be found in the [GitHub Wiki](https://github.com/cablelabs/micronets-gw/wiki).

## Top Level Directory Contents

 - micronets-gw-service: The Python 3.6 micronets-gw daemon development directory.
 - distribution: The directory where the installation package is built into distribution/target via make.
 - filesystem: The replica static installation package file system. Files put here will be in the package install.
 - LICENSE: MIT License
 - README.md: This file.

## Building a Debian installer for the Micronets Gateway

Note: This need to be performed on a Debian system - preferably Ubuntu 16.04 LTS

Cloning the repository:

```
git clone git@github.com:cablelabs/micronets-gw.git
```

Building the Debian installer:

```
make -C micronets-gw/distribution
```

## Installing the Debian package for the Micronets Gateway

Note: If the Micronets Gateway service is running, make sure to stop it using:

```
sudo systemctl stop micronets-gw.service 
```

Then install the package using:

```
dpkg -i micronets-gw/distribution/target/micronets-gw-{ver}.deb
```

where "{ver}" is the version number built above with the `make` command. (e.g. "micronets-gw-1.0.28.deb")

See [the "Dependencies" section of the Micronets Gateway Service README](micronets-gw-service/README.md#Dependencies) for details on installing the gateway service dependancies. 

Once the Micronets Gateway service is installed, the `/etc/network/interfaces` file needs to be customized for your setup. [An example interfaces file can be found in filesystem/opt/micronets-gw/doc](filesystem/opt/micronets-gw/doc/interfaces.sample). Changes to this file require restart of the networking service (e.g. `sudo /etc/init.d/networking restart`). As this is not always reliable/tested (currently), a system restart is recommended after changing the interfaces file.

The Micronets Gateway service configuration can be found in `/opt/micronets-gw/config.py`. Almost all of the settings should be able to left at their defaults - with the exception of the `WEBSOCKET_SERVER_PATH` directory. This should be set to include a gateway identifier. For development purposes, something like `/micronets/v1/ws-proxy/bobs-test-gateway` should suffice.
