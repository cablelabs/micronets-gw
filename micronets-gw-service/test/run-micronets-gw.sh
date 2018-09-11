#!/bin/bash

# Enable tracing of command invocations
set -x

if [ "$#" -lt 1 ]; then
  MICRONET_GW_SERVICE_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
else
  MICRONET_GW_SERVICE_DIR="$1"
fi

echo "MICRONET_GW_SERVICE_DIR: $MICRONET_GW_SERVICE_DIR"

MICRONET_GW_VIRTENV_NAME=virtualenv

cd $MICRONET_GW_SERVICE_DIR

if [ ! -d $MICRONET_GW_VIRTENV_NAME ]; then
    echo "virtual environment '$MICRONET_GW_VIRTENV_NAME' doesn't exist in $MICRONET_GW_SERVICE_DIR"
    exit 1
fi

if [ ! -f $MICRONET_GW_VIRTENV_NAME/bin/activate ]; then
    echo "Cound not find activate script in virtual environment '$MICRONET_GW_VIRTENV_NAME' (in $MICRONET_GW_SERVICE_DIR)"
    exit 1
fi

echo "Entering virtualenv $MICRONET_GW_VIRTENV_NAME (in $MICRONET_GW_SERVICE_DIR/$MICRONET_GW_VIRTENV_NAME)"
source $MICRONET_GW_VIRTENV_NAME/bin/activate

FLASK_ENV=config.DnsmasqTestingConfig python -u ./runner.py
