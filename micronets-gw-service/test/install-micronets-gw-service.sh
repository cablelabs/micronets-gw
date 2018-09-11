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

# This requires the "virtualenv" package to be installed

cd $MICRONET_GW_SERVICE_DIR

echo "Creating virtualenv $MICRONET_GW_VIRTENV_NAME (in $MICRONET_GW_SERVICE_DIR/$MICRONET_GW_VIRTENV_NAME)"
virtualenv --clear -p $(which python3.6) $MICRONET_GW_SERVICE_DIR/$MICRONET_GW_VIRTENV_NAME

source $MICRONET_GW_VIRTENV_NAME/bin/activate

pip install -r requirements.txt
