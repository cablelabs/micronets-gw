#!/bin/bash
BASENAME=micronets-gw-service
PIDFILE=$BASENAME.pid
LOGFILE=$BASENAME.log
BASEDIR=$HOME/Projects/micronets

cd "$BASEDIR"

if [ -f "$PIDFILE" ]; then
  running_pid=$(cat "$PIDFILE")
  rm -v "$PIDFILE"
  echo "Killing running $BASENAME (PID $running_pid)..."
  kill $running_pid
fi

# This config is for using the dnsmasq adapter - listening on all interfaces
# FLASK_ENV=config.DnsmasqTestingConfig
# This config is for listening on all interfaces but using the mock DHCPD adapter
# FLASK_ENV=config.MockDevelopmentConfig
# This config is for listening on all interfaces but using the mock DHCPD adapter
FLASK_ENV=config.MockTestingConfig

source $HOME/.virtualenvs/micronets-gw-service/bin/activate

nohup python micronets-gw-service/runner.py &

new_pid=$!
echo $new_pid > "$PIDFILE"
echo "Starting $BASENAME (PID $new_pid)..."
mv -v nohup.out "$BASENAME.log"
