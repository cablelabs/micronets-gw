#!/bin/bash 
#

source /etc/openvswitch/ovs.conf
 
function ovsdb_start() 
{ 
	echo "OVSDB: Starting Service" 
        $OVS_SBIN_DIR/ovsdb-server --remote=$OVSDB_LISTEN_SOCKET --remote=db:Open_vSwitch,Open_vSwitch,manager_options --log-file --pidfile --detach # -v
	$OVS_BIN_DIR/ovs-vsctl --db=$OVSDB_CONNECT_SOCKET --no-wait init
        echo "OVSDB: Started at PID `cat $OVS_DB_PID_FILE`"
}
 
function ovsdb_stop() 
{ 
	echo  "OVSDB: Stopping Service PID `cat $OVS_DB_PID_FILE`" 
	kill `cat $OVS_DB_PID_FILE`
        sleep 2
        rm $OVS_DB_PID_FILE > /dev/null 2>&1 || true
        echo "OVSDB: Service Stopped."
}
 
function ovsdb_status() 
{ 
	ps -ef | grep ovsdb-server | grep -v grep
	netstat -lntp | grep $OVSDB_SOCKET
	echo  "OVSDB: PID `cat $OVS_DB_PID_FILE`"
}
 
# Management instructions of the service 
case  "$1"  in 
	start)
		ovsdb_start
		;; 
	stop)
		ovsdb_stop
		;; 
	reload)
		ovsdb_stop
		sleep  1
		ovsdb_start
		;; 
	*) 
		Echo  "Usage: $ 0 {start | stop | reload}" 
		exit  1 
		;; 
esac
 
exit  0
