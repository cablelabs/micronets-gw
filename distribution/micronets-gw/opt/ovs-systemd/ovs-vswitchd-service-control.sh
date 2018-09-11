#!/bin/bash 
#

source /etc/openvswitch/ovs.conf
 
function ovs_vswitchd_start() 
{ 
	echo "OvS vSwitch: Starting Service" 
        modprobe openvswitch
        $OVS_SBIN_DIR/ovs-vswitchd $OVSDB_CONNECT_SOCKET --log-file --pidfile --detach # -v
        echo "OvS vSwitch: Started at PID `cat $OVS_VSWITCHD_PID_FILE`"
}
 
function ovs_vswitchd_stop() 
{ 
	echo  "OvS vSwitch: Stopping Service PID `cat $OVS_VSWITCHD_PID_FILE`" 
	kill `cat $OVS_VSWITCHD_PID_FILE`
        sleep 2
        rm $OVS_VSWITCHD_PID_FILE > /dev/null 2>&1 || true
        echo "OvS vSwitch: Service Stopped."
}
 
function ovs_vswitchd_status() 
{ 
	ps -ef | grep ovs-vswitchd | grep -v grep
	netstat -ntp | grep $OVSDB_SOCKET
	echo  "OvS vSwitch: PID `cat $OVS_VSWITCHD_PID_FILE`"
}
 
# Management instructions of the service 
case  "$1"  in 
	start)
		ovs_vswitchd_start
		;; 
	stop)
		ovs_vswitchd_stop
		;; 
	reload)
		ovs_vswitchd_stop
		sleep  1
		ovs_vswitchd_start
		;; 
	*)
		Echo  "Usage: $ 0 {start | stop | reload}" 
		exit  1 
		;; 
esac
 
exit  0
