#!/bin/bash 
#

SCRIPTDIR=/opt/ovs-bootstrap/bin

function ovs-bootstrap_start() 
{
	echo "ovs-bootstap: Starting OneShot" 
        rm var/run/bootstrap > /dev/null 2>&1
        pushd $SCRIPTDIR
        ./bootstrap.sh
        popd
        echo "ovs-bootstrap: OneShot Completed"
}
 
function ovs-bootstrap_stop() 
{ 
	echo  "ovs-bootstrap: OneShot stop N/A!"
}
 
# Management instructions of the service 
case  "$1"  in 
	start)
		ovs-bootstrap_start
		;; 
	stop)
		ovs-bootstrap_stop
		;; 
	*) 
		Echo  "Usage: $ 0 {start | stop}" 
		exit  1 
		;; 
esac
 
exit  0
