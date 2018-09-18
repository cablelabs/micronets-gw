#!/bin/bash 
#

SCRIPTDIR=/opt/micronets-gw/bin

function ovs-bootstrap_start() 
{
	echo "ovs-bootstap: Starting OneShot" 
  ${SCRIPTDIR}/bootstrap.sh
  echo "ovs-bootstrap: OneShot Completed"
}
 
# Management instructions of the service 
case  "$1"  in 
	start)
		ovs-bootstrap_start
		;; 
	*)
    echo "Only start is valid!"
		;; 
	*) 
		Echo  "Usage: $ 0 {start}" 
		exit  0 
		;; 
esac
 
exit  0
