#!/bin/bash
Vm="kali-vm jump-box elk-vm dvwa-vm"
if [ "$1" = "start" ]; then
	for VMS in $Vm; do
		az vm start --resource-group soc-lab-rg --name $VMS
	done
	echo "All vms started"
elif [ "$1" = "stop" ]; then
	for VMS in $Vm; do
		az vm deallocate --resource-group soc-lab-rg --name $VMS
	done 
	echo "All vms stopped"
else
	echo "Usage ./vmstartup.sh [start|stop]"
	exit 1
fi
