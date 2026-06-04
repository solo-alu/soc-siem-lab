#!/bin/bash


count=0

for services in filebeat metricbeat; do
	if systemctl is-active --quiet $services; then
		echo "OK $services is running"
		count=$((count+1))
	else 
		echo "DOWN $services is down"
	fi
done
echo "$count out of 2 services running"
