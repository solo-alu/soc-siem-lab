#!/bin/bash

echo "What is your name?" 
read name
 
echo "Welcome $name to the SOC lab"

for VM in elk-vm jump-box kali-vm dvwa-vm; do
	echo "Checking $VM..." 
	az vm show -d -g soc-lab-rg -n $VM --query powerState -o tsv
done
