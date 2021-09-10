#!/bin/bash

# VLANer - Helper script to facilitate testing via trunk ports
# spyr0 - v0.1
# Usage: sudo ./vlaner.sh [create|destroy] [interface] (default interface is eth1) [config file] (default is vlans.cfg)

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit
fi

interface=${2:-eth1}
configfile=${3:-vlans.cfg}

if [ "$#" -lt 1 ]; then
    echo "VLANer takes in a space delimited file of VLAN IDs then IP address to create VLAN tagged interfaces"
    echo "Usage: sudo ./vlaner.sh [create|destroy] [interface] (default interface is eth1) [config file] (default is vlans.cfg)"
    echo "Note: config file needs to have an empty line at end of file otherwise last interface will not get created"
    echo "Second Note: ensure config file is created using unix line endings (:set ff=unix in vim)"
fi

if [ "$1" == "create" ]; then
  while read -r vlanid address; do # Have to use variables in order. e.g. In other words vlanid comes before address
    echo "Creating interface $interface.$vlanid with the IP address $address"
    ip link add link $interface name $interface.$vlanid type vlan id $vlanid
    echo "Running command - ip addr add dev $interface.$vlanid $address"
    ip addr add dev $interface.$vlanid $address
    ip link set $interface.$vlanid up
  done < $configfile
fi

if [ "$1" == "destroy" ]; then
    while read -r vlanid address; do
      echo "Destroying interface $interface.$vlanid"
      ip link delete $interface.$vlanid
  done < $configfile
fi