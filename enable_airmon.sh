#!/bin/bash

# enable_airmon - Little wrapper script that puts your wireless network card in monitor mode
# spyr0 - v0.1
# Usage: ./enable_airmon.sh [wlan0]

interface=${1:-wlan0}

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
else
  echo "Placing $interface in monitor mode"
  airmon-ng check kill
  ip link set $interface down
  iw dev $interface set type monitor
  iw $interface set txpower fixed 3000
  ip link set $interface up
  iwconfig $interface
fi