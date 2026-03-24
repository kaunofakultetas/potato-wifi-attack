#!/bin/bash

# Kill interfering processes
sudo airmon-ng check kill

# Start monitor mode
sudo airmon-ng start wlp0s20u3

# Set channel to 6
sudo iw dev wlp0s20u3 set channel 6

# Standard airmon-ng usually renames to <iface>mon
INTERFACE="wlp0s20u3mon"

# Fallback check if it didn't rename
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    INTERFACE="wlp0s20u3"
fi

echo -e "\033[92m[+] Starting Attacker Inspector on $INTERFACE...\033[0m"

# Run the inspector
sudo python3 main.py --interface "$INTERFACE"
