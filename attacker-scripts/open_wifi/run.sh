#!/bin/bash

echo -e "\033[92m[+] Starting Attacker Inspector on $WIFI_INTERFACE...\033[0m"

# Run the inspector
sudo python3 main.py --interface "$WIFI_INTERFACE"
