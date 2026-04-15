#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# WiFi interface selection using airmon-ng
echo "Available WiFi interfaces:"
echo ""

iface_list=$(airmon-ng 2>/dev/null | awk 'NR>3 && NF {print NR-3, $1, $2, $3}')

if [ -z "$iface_list" ]; then
    echo "No WiFi interfaces found. Ensure wireless adapters are connected."
    exit 1
fi

# Print with index
declare -a ifaces
i=1
while read -r idx iface chipset driver; do
    ifaces+=("$iface")
    echo "$i. $iface — $chipset $driver"
    ((i++))
done < <(airmon-ng 2>/dev/null | awk 'NR>3 && NF {print $0}')

echo ""
read -p "Select interface [1-${#ifaces[@]}]: " iface_choice

if ! [[ "$iface_choice" =~ ^[0-9]+$ ]] || \
   [ "$iface_choice" -lt 1 ] || \
   [ "$iface_choice" -gt "${#ifaces[@]}" ]; then
    echo "Invalid interface selection."
    exit 1
fi

export WIFI_INTERFACE="${ifaces[$((iface_choice-1))]}"
echo ""
echo "Using interface: $WIFI_INTERFACE"
echo ""

# Set card to monitoring mode
export WIFI_INTERFACE="${ifaces[$((iface_choice-1))]}"
echo ""
echo "Using interface: $WIFI_INTERFACE"
echo ""

# Set card to monitor mode
echo "Setting $WIFI_INTERFACE to monitor mode..."
airmon-ng check kill 2>/dev/null        # kill interfering processes
airmon-ng start "$WIFI_INTERFACE" 2>/dev/null
sudo iw dev $WIFI_INTERFACE set channel 6

# airmon-ng may rename the interface (e.g. wlan1 -> wlan1mon)
if iw dev | grep -q "${WIFI_INTERFACE}mon"; then
    export WIFI_INTERFACE="${WIFI_INTERFACE}mon"
fi
echo "Monitor interface: $WIFI_INTERFACE"
echo ""

# Restart NetworkManager so other interfaces (e.g. wlan0) stay online
echo "Restarting NetworkManager..."
systemctl restart NetworkManager
sleep 3
echo ""

# Attack menu
echo "Select an attack demonstration:"
echo "1. Open Wifi Attack"
echo "2. Weak WPA2 Attack"
echo "3. Evil Twin Attack"
echo "4. Exit"
read -p "Choice: " choice

source ./.venv/bin/activate

case $choice in
    1)
        cd "$SCRIPT_DIR/open_wifi" && "$SCRIPT_DIR/open_wifi/run.sh"
        ;;
    2)
        cd "$SCRIPT_DIR/wpa2" && "$SCRIPT_DIR/wpa2/run.sh"
        ;;
    3)
        echo "wip"
        ;;
    4)
        exit 0
        ;;
    *)
        echo "Invalid choice"
        ;;
esac