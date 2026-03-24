#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Select an attack demonstration:"
echo "1. Open Wifi Attack"
echo "2. Weak WPA2 Attack"
echo "3. Evil Twin Attack"
echo "4. Exit"

read -p "Choice: " choice

source ./.venv/bin/activate

case $choice in
    1)
        # run ./open_wifi/run.sh
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