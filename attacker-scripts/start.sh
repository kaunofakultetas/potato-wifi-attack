#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Select an attack demonstration:"
echo "1. Open Wifi Attack"
echo "2. Weak WPA2 Attack"
echo "3. Evil Twin Attack"
echo "4. Exit"

read -p "Choice: " choice

case $choice in
    1)
        # Run the venv python directly and point to the script
        "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/open_wifi/run.py"
        ;;
    2)
        "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/wpa2/run.py"
        ;;
    3)
        "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/evil_twin/run.py"
        ;;
    4)
        exit 0
        ;;
    *)
        echo "Invalid choice"
        ;;
en