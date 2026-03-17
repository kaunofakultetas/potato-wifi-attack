"""
packet_engine.py — Core packet capture & analysis engine.

Runs Scapy sniffing in a background thread and pushes parsed results
into thread-safe queues consumed by the CLI logger and GUI.
"""

import queue
import threading
import time
import re
import io
import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, Ether, ARP, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    """Structured representation of a captured packet."""
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    flags: str = ""
    info: str = ""
    raw_payload: bytes = b""
    # Enrichment fields
    credentials: Optional[dict] = None          # {"username": …, "password": …}
    image_data: Optional[bytes] = None           # raw image bytes if detected
    image_type: Optional[str] = None             # e.g. "JPEG", "PNG"
    dns_query: Optional[str] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    http_content_type: Optional[str] = None
    http_body: Optional[bytes] = None
    tags: List[str] = field(default_factory=list)
    severity: str = "info"                       # info | warning | critical


# ---------------------------------------------------------------------------
# Credential patterns
# ---------------------------------------------------------------------------

_USER_FIELDS = [rb'user', rb'username', rb'login', rb'email', rb'usr', rb'user_login']
_PASS_FIELDS = [rb'pass', rb'password', rb'pwd', rb'secret', rb'passwd', rb'login_password']

def _extract_credentials(payload: bytes) -> Optional[dict]:
    """Try to extract credentials from raw payload bytes."""
    import base64
    import urllib.parse

    # 1. Try URL-encoded forms / Generic text matches (order-independent)
    # We look for user=... and pass=...
    user = None
    password = None
    
    # Try searching for user fields
    for f_name in _USER_FIELDS:
        # Use \b to match start of field name (works for &field=, ?field=, or \nfield=)
        pat = re.compile(rb'\b' + f_name + rb'=\s*([^&\s]*)', re.IGNORECASE)
        m = pat.search(payload)
        if m:
            user = m.group(1)
            break
            
    # Try searching for password fields
    for f_name in _PASS_FIELDS:
        pat = re.compile(rb'\b' + f_name + rb'=\s*([^&\s]*)', re.IGNORECASE)
        m = pat.search(payload)
        if m:
            password = m.group(1)
            break
            
    if user and password:
        try:
            u_str = urllib.parse.unquote(user.decode("utf-8", errors="strict"))
            p_str = urllib.parse.unquote(password.decode("utf-8", errors="strict"))
            
            if len(u_str) > 150 or len(p_str) > 150:
                raise ValueError("String too long")
                
            def is_valid(s):
                return all(c.isprintable() or c in ' \t\r\n' for c in s)
                
            if not is_valid(u_str) or not is_valid(p_str):
                raise ValueError("Contains non-printable characters")

            return {
                "username": u_str,
                "password": p_str,
                "method": "Form/Generic Match"
            }
        except Exception:
            pass

    # 2. Basic Auth header (base64)
    basic_match = re.search(rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', payload, re.IGNORECASE)
    if basic_match:
        try:
            import base64
            decoded = base64.b64decode(basic_match.group(1)).decode("utf-8", errors="replace")
            if ":" in decoded:
                u, p = decoded.split(":", 1)
                return {"username": u, "password": p, "method": "Basic Auth"}
        except Exception:
            pass

    # 3. JSON body
    user_json = None
    pass_json = None
    user_pat = re.compile(rb'"(?:user(?:name)?|login|email)":\s*"([^"]+)"', re.IGNORECASE)
    pass_pat = re.compile(rb'"(?:pass(?:word)?|pwd|secret)":\s*"([^"]+)"', re.IGNORECASE)
    
    m_u = user_pat.search(payload)
    m_p = pass_pat.search(payload)
    if m_u and m_p:
        try:
            u_str = m_u.group(1).decode("utf-8", errors="strict")
            p_str = m_p.group(1).decode("utf-8", errors="strict")
            if len(u_str) <= 150 and len(p_str) <= 150:
                return {
                    "username": u_str,
                    "password": p_str,
                    "method": "JSON API",
                }
        except Exception:
            pass

    # 4. FTP USER / PASS
    ftp_user = re.search(rb'^USER\s+(\S+)', payload, re.IGNORECASE | re.MULTILINE)
    ftp_pass = re.search(rb'^PASS\s+(\S+)', payload, re.IGNORECASE | re.MULTILINE)
    try:
        if ftp_user:
            u_str = ftp_user.group(1).decode("utf-8", errors="strict")
            if len(u_str) <= 150:
                return {"username": u_str, "password": "<pending>", "method": "FTP"}
        if ftp_pass:
            p_str = ftp_pass.group(1).decode("utf-8", errors="strict")
            if len(p_str) <= 150:
                return {"username": "<pending>", "password": p_str, "method": "FTP"}
    except Exception:
        pass

    return None


# Image magic bytes
_IMAGE_SIGS = {
    b'\xff\xd8\xff': "JPEG",
    b'\x89PNG\r\n\x1a\n': "PNG",
    b'GIF87a': "GIF",
    b'GIF89a': "GIF",
    b'BM': "BMP",
    b'RIFF': "WEBP",  # partial — would also need 'WEBP' at offset 8
}


def _detect_image(payload: bytes) -> tuple:
    """Return (image_bytes, image_type) or (None, None)."""
    for sig, img_type in _IMAGE_SIGS.items():
        idx = payload.find(sig)
        if idx != -1:
            return payload[idx:], img_type
    return None, None


from typing import Optional, List, Any, Dict

# ...

def _parse_http(payload: bytes) -> Dict[str, Any]:
    """Best-effort HTTP header parsing."""
    result: Dict[str, Any] = {"headers_found": False}
    try:
        # Check for header/body separator
        if b"\r\n\r\n" in payload:
            header_part, body_part = payload.split(b"\r\n\r\n", 1)
            result["body"] = body_part
            result["headers_found"] = True
        else:
            header_part = payload
            result["body"] = b""
        
        text = header_part[:4096].decode("utf-8", errors="replace")
        lines = text.splitlines()
        if not lines: return result

        first_line = lines[0]
        # Request line
        req_match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP', first_line)
        if req_match:
            result["http_method"] = req_match.group(1)
            result["http_path"] = req_match.group(2)
            result["headers_found"] = True

        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip().lower()
                v = v.strip()
                if k == "host": result["http_host"] = v
                elif k == "content-type": result["http_content_type"] = v
                elif k == "authorization": result["authorization"] = v
        
    except Exception:
        pass
    return result

def _parse_sni(payload: bytes) -> Optional[str]:
    """Best-effort extraction of Server Name Indication (SNI) from TLS Client Hello."""
    try:
        if len(payload) < 43 or payload[0] != 0x16:
            return None
        record_len = int.from_bytes(payload[3:5], 'big')
        if record_len + 5 > len(payload):
            return None
        if payload[5] != 0x01:
            return None
        offset = 9 + 2 + 32
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        cipher_suites_len = int.from_bytes(payload[offset:offset+2], 'big')
        offset += 2 + cipher_suites_len
        comp_methods_len = payload[offset]
        offset += 1 + comp_methods_len
        if offset + 2 > len(payload):
            return None
        ext_total_len = int.from_bytes(payload[offset:offset+2], 'big')
        offset += 2
        end_of_ext = offset + ext_total_len
        while offset + 4 <= end_of_ext and offset + 4 <= len(payload):
            ext_type = int.from_bytes(payload[offset:offset+2], 'big')
            ext_len = int.from_bytes(payload[offset+2:offset+4], 'big')
            offset += 4
            if ext_type == 0x00: # SNI
                sn_list_len = int.from_bytes(payload[offset:offset+2], 'big')
                sn_offset = offset + 2
                while sn_offset < offset + ext_len:
                    name_type = payload[sn_offset]
                    name_len = int.from_bytes(payload[sn_offset+1:sn_offset+3], 'big')
                    sn_offset += 3
                    if name_type == 0x00:
                        return payload[sn_offset:sn_offset+name_len].decode('utf-8')
                    sn_offset += name_len
            offset += ext_len
    except Exception:
        pass
    return None

def parse_packet(pkt) -> Optional[PacketRecord]:
    """Convert a raw Scapy packet into a PacketRecord."""
    if not pkt.haslayer(IP):
        # Handle ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            return PacketRecord(
                timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                src_ip=arp.psrc,
                dst_ip=arp.pdst,
                protocol="ARP",
                length=len(pkt),
                info=f"{'Request' if arp.op == 1 else 'Reply'}  {arp.hwsrc} → {arp.hwdst}",
                tags=["ARP"],
            )
        return None

    ip = pkt[IP]
    rec = PacketRecord(
        timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
        src_ip=ip.src,
        dst_ip=ip.dst,
        protocol="IP",
        length=len(pkt),
    )

    payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.protocol = "TCP"
        rec.src_port = tcp.sport
        rec.dst_port = tcp.dport
        rec.flags = str(tcp.flags)
        if tcp.dport == 80 or tcp.sport == 80:
            rec.protocol = "HTTP"
        elif tcp.dport == 443 or tcp.sport == 443:
            rec.protocol = "TLS/HTTPS"
        elif tcp.dport == 21 or tcp.sport == 21:
            rec.protocol = "FTP"
        elif tcp.dport == 25 or tcp.sport == 25:
            rec.protocol = "SMTP"
        # Info summary
        rec.info = f":{tcp.sport} → :{tcp.dport}  [{tcp.flags}]  seq={tcp.seq}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.protocol = "UDP"
        rec.src_port = udp.sport
        rec.dst_port = udp.dport
        if pkt.haslayer(DNS):
            rec.protocol = "DNS"
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace")
                rec.dns_query = qname
                rec.info = f"Query: {qname}"
                rec.tags.append("DNS")
            else:
                rec.info = "DNS response"
                rec.tags.append("DNS")
        else:
            rec.info = f":{udp.sport} → :{udp.dport}  len={udp.len}"
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        rec.protocol = "ICMP"
        rec.info = f"type={icmp.type}  code={icmp.code}"
    else:
        rec.info = f"IP proto={ip.proto}"

    rec.raw_payload = payload

    # --- Enrichment ---
    if payload:
        # HTTP headers
        http_info = _parse_http(payload)
        if http_info.get("headers_found"):
            rec.http_method = http_info.get("http_method")
            rec.http_host = http_info.get("http_host")
            rec.http_path = http_info.get("http_path")
            rec.http_content_type = http_info.get("http_content_type")
            rec.http_body = http_info.get("body")
            
            if rec.http_method:
                info = f"{rec.http_method} {rec.http_path or '/'} ({rec.http_host or '?'})"
                # If POST, try to show a snippet of the body
                body = http_info.get("body", b"")
                if rec.http_method == "POST" and body:
                    body_snippet = body[:50].decode("utf-8", errors="replace").replace("\r", "").replace("\n", " ")
                    info += f" | Body: {body_snippet}..."
                rec.info = info
                rec.tags.append("HTTP")
                
        # TLS SNI parsing
        if rec.protocol == "TLS/HTTPS":
            sni = _parse_sni(payload)
            if sni:
                rec.http_host = sni
                rec.info = f"TLS → {sni} [{rec.dst_port}]"
                if "HTTPS" not in rec.tags:
                    rec.tags.append("HTTPS")

        # Credentials (pass the whole payload)
        creds = _extract_credentials(payload)
        if creds:
            rec.credentials = creds
            rec.tags.append("🔑 CREDENTIALS")
            rec.severity = "critical"
            # If it's a partial match, mark it
            if creds.get("partial"):
                rec.tags[-1] += " (PARTIAL)"

        # Image detection
        img_bytes, img_type = _detect_image(payload)
        if img_bytes and len(img_bytes) > 128:
            rec.image_data = img_bytes
            rec.image_type = img_type
            rec.tags.append(f"🖼 IMAGE ({img_type})")
            rec.severity = "warning"

    return rec


# ---------------------------------------------------------------------------
# Engine: background sniffer that feeds queues
# ---------------------------------------------------------------------------

class PacketEngine:
    """Captures packets and feeds structured records to subscribers."""

    def __init__(self, interface: str = None, bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._subscribers: List[queue.Queue] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._lock = threading.Lock()
        
        # Simple TCP Reassembly
        # {(src_ip, sport, dst_ip, dport): b"accumulated_payload"}
        self._streams = {}
        self._stream_lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=5000)
        self._subscribers.append(q)
        return q

    @property
    def packet_count(self) -> int:
        return self._packet_count

    def _dispatch(self, record: PacketRecord):
        with self._lock:
            self._packet_count += 1
        for q in self._subscribers:
            try:
                q.put_nowait(record)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(record)
                except Exception:
                    pass

    def _on_packet(self, pkt):
        # 1. Basic parse
        rec = parse_packet(pkt)
        if not rec: return

        # 2. TCP Reassembly logic for better credential detection
        if SCAPY_AVAILABLE and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            ip = pkt[IP]
            tcp = pkt[TCP]
            stream_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            
            with self._stream_lock:
                # Append to buffer
                current_payload = bytes(pkt[Raw].load)
                if stream_key not in self._streams:
                    self._streams[stream_key] = current_payload
                else:
                    self._streams[stream_key] += current_payload
                
                # Limit buffer size per stream (e.g. 1MB) to prevent memory leaks
                if len(self._streams[stream_key]) > 1024 * 1024:
                    self._streams[stream_key] = self._streams[stream_key][-1024*1024:]
                
                # Try credential extraction on the ENTIRE reassembled stream
                full_stream_payload = self._streams[stream_key]
                stream_creds = _extract_credentials(full_stream_payload)
                
                if stream_creds:
                    # If the stream now has creds but the individual packet didn't,
                    # enrich this packet so the user sees it immediately.
                    if not rec.credentials:
                        rec.credentials = stream_creds
                        if "🔑 CREDENTIALS" not in rec.tags:
                            rec.tags.append("🔑 CREDENTIALS")
                        rec.severity = "critical"
                        if stream_creds.get("partial"):
                            rec.tags[-1] += " (PARTIAL)"
                    
                # Cleanup old streams (simple heuristic: if it's a FIN/RST packet)
                if tcp.flags.F or tcp.flags.R:
                    if stream_key in self._streams:
                        del self._streams[stream_key]

        self._dispatch(rec)

    def start(self):
        if not SCAPY_AVAILABLE:
            # Demo mode — generate synthetic packets
            self._running = True
            self._thread = threading.Thread(target=self._demo_loop, daemon=True)
            self._thread.start()
            return

        self._running = True
        kwargs = {
            "prn": self._on_packet,
            "store": False,
            "stop_filter": lambda _: not self._running,
        }
        if self.interface:
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter

        self._thread = threading.Thread(target=lambda: sniff(**kwargs), daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    # ------------------------------------------------------------------
    # Demo / synthetic packet generator (when scapy is unavailable or
    # when running without root)
    # ------------------------------------------------------------------
    def _demo_loop(self):
        import random
        import string

        sample_ips = [
            "192.168.1.10", "192.168.1.1", "10.0.0.5", "172.16.0.100",
            "8.8.8.8", "1.1.1.1", "93.184.216.34", "151.101.1.69",
        ]
        sample_hosts = [
            "login.example.com", "api.service.io", "cdn.images.net",
            "mail.corp.local", "db.internal.lan", "oauth.provider.com",
        ]
        sample_paths = [
            "/login", "/api/v2/auth", "/upload/avatar.jpg", "/dashboard",
            "/api/users", "/static/logo.png", "/graphql", "/webhook",
        ]
        sample_dns = [
            "www.google.com.", "api.github.com.", "cdn.cloudflare.com.",
            "login.microsoftonline.com.", "s3.amazonaws.com.",
        ]

        protocols = ["TCP", "UDP", "HTTP", "DNS", "TLS/HTTPS", "ICMP", "ARP", "FTP", "SMTP"]

        while self._running:
            proto = random.choice(protocols)
            src = random.choice(sample_ips)
            dst = random.choice(sample_ips)
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 53, 21, 25, 8080, 3306, 5432])

            rec = PacketRecord(
                timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                src_ip=src,
                dst_ip=dst,
                protocol=proto,
                length=random.randint(40, 1500),
                src_port=sport,
                dst_port=dport,
            )

            if proto == "DNS":
                qname = random.choice(sample_dns)
                rec.dns_query = qname
                rec.info = f"Query: {qname}"
                rec.tags.append("DNS")
                rec.dst_port = 53
            elif proto in ("HTTP", "FTP"):
                method = random.choice(["GET", "POST", "PUT", "DELETE"])
                host = random.choice(sample_hosts)
                path = random.choice(sample_paths)
                rec.http_method = method
                rec.http_host = host
                rec.http_path = path
                rec.info = f"{method} {path} ({host})"
                rec.tags.append("HTTP")
                rec.dst_port = 80

                # Occasionally inject credentials
                if random.random() < 0.08:
                    rec.credentials = {
                        "username": random.choice(["admin", "jdoe", "root", "alice", "bob"]),
                        "password": ''.join(random.choices(string.ascii_letters + string.digits, k=10)),
                        "method": random.choice(["Form/JSON", "Basic Auth", "FTP"]),
                    }
                    rec.tags.append("🔑 CREDENTIALS")
                    rec.severity = "critical"
                    rec.info += "  ⚠ Credentials detected!"

                # Occasionally inject image marker
                if random.random() < 0.05:
                    img_type = random.choice(["JPEG", "PNG", "GIF"])
                    # Generate a tiny dummy image
                    rec.image_type = img_type
                    rec.tags.append(f"🖼 IMAGE ({img_type})")
                    rec.severity = "warning"
                    rec.http_content_type = f"image/{img_type.lower()}"
                    rec.info += f"  [{img_type} image]"
                    # Create a small synthetic image for demo
                    rec.image_data = self._make_demo_image(img_type)

            elif proto == "TLS/HTTPS":
                rec.dst_port = 443
                host = random.choice(sample_hosts)
                rec.http_host = host
                rec.info = f"TLS → {host}:{443}  [encrypted]"
            elif proto == "ICMP":
                rec.info = f"type={random.choice([0,8])}  code=0"
            elif proto == "ARP":
                rec.info = f"{'Request' if random.random() < 0.5 else 'Reply'}  {src} → {dst}"
                rec.tags.append("ARP")
            else:
                flags = random.choice(["S", "SA", "A", "PA", "FA", "R"])
                rec.flags = flags
                rec.info = f":{sport} → :{dport}  [{flags}]  seq={random.randint(1000,999999)}"

            self._dispatch(rec)
            time.sleep(random.uniform(0.15, 0.8))

    @staticmethod
    def _make_demo_image(img_type: str) -> bytes:
        """Create a small coloured demo image."""
        try:
            from PIL import Image as PILImage
            import random
            w, h = 120, 80
            color = (random.randint(30, 220), random.randint(30, 220), random.randint(30, 220))
            img = PILImage.new("RGB", (w, h), color)
            buf = io.BytesIO()
            fmt = {"JPEG": "JPEG", "PNG": "PNG", "GIF": "GIF", "BMP": "BMP"}.get(img_type, "PNG")
            img.save(buf, format=fmt)
            return buf.getvalue()
        except Exception:
            return b""
