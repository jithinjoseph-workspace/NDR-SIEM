#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, subprocess, os, re, time, threading, ipaddress
from pathlib import Path

HOME_DIR = os.path.expanduser("~")
LOGDIR = os.path.join(HOME_DIR, "logs")
INSTALL_DIR = Path(__file__).resolve().parent.parent
RUNTIME_DIR = INSTALL_DIR / ".runtime"
IFACE_FILE = RUNTIME_DIR / "ndr_interface"

NDR_ARP_SCRIPT = """\
module ARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:        time    &log;
        operation: string  &log;
        mac:       string  &log;
        dst_mac:   string  &log;
        ip:        addr    &log;
        dst_ip:    addr    &log;
    };
}

event zeek_init() &priority=5
{
    Log::create_stream(ARP::LOG, [$columns=Info, $path="arp"]);
}

event arp_request(mac_src: string, mac_dst: string,
                  SPA: addr, SHA: string,
                  TPA: addr, THA: string)
{
    Log::write(ARP::LOG, Info(
        $ts        = network_time(),
        $operation = "request",
        $mac       = SHA,
        $dst_mac   = mac_dst,
        $ip        = SPA,
        $dst_ip    = TPA
    ));
}

event arp_reply(mac_src: string, mac_dst: string,
                SPA: addr, SHA: string,
                TPA: addr, THA: string)
{
    Log::write(ARP::LOG, Info(
        $ts        = network_time(),
        $operation = "reply",
        $mac       = SHA,
        $dst_mac   = THA,
        $ip        = SPA,
        $dst_ip    = TPA
    ));
}
"""

ZEEK_SITE = "/opt/zeek/share/zeek/site"

def ensure_zeek_arp():
    """Write ndr-arp.zeek and ensure local.zeek loads it."""
    arp_path = f"{ZEEK_SITE}/ndr-arp.zeek"
    local_path = f"{ZEEK_SITE}/local.zeek"

    p = subprocess.run(
        ["sudo", "tee", arp_path],
        input=NDR_ARP_SCRIPT.encode(),
        capture_output=True,
    )
    if p.returncode != 0:
        return

    try:
        result = subprocess.run(["sudo", "cat", local_path], capture_output=True, text=True)
        content = result.stdout
        if "@load ndr-arp" not in content:
            new_content = content.rstrip() + "\n@load ndr-arp\n"
            subprocess.run(
                ["sudo", "tee", local_path],
                input=new_content.encode(),
                capture_output=True,
            )
    except Exception:
        pass

# Auto-create log directories on startup
os.makedirs(f"{LOGDIR}/suricata", exist_ok=True)
os.makedirs(f"{LOGDIR}/zeek", exist_ok=True)
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


def bootstrap_from_arp_cache():
    """On startup, read the kernel ARP cache and write entries to arp.log
    so Vector ships them instantly — existing devices appear without any scanning."""
    arp_log = f"{LOGDIR}/zeek/arp.log"
    try:
        out = subprocess.run(["ip", "neigh", "show"],
                             capture_output=True, text=True).stdout
        now = time.time()
        entries = []
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" not in parts:
                continue
            idx = parts.index("lladdr")
            ip_str = parts[0]
            mac = parts[idx + 1] if idx + 1 < len(parts) else ""
            state = parts[-1]
            if state in ("FAILED", "INCOMPLETE") or not mac:
                continue
            try:
                addr = ipaddress.ip_address(ip_str)
                if not addr.is_private or addr.is_loopback:
                    continue
            except Exception:
                continue
            entries.append(json.dumps({
                "ts": now, "operation": "reply",
                "mac": mac, "dst_mac": "",
                "ip": ip_str, "dst_ip": ""
            }))
        if entries:
            os.makedirs(os.path.dirname(arp_log), exist_ok=True)
            with open(arp_log, "a") as f:
                f.write("\n".join(entries) + "\n")
            print(f"[NDR] Bootstrapped {len(entries)} known devices from ARP cache")
    except Exception as e:
        print(f"[NDR] ARP cache bootstrap error: {e}")

def snmp_router_discovery():
    """Query the router's ARP table via SNMP to get all connected devices.
    Auto-detects gateway, tries common community strings."""
    arp_log = f"{LOGDIR}/zeek/arp.log"
    try:
        gw_out = subprocess.run(["ip", "route", "show", "default"],
                                capture_output=True, text=True).stdout
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', gw_out)
        if not m:
            return
        gateway = m.group(1)
    except Exception:
        return

    entries = []
    for community in ["public", "private", "community", "admin"]:
        try:
            result = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, "-t", "3", "-r", "0",
                 gateway, "1.3.6.1.2.1.4.22.1.2"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0 or not result.stdout.strip():
                continue
            now = time.time()
            for line in result.stdout.splitlines():
                ip_m = re.search(r'\.(\d+\.\d+\.\d+\.\d+)\s*=', line)
                mac_m = re.search(r'(?:Hex-STRING:|STRING:)\s*([0-9A-Fa-f :]+)', line)
                if not ip_m or not mac_m:
                    continue
                ip = ip_m.group(1)
                mac_raw = mac_m.group(1).strip()
                mac = ":".join(mac_raw.split()).lower() if " " in mac_raw else mac_raw.lower()
                if len(mac) != 17:
                    continue
                entries.append(json.dumps({
                    "ts": now, "operation": "reply",
                    "mac": mac, "dst_mac": "", "ip": ip, "dst_ip": ""
                }))
            if entries:
                print(f"[NDR] SNMP: {len(entries)} devices from router {gateway} (community={community})")
                break
        except Exception:
            continue

    if entries:
        os.makedirs(os.path.dirname(arp_log), exist_ok=True)
        with open(arp_log, "a") as f:
            f.write("\n".join(entries) + "\n")

def discover_subnets():
    """Read network interface CIDRs and write to ipam.log so the engine
    can build per-tenant subnet maps and detect IP conflicts."""
    ipam_log = f"{LOGDIR}/zeek/ipam.log"
    try:
        out = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True).stdout
        now = time.time()
        iface = None
        entries = []
        for line in out.splitlines():
            m = re.match(r'^\d+:\s+(\S+):', line)
            if m:
                iface = m.group(1).rstrip(':')
                continue
            m = re.match(r'\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', line)
            if m and iface:
                ip, prefix = m.group(1), int(m.group(2))
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                cidr = str(network)
                gateway = str(network.network_address + 1)
                entries.append(json.dumps({
                    "ts": now, "log_type": "ipam",
                    "interface": iface, "cidr": cidr,
                    "local_ip": ip, "gateway": gateway
                }))
        if entries:
            os.makedirs(os.path.dirname(ipam_log), exist_ok=True)
            with open(ipam_log, 'a') as f:
                for e in entries:
                    f.write(e + '\n')
        print(f"[NDR] Subnet discovery: {len(entries)} subnets written")
    except Exception as e:
        print(f"[NDR] discover_subnets error: {e}")

def arp_scan(iface: str):
    """ARP scan the local subnet on startup.
    Only real devices reply to ARP — no ghost placeholders possible.
    Zeek captures the ARP replies via ndr-arp.zeek and enriches assets."""
    try:
        subprocess.run(
            ["sudo", "arp-scan", f"--interface={iface}", "--localnet", "--quiet"],
            capture_output=True, timeout=60
        )
        print("[NDR] ARP scan complete")
    except Exception as e:
        print(f"[NDR] ARP scan error: {e}")

def arp_probe_unknown():
    """Background loop: every 5 min, ARP-probe internal IPs seen in traffic
    that have no ARP entry — so Zeek captures the reply and enriches the asset.
    Uses arping (Layer 2) instead of ping to avoid creating ghost placeholders."""
    conn_log = f"{LOGDIR}/zeek/conn.log"
    while True:
        time.sleep(300)
        try:
            iface = IFACE_FILE.read_text().strip() if IFACE_FILE.exists() else "eth0"

            # IPs with known MACs from kernel ARP cache
            arp_out = subprocess.run(["ip", "neigh", "show"],
                                     capture_output=True, text=True).stdout
            known = {line.split()[0] for line in arp_out.splitlines() if line}

            # IPs seen in the last 500 conn.log lines
            seen = set()
            if os.path.exists(conn_log):
                with open(conn_log) as f:
                    for line in f.readlines()[-500:]:
                        try:
                            obj = json.loads(line)
                            for key in ("id.orig_h", "id.resp_h"):
                                ip = obj.get(key, "")
                                if ip:
                                    seen.add(ip)
                        except Exception:
                            pass

            # ARP-probe internal IPs not yet in ARP cache
            for ip in seen - known:
                try:
                    if ipaddress.IPv4Address(ip).is_private:
                        subprocess.run(
                            ["sudo", "arping", "-c", "1", "-w", "1", "-I", iface, ip],
                            capture_output=True, timeout=3
                        )
                except Exception:
                    pass
        except Exception:
            pass

def start_arkime():
    subprocess.run(
        ["sudo", "systemctl", "start", "arkime-capture"],
        capture_output=True)
    subprocess.run(
        ["sudo", "systemctl", "start", "arkime-viewer"],
        capture_output=True)


def stop_arkime():
    # Stop capture only — viewer stays running so old PCAP data remains downloadable
    subprocess.run(
        ["sudo", "systemctl", "stop", "arkime-capture"],
        capture_output=True)


def get_arkime_status():
    r = subprocess.run(
        ["systemctl", "is-active", "arkime-capture"],
        capture_output=True, text=True)
    return r.stdout.strip()


class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[Agent] {args[0]} {args[1]}")

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def get_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        if self.path == "/agent/status":
            zeek = subprocess.run("sudo pgrep -x zeek", shell=True, capture_output=True).returncode == 0
            suri = subprocess.run("ps aux | grep -v grep | grep -v ndr-agent | grep -c suricata",
                shell=True, capture_output=True, text=True).stdout.strip() != "0"
            
            # Check Docker containers
            vector = subprocess.run(
                "docker ps --filter name=ndr-vector --filter status=running --format '{{.Names}}' 2>/dev/null",
                shell=True, capture_output=True, text=True
            ).stdout.strip() != ""
    
            kafka = subprocess.run(
                "docker ps --filter name=kafka --filter status=running --format '{{.Names}}' 2>/dev/null",
                shell=True, capture_output=True, text=True
            ).stdout.strip() != ""

            # Check ClickHouse
            clickhouse = subprocess.run(
                "curl -s http://localhost:8123/ping 2>/dev/null",
                shell=True, capture_output=True, text=True
            ).stdout.strip() == "Ok."

            iface = IFACE_FILE.read_text().strip() if IFACE_FILE.exists() else "eth0"

            self.send_json({
                "zeek":       "running" if zeek       else "stopped",
                "suricata":   "running" if suri        else "stopped",
                "vector":     "running" if vector      else "stopped",
                "kafka":      "running" if kafka       else "stopped",
                "clickhouse": "running" if clickhouse  else "stopped",
                "arkime":     get_arkime_status(),
                "interface":  iface
            })                   

        elif self.path == "/agent/interfaces":
            out = subprocess.run(["ip", "-o", "link"], capture_output=True, text=True)
            ifaces = []
            for line in out.stdout.splitlines():
                parts = line.split(":")
                if len(parts) > 1:
                    iface = parts[1].strip()
                    if iface != "lo" and not iface.startswith("docker") \
                       and not iface.startswith("br-") \
                       and not iface.startswith("veth"):
                        ifaces.append(iface)
            self.send_json(ifaces)

        elif self.path == "/agent/interface":
            iface = IFACE_FILE.read_text().strip() if IFACE_FILE.exists() else "eth0"
            self.send_json({"interface": iface})

        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/agent/start":
            iface = IFACE_FILE.read_text().strip() if IFACE_FILE.exists() else "eth0"
            # Auto-create log directories
            os.makedirs(f"{LOGDIR}/suricata", exist_ok=True)
            os.makedirs(f"{LOGDIR}/zeek", exist_ok=True)
            # Kill existing processes
            subprocess.run(["sudo", "pkill", "-9", "-f", "suricata"], capture_output=True)
            subprocess.run(["sudo", "pkill", "-9", "-f", "zeek"], capture_output=True)
            time.sleep(2)
    
            # Clean ALL stale PID files
            subprocess.run(["sudo", "rm", "-f", "/var/run/suricata.pid"], capture_output=True)
            subprocess.run(["sudo", "rm", "-f", "/run/suricata.pid"], capture_output=True)
            subprocess.run(["sudo", "rm", "-f", "/var/run/suricata/suricata.pid"], capture_output=True)
            
            # Clear Vector checkpoints so it reads from current position
            subprocess.run(["sudo", "rm", "-rf",
                f"{HOME_DIR}/.vector/data/suricata",
                f"{HOME_DIR}/.vector/data/zeek"],
                capture_output=True)            
            os.makedirs(f"{HOME_DIR}/.vector/data/suricata", exist_ok=True)
            os.makedirs(f"{HOME_DIR}/.vector/data/zeek", exist_ok=True)
            # Write subnet CIDRs to ipam.log for IPAM engine
            discover_subnets()
            # Seed arp.log with existing ARP cache — instant asset bootstrap
            bootstrap_from_arp_cache()
            # Query router ARP table via SNMP
            snmp_router_discovery()
            # Ensure ARP logging script is in place
            ensure_zeek_arp()
            # Start Zeek
            subprocess.Popen(["sudo", "/opt/zeek/bin/zeek", "-i", iface, "local",f"Log::default_logdir={LOGDIR}/zeek"],
                            stdout=open("/tmp/zeek.log", "w"),
                            stderr=subprocess.STDOUT)
    
            # Start Suricata
            subprocess.Popen(["sudo", "suricata",
                 "-c", "/etc/suricata/suricata.yaml",
                 "-i", iface,
                 "-l", f"{LOGDIR}/suricata",
                 "-D",
                 "--pidfile", "/tmp/suricata.pid",
                 "--set", "detect.profile=low",        # low profile for 1 CPU
                 "--set", "max-pending-packets=128",   # reduce memory usage
                 ],  # use /tmp instead
                            stdout=open("/tmp/suricata.log", "w"),
                            stderr=subprocess.STDOUT)

            # Start Arkime
            start_arkime()

            # Full subnet ARP scan on start — only real devices reply
            threading.Thread(target=arp_scan, args=(iface,), daemon=True).start()
            # Ongoing loop: ARP-probe unknown devices every 5 min
            threading.Thread(target=arp_probe_unknown, daemon=True).start()

            self.send_json({"status": "started", "interface": iface})
        elif self.path == "/agent/stop":
            subprocess.run(["sudo", "systemctl", "stop", "suricata"], capture_output=True)
            subprocess.run(["sudo", "pkill", "-9", "-f", "suricata"], capture_output=True)
            subprocess.run(["sudo", "pkill", "-9", "-f", "zeek"], capture_output=True)
            # Clean pid files
            subprocess.run(["sudo", "rm", "-f", "/var/run/suricata.pid"], capture_output=True)
            subprocess.run(["sudo", "rm", "-f", "/run/suricata.pid"], capture_output=True)
            subprocess.run(["sudo", "rm", "-f", "/tmp/suricata.pid"], capture_output=True)
            # Clear Vector checkpoints to prevent replay
            subprocess.run(["sudo", "rm", "-rf",
                f"{HOME_DIR}/.vector/data/suricata",
                f"{HOME_DIR}/.vector/data/zeek"],
                capture_output=True)
            os.makedirs(f"{HOME_DIR}/.vector/data/suricata", exist_ok=True)
            os.makedirs(f"{HOME_DIR}/.vector/data/zeek", exist_ok=True)
            # Stop Arkime
            stop_arkime()
            # Rotate logs
            subprocess.run(["sudo", "logrotate", "-f",
                "/etc/logrotate.d/suricata-ndr"],
                capture_output=True)
            subprocess.run(["sudo", "logrotate", "-f",
                "/etc/logrotate.d/zeek-ndr"],
                capture_output=True)
            self.send_json({"status": "stopped"})

        elif self.path == "/agent/interface":
            body = self.get_body()
            iface = body.get("interface", "eth0")
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
            IFACE_FILE.write_text(iface)
            self.send_json({"status": "ok", "interface": iface})

        else:
            self.send_json({"error": "not found"}, 404)

ZEEK_SID_FILTERS = {
    '2049049': ('DNS',  'rec?$query && "ngrok" in rec$query'),
    '2066052': ('SSL',  'rec?$server_name && "ngrok" in rec$server_name'),
    '2066057': ('SSL',  'rec?$server_name && "ngrok" in rec$server_name'),
    '2022973': ('DHCP', 'rec?$host_name && "kali" in to_lower(rec$host_name)'),
}

ZEEK_HOOK_TYPES = {
    'DNS':  ('DNS::Info',  'DNS::log_policy'),
    'SSL':  ('SSL::Info',  'SSL::log_policy'),
    'DHCP': ('DHCP::Info', 'DHCP::log_policy'),
}

def apply_suppress_sid(cmd: str) -> bool:
    """Apply suppress_sid command at both Suricata and Zeek collection layer.
    Returns True if successfully applied, False if write failed.
    Format: suppress_sid:SID  or  suppress_sid:SID:by_src:IP  or  suppress_sid:SID:by_dst:IP
    """
    parts = cmd.split(':')
    if len(parts) < 2:
        return False
    sid = parts[1].strip()

    # ── Suricata threshold.conf ───────────────────────────────────────────
    threshold_file = '/etc/suricata/threshold.conf'
    if len(parts) >= 4:
        track_kw = 'by_dst' if parts[2].strip() == 'by_dst' else 'by_src'
        suppress_line = f'suppress gen_id 1, sig_id {sid}, track {track_kw}, ip {parts[3].strip()}\n'
    else:
        suppress_line = f'suppress gen_id 1, sig_id {sid}\n'

    try:
        existing = open(threshold_file).read() if os.path.exists(threshold_file) else ''
    except Exception:
        existing = ''

    if suppress_line.strip() not in existing:
        # threshold.conf is root-owned — use sudo tee to append
        result = subprocess.run(
            ['sudo', 'tee', '-a', threshold_file],
            input=suppress_line.encode(), capture_output=True
        )
        if result.returncode != 0:
            return False
        print(f"[NDR] Suricata: suppressed SID {sid}")
        try:
            pid = subprocess.run(['pidof', 'suricata'], capture_output=True, text=True).stdout.strip().split()[0]
            subprocess.run(['sudo', 'kill', '-USR2', pid], check=True)
        except Exception:
            subprocess.run(['sudo', 'suricatasc', '-c', 'reload-rules'], capture_output=True)

    # ── Zeek ndr-suppress.zeek ────────────────────────────────────────────
    zeek_filter_file = '/opt/zeek/share/zeek/site/ndr-suppress.zeek'
    if sid in ZEEK_SID_FILTERS:
        log_type, condition = ZEEK_SID_FILTERS[sid]
        rec_type, hook_name = ZEEK_HOOK_TYPES[log_type]
        hook_block = (
            f'\nhook {hook_name}(rec: {rec_type}, id: Log::ID, filter: Log::Filter) {{\n'
            f'    if ( {condition} ) break;\n}}\n'
        )
        try:
            existing_zeek = open(zeek_filter_file).read() if os.path.exists(zeek_filter_file) else ''
        except Exception:
            existing_zeek = ''

        if hook_block.strip() not in existing_zeek:
            subprocess.run(
                ['sudo', 'tee', '-a', zeek_filter_file],
                input=hook_block.encode(), capture_output=True
            )

            # Ensure local.zeek loads ndr-suppress
            local_zeek = '/opt/zeek/share/zeek/site/local.zeek'
            try:
                lz = open(local_zeek).read()
            except Exception:
                lz = ''
            if '@load ndr-suppress' not in lz:
                subprocess.run(
                    ['sudo', 'tee', '-a', local_zeek],
                    input=b'@load ndr-suppress\n', capture_output=True
                )

            # Restart Zeek to apply new hook
            iface = IFACE_FILE.read_text().strip() if IFACE_FILE.exists() else 'eth0'
            subprocess.run(['sudo', 'pkill', '-f', 'zeek'], capture_output=True)
            time.sleep(1)
            subprocess.Popen(
                ['sudo', '/opt/zeek/bin/zeek', '-i', iface, 'local',
                 f'Log::default_logdir={LOGDIR}/zeek'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            print(f"[NDR] Zeek: filter added for SID {sid}, Zeek restarted")
    return True


def suppression_sync_loop():
    """Poll ClickHouse directly every 5 min for pending suppress_sid commands.
    ClickHouse uses network_mode: host so localhost:8123 is always reachable.
    No sensor key needed — this runs on the same machine as the NDR stack."""
    import urllib.request, urllib.parse, base64
    ch_url   = 'http://localhost:8123/'
    ch_auth  = base64.b64encode(b'ndr:ndr123').decode()
    headers  = {'Authorization': f'Basic {ch_auth}'}

    select_q = (
        "SELECT command FROM ndr.sensor_commands FINAL "
        "WHERE tenant_id='default' AND sensor_id='' AND status='pending'"
    )
    while True:
        try:
            req = urllib.request.Request(
                ch_url + '?query=' + urllib.parse.quote(select_q),
                headers=headers
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                for line in resp.read().decode().strip().splitlines():
                    cmd = line.strip()
                    if not cmd.startswith('suppress_sid:'):
                        continue
                    if apply_suppress_sid(cmd):
                        # Only mark done after successful write
                        done_q = (
                            "ALTER TABLE ndr.sensor_commands "
                            "UPDATE status='done' "
                            f"WHERE tenant_id='default' AND sensor_id='' "
                            f"AND command='{cmd.replace(chr(39), chr(39)*2)}' AND status='pending'"
                        )
                        done_req = urllib.request.Request(
                            ch_url, data=done_q.encode(), headers=headers
                        )
                        urllib.request.urlopen(done_req, timeout=5)
        except Exception:
            pass
        time.sleep(300)


if __name__ == "__main__":
    threading.Thread(target=suppression_sync_loop, daemon=True).start()
    server = HTTPServer(("0.0.0.0", 3001), AgentHandler)
    print("🚀 NDR Host Agent listening on port 3001")
    server.serve_forever()
