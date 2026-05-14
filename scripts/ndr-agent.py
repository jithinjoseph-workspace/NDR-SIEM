#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, subprocess, os, re, time

HOME_DIR = os.path.expanduser("~")
LOGDIR = os.path.join(HOME_DIR, "logs")
IFACE_FILE = "/tmp/ndr_interface"

# Auto-create log directories on startup
os.makedirs(f"{LOGDIR}/suricata", exist_ok=True)
os.makedirs(f"{LOGDIR}/zeek", exist_ok=True)
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
                "docker ps --filter name=vector --filter status=running --format '{{.Names}}' 2>/dev/null",
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

            iface = open(IFACE_FILE).read().strip() if os.path.exists(IFACE_FILE) else "eth0"

            self.send_json({
                "zeek":       "running" if zeek       else "stopped",
                "suricata":   "running" if suri        else "stopped",
                "vector":     "running" if vector      else "stopped",
                "kafka":      "running" if kafka       else "stopped",
                "clickhouse": "running" if clickhouse  else "stopped",
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
            iface = open(IFACE_FILE).read().strip() if os.path.exists(IFACE_FILE) else "eth0"
            self.send_json({"interface": iface})

        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/agent/start":
            iface = open(IFACE_FILE).read().strip() if os.path.exists(IFACE_FILE) else "eth0"
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
    
            # Start Zeek
            subprocess.Popen(["sudo", "/opt/zeek/bin/zeek", "-i", iface, "local",
                            f"Log::default_logdir={LOGDIR}/zeek"],
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
    
            self.send_json({"status": "started", "interface": iface})
        elif self.path == "/agent/stop":
            subprocess.run(["sudo", "systemctl", "stop", "suricata"], capture_output=True)
            subprocess.run(["sudo", "pkill", "-9", "-f", "suricata"], capture_output=True)
            subprocess.run(["sudo", "pkill", "-9", "-f", "zeek"], capture_output=True)
            # Clean pid files
            subprocess.run(["sudo", "rm", "-f", "/var/run/suricata.pid"], capture_output=True)
            subprocess.run(["sudo", "rm", "-f", "/run/suricata.pid"], capture_output=True)
            subprocess.run(["sudo", "rm", "-f", "/tmp/suricata.pid"], capture_output=True)
            self.send_json({"status": "stopped"})

        elif self.path == "/agent/interface":
            body = self.get_body()
            iface = body.get("interface", "eth0")
            open(IFACE_FILE, "w").write(iface)
            self.send_json({"status": "ok", "interface": iface})

        else:
            self.send_json({"error": "not found"}, 404)

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 3001), AgentHandler)
    print("🚀 NDR Host Agent listening on port 3001")
    server.serve_forever()
