import requests
import urllib3

# Disable insecure request warnings if using self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# CONFIGURATION - Set these parameters before running on your Linux VM
# ==============================================================================
BASE_URL = "https://10.0.2.15:3000"
SUPER_ADMIN_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcl9hZG1pbiIsInRlbmFudF9pZCI6ImRlZmF1bHQiLCJwZXJtaXNzaW9ucyI6WyJkYXNoYm9hcmQiLCJhbGVydHMiLCJpbnRlbCIsImV2aWRlbmNlIiwicnVsZXMiLCJzb2FyIiwicmVwb3J0cyIsInNldHRpbmdzIiwidXNlcnMiLCJ0ZW5hbnRzIiwic2Vuc29ycyIsImVuZ2luZXMiLCJhZG1pbiJdLCJmZWF0dXJlcyI6WyJuZHIiLCJzb2FyIiwidGhyZWF0X2ludGVsIiwiYWkiXSwic2Vuc29yX2lkcyI6W10sImV4cCI6MTc5MDIyODkyMywiaWF0IjoxNzkwMjI1MzIzLCJqdGkiOiI4NzkzZGFjNy1lOTMxLTQxY2MtYjA3ZS1hMjVkNGE5NjU2YjcifQ.qK85m1u0JyMgdhenh1CYO9gyKClh0gjovXCsmIsJfrk"
TENANT_ADMIN_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZW5hbnQtYWRtaW4iLCJyb2xlIjoidGVuYW50X2FkbWluIiwidGVuYW50X2lkIjoiZGVmYXVsdCIsInBlcm1pc3Npb25zIjpbImRhc2hib2FyZCIsImFsZXJ0cyIsImludGVsIiwiZXZpZGVuY2UiLCJydWxlcyIsInNvYXIiLCJyZXBvcnRzIiwic2V0dGluZ3MiLCJ1c2VycyIsInNlbnNvcnMiXSwiZmVhdHVyZXMiOlsibmRyIiwic29hciIsInRocmVhdF9pbnRlbCIsImFpIl0sInNlbnNvcl9pZHMiOltdLCJleHAiOjE3OTAyMjkwMTgsImlhdCI6MTc5MDIyNTQxOCwianRpIjoiNjg2OTllNTQtZjVjYy00OGFhLWJjZTUtNjgzNTk3ZDIwZmFhIn0.ayAZm8FvRgXCaffwlVWWXJXeRlHTpPW7Bo4t6wGV_t8"
DISPOSABLE_TENANT_ID = "automated-test-tenant"
DISPOSABLE_TENANT_USER_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdXRvX2FkbWluIiwicm9sZSI6InRlbmFudF9hZG1pbiIsInRlbmFudF9pZCI6ImF1dG9tYXRlZC10ZXN0LXRlbmFudCIsInBlcm1pc3Npb25zIjpbImRhc2hib2FyZCIsImFsZXJ0cyIsImludGVsIiwiZXZpZGVuY2UiLCJydWxlcyIsInNvYXIiLCJyZXBvcnRzIiwic2V0dGluZ3MiLCJ1c2VycyIsInNlbnNvcnMiXSwiZmVhdHVyZXMiOlsibmRyIl0sInNlbnNvcl9pZHMiOltdLCJleHAiOjE3OTAwNjE1NDIsImlhdCI6MTc5MDA1Nzk0MiwianRpIjoiODkwNmZlYWUtZGEyMS00MDc3LTkwMjAtM2FlOGI0MDgwNGZiIn0.sZ_aE7LeesEUkXb6LR3NPxWWr6j8OG-yLcpjEiWsM18"
ANALYST_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZWZhdWx0QW5hbHlzdCIsInJvbGUiOiJhbmFseXN0IiwidGVuYW50X2lkIjoiZGVmYXVsdCIsInBlcm1pc3Npb25zIjpbImRhc2hib2FyZCIsImFsZXJ0cyIsImFzc2V0cyIsImxvZ3MiLCJuZXR3b3JrLW1hcCIsImxpdmUiLCJydWxlcyIsImV2aWRlbmNlIiwiYWktYWN0aXZpdHkiLCJhaS1yZXBvcnQiLCJpbnRlbCIsInNvYXIiXSwiZmVhdHVyZXMiOlsibmRyIiwic29hciIsInRocmVhdF9pbnRlbCIsImFpIl0sInNlbnNvcl9pZHMiOlsibG9jYWwtY2VudHJhbCJdLCJleHAiOjE3OTAyMzExNDEsImlhdCI6MTc5MDIyNzU0MSwianRpIjoiODYzZjExMWMtNDEzNy00Njg0LTg1ZTktMDUwODI0ZjIxZWJhIn0.BUfo8ok-EgLwXGYmmWEI8XQOIWIKMMHyR26zgntbbao"

sa_headers = {
    "Authorization": f"Bearer {SUPER_ADMIN_TOKEN}",
    "Content-Type": "application/json"
}

analyst_headers = {
    "Authorization": f"Bearer {ANALYST_TOKEN}",
    "Content-Type": "application/json"
}

def print_result(tc_id, status, details=""):
    color = "\033[92m" if status == "PASS" else "\033[91m"
    if status == "SKIP":
        color = "\033[93m"
    reset = "\033[0m"
    print(f"{color}{tc_id} = {status}{reset} | {details}")

def test_tc_026():
    """List NDR Engines"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/engines", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-026", "PASS", f"Retrieved engines list. Count: {len(resp.json())}")
        else:
            print_result("TC-026", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-026", "FAIL", str(e))

def test_tc_027():
    """View Global Telemetry"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/telemetry", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-027", "PASS", "Successfully retrieved global telemetry.")
        else:
            print_result("TC-027", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-027", "FAIL", str(e))

def test_tc_028():
    """View Active Sessions Across Tenants"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/active-sessions", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-028", "PASS", f"Successfully retrieved active sessions. Count: {len(resp.json())}")
        else:
            print_result("TC-028", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-028", "FAIL", str(e))

def test_tc_029():
    """Check Component Version"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/version", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-029", "PASS", f"Retrieved version.")
        else:
            print_result("TC-029", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-029", "FAIL", str(e))

def test_tc_030():
    """Check Cluster Leader Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/leader-status", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-030", "PASS", f"Leader status OK.")
        else:
            print_result("TC-030", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-030", "FAIL", str(e))

def test_tc_031():
    """View Cross-Tenant Statistics"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/stats-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-031", "PASS", "Successfully retrieved cross-tenant statistics.")
        else:
            print_result("TC-031", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-031", "FAIL", str(e))

def test_tc_032():
    """Add Global AI Provider"""
    try:
        payload = {"name": "test-ai", "provider_type": "openai", "api_key": "test"}
        resp = requests.post(f"{BASE_URL}/api/settings/ai/providers", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-032", "PASS", "Successfully added AI provider.")
        else:
            print_result("TC-032", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-032", "FAIL", str(e))

def test_tc_033():
    """Sync Community Rules"""
    try:
        resp = requests.post(f"{BASE_URL}/api/rules/sync-community", headers=sa_headers, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-033", "PASS", "Successfully triggered community rules sync.")
        else:
            print_result("TC-033", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-033", "FAIL", str(e))

def test_tc_034():
    """Apply System Update"""
    try:
        resp = requests.post(f"{BASE_URL}/api/admin/apply-update", headers=sa_headers, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-034", "PASS", "Successfully triggered system update.")
        else:
            print_result("TC-034", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-034", "FAIL", str(e))

def test_tc_035():
    """View Scaling Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/scale-status", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-035", "PASS", "Successfully retrieved scaling status.")
        else:
            print_result("TC-035", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-035", "FAIL", str(e))

def test_tc_036():
    """List Client UI Errors"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/client-errors", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-036", "PASS", "Successfully retrieved client UI errors.")
        else:
            print_result("TC-036", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-036", "FAIL", str(e))

def test_tc_037():
    """Top IPs Across Tenants"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/top-ips-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-037", "PASS", "Successfully retrieved top IPs.")
        else:
            print_result("TC-037", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-037", "FAIL", str(e))

def test_tc_038():
    """Protocols Across Tenants"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/protocols-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-038", "PASS", "Successfully retrieved protocol stats.")
        else:
            print_result("TC-038", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-038", "FAIL", str(e))

def test_tc_039():
    """Global Threat Intel Matches"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/threat-intel-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-039", "PASS", "Successfully retrieved TI matches.")
        else:
            print_result("TC-039", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-039", "FAIL", str(e))

def test_tc_040():
    """Global Threat Map Data"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/threat-map-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-040", "PASS", "Successfully retrieved threat map data.")
        else:
            print_result("TC-040", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-040", "FAIL", str(e))

def test_tc_041():
    """Scale Engines"""
    try:
        payload = {"replicas": 3}
        resp = requests.post(f"{BASE_URL}/api/admin/engines/scale", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-041", "PASS", "Successfully triggered engine scaling.")
        else:
            print_result("TC-041", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-041", "FAIL", str(e))

def test_tc_042():
    """List Licenses"""
    try:
        resp = requests.get(f"{BASE_URL}/api/licenses", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-042", "PASS", "Successfully retrieved licenses.")
        else:
            print_result("TC-042", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-042", "FAIL", str(e))

def test_tc_043():
    """Generate License"""
    try:
        payload = {"tenant_id": "test-tenant", "features": ["ndr"]}
        resp = requests.post(f"{BASE_URL}/api/license/generate", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-043", "PASS", "Successfully generated license.")
        else:
            print_result("TC-043", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-043", "FAIL", str(e))

def test_tc_044():
    """Delete License"""
    try:
        resp = requests.delete(f"{BASE_URL}/api/licenses/test-license-id", headers=sa_headers, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-044", "PASS", "Successfully deleted license.")
        else:
            print_result("TC-044", "FAIL", f"DELETE failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-044", "FAIL", str(e))

def test_tc_045():
    """View Global IPAM Subnets"""
    try:
        resp = requests.get(f"{BASE_URL}/api/ipam/subnets", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-045", "PASS", "Successfully retrieved subnets.")
        else:
            print_result("TC-045", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-045", "FAIL", str(e))

def test_tc_046():
    """List Honeypots"""
    try:
        resp = requests.get(f"{BASE_URL}/api/honeypots", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-046", "PASS", "Successfully retrieved honeypots.")
        else:
            print_result("TC-046", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-046", "FAIL", str(e))

def test_tc_047():
    """Create Honeypot"""
    try:
        payload = {"ip": "10.0.0.100", "name": "Decoy"}
        resp = requests.post(f"{BASE_URL}/api/honeypots", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-047", "PASS", "Successfully created honeypot.")
        else:
            print_result("TC-047", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-047", "FAIL", str(e))

def test_tc_048():
    """Delete Honeypot"""
    try:
        resp = requests.delete(f"{BASE_URL}/api/honeypots/1", headers=sa_headers, verify=False)
        if resp.status_code in [200, 202, 204]:
            print_result("TC-048", "PASS", "Successfully deleted honeypot.")
        else:
            print_result("TC-048", "FAIL", f"DELETE failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-048", "FAIL", str(e))

def test_tc_049():
    """AI Suggest Trusted Domains"""
    try:
        resp = requests.post(f"{BASE_URL}/api/trusted-domains/ai-suggest", headers=sa_headers, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-049", "PASS", "Successfully generated AI suggestions.")
        else:
            print_result("TC-049", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-049", "FAIL", str(e))

def test_tc_050():
    """Add Manual IOC"""
    try:
        payload = {"ioc_type": "ip", "value": "1.2.3.4"}
        resp = requests.post(f"{BASE_URL}/api/threat-intel/add", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-050", "PASS", "Successfully added IOC.")
        else:
            print_result("TC-050", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-050", "FAIL", str(e))


def test_tc_051():
    """View Global Settings"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-051", "PASS", "Successfully retrieved settings.")
        else:
            print_result("TC-051", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-051", "FAIL", str(e))

def test_tc_052():
    """Update Global Settings"""
    try:
        payload = {'session_timeout': 30}
        resp = requests.post(f"{BASE_URL}/api/settings", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-052", "PASS", "Successfully updated settings.")
        else:
            print_result("TC-052", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-052", "FAIL", str(e))

def test_tc_053():
    """View Global SMTP"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/smtp", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-053", "PASS", "Successfully retrieved SMTP settings.")
        else:
            print_result("TC-053", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-053", "FAIL", str(e))

def test_tc_054():
    """Update Global SMTP"""
    try:
        payload = {'host': 'smtp.example.com', 'port': 587}
        resp = requests.post(f"{BASE_URL}/api/settings/smtp", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-054", "PASS", "Successfully updated SMTP settings.")
        else:
            print_result("TC-054", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-054", "FAIL", str(e))

def test_tc_055():
    """View AI Config"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/ai", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-055", "PASS", "Successfully retrieved AI config.")
        else:
            print_result("TC-055", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-055", "FAIL", str(e))

def test_tc_056():
    """Update AI Config"""
    try:
        payload = {'enabled': True}
        resp = requests.post(f"{BASE_URL}/api/settings/ai", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-056", "PASS", "Successfully updated AI config.")
        else:
            print_result("TC-056", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-056", "FAIL", str(e))

def test_tc_057():
    """View Trusted Domains"""
    try:
        resp = requests.get(f"{BASE_URL}/api/trusted-domains", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-057", "PASS", "Successfully retrieved trusted domains.")
        else:
            print_result("TC-057", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-057", "FAIL", str(e))

def test_tc_058():
    """Add Trusted Domain"""
    try:
        payload = {'domain': 'example.com'}
        resp = requests.post(f"{BASE_URL}/api/trusted-domains", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-058", "PASS", "Successfully added trusted domain.")
        else:
            print_result("TC-058", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-058", "FAIL", str(e))

def test_tc_059():
    """Delete Trusted Domain"""
    try:
        payload = {'domain': 'example.com'}
        resp = requests.post(f"{BASE_URL}/api/trusted-domains/delete", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-059", "PASS", "Successfully deleted trusted domain.")
        else:
            print_result("TC-059", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-059", "FAIL", str(e))

def test_tc_060():
    """View DoH Providers"""
    try:
        resp = requests.get(f"{BASE_URL}/api/doh-providers", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-060", "PASS", "Successfully retrieved DoH providers.")
        else:
            print_result("TC-060", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-060", "FAIL", str(e))

def test_tc_061():
    """Add DoH Provider"""
    try:
        payload = {'ip': '8.8.8.8', 'name': 'Google'}
        resp = requests.post(f"{BASE_URL}/api/doh-providers", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-061", "PASS", "Successfully added DoH provider.")
        else:
            print_result("TC-061", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-061", "FAIL", str(e))

def test_tc_062():
    """View Sensor Keys"""
    try:
        resp = requests.get(f"{BASE_URL}/api/sensor-keys", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-062", "PASS", "Successfully retrieved sensor keys.")
        else:
            print_result("TC-062", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-062", "FAIL", str(e))

def test_tc_063():
    """View AI Activity"""
    try:
        resp = requests.get(f"{BASE_URL}/api/ai-activity", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-063", "PASS", "Successfully retrieved AI activity.")
        else:
            print_result("TC-063", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-063", "FAIL", str(e))

def test_tc_064():
    """Monitor Kafka"""
    try:
        resp = requests.get(f"{BASE_URL}/api/monitor/kafka", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-064", "PASS", "Successfully retrieved Kafka status.")
        else:
            print_result("TC-064", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-064", "FAIL", str(e))

def test_tc_065():
    """View Retrospective Scans"""
    try:
        resp = requests.get(f"{BASE_URL}/api/retrospective/scans", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-065", "PASS", "Successfully retrieved retrospective scans.")
        else:
            print_result("TC-065", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-065", "FAIL", str(e))

def test_tc_066():
    """View Global Severity"""
    try:
        resp = requests.get(f"{BASE_URL}/api/admin/severity-all-tenants", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-066", "PASS", "Successfully retrieved severity stats.")
        else:
            print_result("TC-066", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-066", "FAIL", str(e))

def test_tc_067():
    """View Interfaces"""
    try:
        resp = requests.get(f"{BASE_URL}/api/interfaces", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-067", "PASS", "Successfully retrieved interfaces.")
        else:
            print_result("TC-067", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-067", "FAIL", str(e))

def test_tc_068():
    """View Agent Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/agent-status", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-068", "PASS", "Successfully retrieved agent status.")
        else:
            print_result("TC-068", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-068", "FAIL", str(e))

def test_tc_069():
    """View Unified Stats"""
    try:
        resp = requests.get(f"{BASE_URL}/api/stats/unified", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-069", "PASS", "Successfully retrieved unified stats.")
        else:
            print_result("TC-069", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-069", "FAIL", str(e))

def test_tc_070():
    """View Network Map"""
    try:
        resp = requests.get(f"{BASE_URL}/api/network-map", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-070", "PASS", "Successfully retrieved network map.")
        else:
            print_result("TC-070", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-070", "FAIL", str(e))

def test_tc_071():
    """View Scale Status"""
    try:
        resp = requests.get(f"{BASE_URL}/api/scale-status", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-071", "PASS", "Successfully retrieved scale status.")
        else:
            print_result("TC-071", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-071", "FAIL", str(e))

def test_tc_072():
    """View Rule Hit Counts"""
    try:
        resp = requests.get(f"{BASE_URL}/api/rules/hit-counts", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-072", "PASS", "Successfully retrieved rule hit counts.")
        else:
            print_result("TC-072", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-072", "FAIL", str(e))

def test_tc_073():
    """View Threat Intel Map"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel-map", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-073", "PASS", "Successfully retrieved threat intel map.")
        else:
            print_result("TC-073", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-073", "FAIL", str(e))

def test_tc_074():
    """View Threat Intel Watchlist"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel/watchlist", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-074", "PASS", "Successfully retrieved TI watchlist.")
        else:
            print_result("TC-074", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-074", "FAIL", str(e))

def test_tc_075():
    """Trigger Global Export"""
    try:
        resp = requests.get(f"{BASE_URL}/api/export", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-075", "PASS", "Successfully retrieved export.")
        else:
            print_result("TC-075", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-075", "FAIL", str(e))

def test_tc_076():
    """View License Public Key"""
    try:
        resp = requests.get(f"{BASE_URL}/api/license/public-key", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-076", "PASS", "Successfully retrieved public key.")
        else:
            print_result("TC-076", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-076", "FAIL", str(e))

def test_tc_077():
    """View Tenant Features"""
    try:
        resp = requests.get(f"{BASE_URL}/api/tenant/features", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-077", "PASS", "Successfully retrieved tenant features.")
        else:
            print_result("TC-077", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-077", "FAIL", str(e))

def test_tc_078():
    """View AI Providers"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/ai/providers", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-078", "PASS", "Successfully retrieved AI providers.")
        else:
            print_result("TC-078", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-078", "FAIL", str(e))

def test_tc_079():
    """View Trusted Cloud Settings"""
    try:
        resp = requests.get(f"{BASE_URL}/api/settings/trusted-cloud", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-079", "PASS", "Successfully retrieved trusted cloud settings.")
        else:
            print_result("TC-079", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-079", "FAIL", str(e))

def test_tc_080():
    """View Subnet Roles"""
    try:
        resp = requests.get(f"{BASE_URL}/api/assets/subnet-roles", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-080", "PASS", "Successfully retrieved subnet roles.")
        else:
            print_result("TC-080", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-080", "FAIL", str(e))

def test_tc_081():
    """Force Logout User"""
    try:
        resp = requests.delete(f"{BASE_URL}/api/admin/sessions/testuser", headers=sa_headers, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-081", "PASS", "Successfully triggered force logout.")
        else:
            print_result("TC-081", "FAIL", f"DELETE failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-081", "FAIL", str(e))

def test_tc_082():
    """View System Health"""
    try:
        resp = requests.get(f"{BASE_URL}/api/health", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-082", "PASS", "Successfully retrieved system health.")
        else:
            print_result("TC-082", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-082", "FAIL", str(e))

def test_tc_083():
    """Export System Logs"""
    try:
        resp = requests.get(f"{BASE_URL}/api/export-logs", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-083", "PASS", "Successfully retrieved system logs.")
        else:
            print_result("TC-083", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-083", "FAIL", str(e))

def test_tc_084():
    """View Announcements"""
    try:
        resp = requests.get(f"{BASE_URL}/api/announcements", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-084", "PASS", "Successfully retrieved announcements.")
        else:
            print_result("TC-084", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-084", "FAIL", str(e))

def test_tc_085():
    """View Support Messages"""
    try:
        resp = requests.get(f"{BASE_URL}/api/support/messages", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-085", "PASS", "Successfully retrieved support messages.")
        else:
            print_result("TC-085", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-085", "FAIL", str(e))

def test_tc_086():
    """View Threat Predictions"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat/predictions", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-086", "PASS", "Successfully retrieved threat predictions.")
        else:
            print_result("TC-086", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-086", "FAIL", str(e))

def test_tc_087():
    """View Threat Exposure"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat/exposure", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-087", "PASS", "Successfully retrieved threat exposure.")
        else:
            print_result("TC-087", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-087", "FAIL", str(e))

def test_tc_088():
    """View All Assets"""
    try:
        resp = requests.get(f"{BASE_URL}/api/assets", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-088", "PASS", "Successfully retrieved assets.")
        else:
            print_result("TC-088", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-088", "FAIL", str(e))

def test_tc_089():
    """View Detection Rules"""
    try:
        resp = requests.get(f"{BASE_URL}/api/rules", headers=sa_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-089", "PASS", "Successfully retrieved detection rules.")
        else:
            print_result("TC-089", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-089", "FAIL", str(e))

def test_tc_090():
    """Perform Geo Lookup"""
    try:
        payload = {'ip': '8.8.8.8'}
        resp = requests.post(f"{BASE_URL}/api/geo-lookup", headers=sa_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 204]:
            print_result("TC-090", "PASS", "Successfully retrieved geo lookup data.")
        else:
            print_result("TC-090", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-090", "FAIL", str(e))

def test_tc_091():
    """Analyst - View Assigned Alerts"""
    try:
        resp = requests.get(f"{BASE_URL}/api/xdr/alerts?assigned_to=me", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-091", "PASS", "Successfully retrieved assigned alerts.")
        else:
            print_result("TC-091", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-091", "FAIL", str(e))

def test_tc_092(alert_id="test-alert-id"):
    """Analyst - Acknowledge Alert"""
    try:
        resp = requests.post(f"{BASE_URL}/api/xdr/alerts/{alert_id}/acknowledge", headers=analyst_headers, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-092", "PASS", "Successfully acknowledged alert.")
        else:
            print_result("TC-092", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-092", "FAIL", str(e))

def test_tc_093(alert_id="test-alert-id"):
    """Analyst - Add Alert Comment"""
    try:
        payload = {"comment": "Investigating this issue."}
        resp = requests.post(f"{BASE_URL}/api/xdr/alerts/{alert_id}/comments", headers=analyst_headers, json=payload, verify=False)
        if resp.status_code in [200, 201]:
            print_result("TC-093", "PASS", "Successfully added comment to alert.")
        else:
            print_result("TC-093", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-093", "FAIL", str(e))

def test_tc_094(alert_id="test-alert-id"):
    """Analyst - View Alert Details"""
    try:
        resp = requests.get(f"{BASE_URL}/api/xdr/alerts/{alert_id}", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-094", "PASS", "Successfully retrieved alert details.")
        else:
            print_result("TC-094", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-094", "FAIL", str(e))

def test_tc_095():
    """Analyst - Search Logs (Scoped)"""
    try:
        resp = requests.get(f"{BASE_URL}/api/siem/logs?query=error", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-095", "PASS", "Successfully searched logs.")
        else:
            print_result("TC-095", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-095", "FAIL", str(e))

def test_tc_096():
    """Analyst - View Threat Intel"""
    try:
        resp = requests.get(f"{BASE_URL}/api/threat-intel", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-096", "PASS", "Successfully retrieved threat intel.")
        else:
            print_result("TC-096", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-096", "FAIL", str(e))

def test_tc_097():
    """Analyst - View Network Map (Read-Only)"""
    try:
        resp = requests.get(f"{BASE_URL}/api/network-map", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-097", "PASS", "Successfully retrieved network map.")
        else:
            print_result("TC-097", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-097", "FAIL", str(e))

def test_tc_098():
    """Analyst - Create Report"""
    try:
        payload = {"type": "daily_summary"}
        resp = requests.post(f"{BASE_URL}/api/reports/generate", headers=analyst_headers, json=payload, verify=False)
        if resp.status_code in [200, 201, 202]:
            print_result("TC-098", "PASS", "Successfully generated report.")
        else:
            print_result("TC-098", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-098", "FAIL", str(e))

def test_tc_099():
    """Analyst - View Own Profile"""
    try:
        resp = requests.get(f"{BASE_URL}/api/auth/me", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-099", "PASS", "Successfully retrieved user profile.")
        else:
            print_result("TC-099", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-099", "FAIL", str(e))

def test_tc_100():
    """Analyst - Update Own Password"""
    try:
        payload = {"password": "new_secure_password"}
        resp = requests.post(f"{BASE_URL}/api/auth/reset-password", headers=analyst_headers, json=payload, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-100", "PASS", "Successfully updated password.")
        else:
            print_result("TC-100", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-100", "FAIL", str(e))

def test_tc_101():
    """Analyst - View Rules (Read-Only)"""
    try:
        resp = requests.get(f"{BASE_URL}/api/siem/rules", headers=analyst_headers, verify=False)
        if resp.status_code == 200:
            print_result("TC-101", "PASS", "Successfully retrieved rules.")
        else:
            print_result("TC-101", "FAIL", f"GET failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-101", "FAIL", str(e))

def test_tc_102(alert_id="test-alert-id"):
    """Analyst - Reject Alert (False Positive)"""
    try:
        resp = requests.post(f"{BASE_URL}/api/xdr/alerts/{alert_id}/reject", headers=analyst_headers, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-102", "PASS", "Successfully rejected alert.")
        else:
            print_result("TC-102", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-102", "FAIL", str(e))

def test_tc_103():
    """Analyst - Access Admin Config (Negative)"""
    try:
        resp = requests.get(f"{BASE_URL}/api/auth/tenants", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-103", "PASS", "Correctly denied access to admin config.")
        else:
            print_result("TC-103", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-103", "FAIL", str(e))

def test_tc_104(user_id="test-user-id"):
    """Analyst - Delete User (Negative)"""
    try:
        resp = requests.delete(f"{BASE_URL}/api/auth/users/{user_id}", headers=analyst_headers, verify=False)
        if resp.status_code == 403:
            print_result("TC-104", "PASS", "Correctly denied access to delete user.")
        else:
            print_result("TC-104", "FAIL", f"Expected 403, got {resp.status_code}")
    except Exception as e:
        print_result("TC-104", "FAIL", str(e))

def test_tc_105(alert_id="test-alert-id"):
    """Analyst - Escalate Alert"""
    try:
        resp = requests.post(f"{BASE_URL}/api/xdr/alerts/{alert_id}/escalate", headers=analyst_headers, verify=False)
        if resp.status_code in [200, 204]:
            print_result("TC-105", "PASS", "Successfully escalated alert.")
        else:
            print_result("TC-105", "FAIL", f"POST failed with {resp.status_code}")
    except Exception as e:
        print_result("TC-105", "FAIL", str(e))


if __name__ == "__main__":
    print("Starting Automated Tests (TC-051 to TC-065)...")
    print("-" * 50)
    # Older tests commented out per instruction
    # test_tc_026()
    # test_tc_027()
    # test_tc_028()
    # test_tc_029()
    # test_tc_030()
    # test_tc_031()
    # test_tc_032()
    # test_tc_033()
    # test_tc_034()
    # test_tc_035()
    # test_tc_036()
    # test_tc_037()
    # test_tc_038()
    # test_tc_039()
    # test_tc_040()
    # test_tc_041()
    # test_tc_042()
    # test_tc_043()
    # test_tc_044()
    # test_tc_045()
    # test_tc_046()
    # test_tc_047()
    # test_tc_048()
    # test_tc_049()
    # test_tc_050()
    print(f"Starting Automated Tests (TC-081 to TC-090)...")
    print("-" * 50)
    
    # Execute the tests
    # test_tc_066()
    # test_tc_067()
    # test_tc_068()
    # test_tc_069()
    # test_tc_070()
    # test_tc_071()
    # test_tc_072()
    # test_tc_073()
    # test_tc_074()
    # test_tc_075()
    # test_tc_076()
    # test_tc_077()
    # test_tc_078()
    # test_tc_079()
    # test_tc_080()
    
    # test_tc_081()
    # test_tc_082()
    # test_tc_083()
    # test_tc_084()
    # test_tc_085()
    # test_tc_086()
    # test_tc_087()
    # test_tc_088()
    # test_tc_089()
    # test_tc_090()
    
    print(f"Starting Analyst Automated Tests (TC-091 to TC-105)...")
    print("-" * 50)
    
    # Dynamically fetch IDs
    test_alert_id = "test-alert-id"
    test_user_id = "test-user-id"
    try:
        # We use sa_headers to fetch them so we are sure they exist
        alert_resp = requests.get(f"{BASE_URL}/api/xdr/alerts", headers=sa_headers, verify=False)
        if alert_resp.status_code == 200 and 'alerts' in alert_resp.json():
            alerts_list = alert_resp.json().get('alerts', [])
            if alerts_list:
                test_alert_id = alerts_list[0].get('alert_id', 'test-alert-id')
            
        user_resp = requests.get(f"{BASE_URL}/api/auth/users", headers=sa_headers, verify=False)
        if user_resp.status_code == 200 and 'users' in user_resp.json():
            users_list = user_resp.json().get('users', [])
            if users_list:
                test_user_id = users_list[0].get('id', 'test-user-id')
            
        print(f"[*] Dynamically loaded alert_id: {test_alert_id}")
        print(f"[*] Dynamically loaded user_id: {test_user_id}")
    except Exception as e:
        print(f"[!] Warning: Could not fetch dynamic IDs. Using defaults. Error: {e}")
    print("-" * 50)
    
    test_tc_091()
    test_tc_092(test_alert_id)
    test_tc_093(test_alert_id)
    test_tc_094(test_alert_id)
    test_tc_095()
    test_tc_096()
    test_tc_097()
    test_tc_098()
    test_tc_099()
    test_tc_100()
    test_tc_101()
    test_tc_102(test_alert_id)
    test_tc_103()
    test_tc_104(test_user_id)
    test_tc_105(test_alert_id)

    print("-" * 50)
    print("Tests complete. Please record the results.")
