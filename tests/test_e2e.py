import asyncio
import os
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Mock HTTP Server to simulate target web application
class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.49 (Unix)")
            self.send_header("X-Powered-By", "PHP/8.1.0-dev")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Secure Internal Portal</title></head><body><h1>Welcome</h1></body></html>")
        elif self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>Admin Dashboard</title></head><body>Admin Panel</body></html>")
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=SuperSecret123!\nAPP_SECRET=xyz789\n")
        elif self.path == "/api/v1":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok","version":"1.0.0"}')
        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.49 (Unix)")
        self.send_header("X-Powered-By", "PHP/8.1.0-dev")
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress mock server log
        pass


def run_server(server):
    server.serve_forever()


def test_full_pipeline():
    port = 18080
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    server_thread = threading.Thread(target=run_server, args=(server,), daemon=True)
    server_thread.start()
    print(f"[*] Mock target server running on http://127.0.0.1:{port}")
    time.sleep(0.5)

    import subprocess
    cmd = [
        sys.executable, "main.py", "scan", "127.0.0.1",
        "-p", str(port),
        "-t", "10",
        "--authorized",
        "-o", "output"
    ]
    print(f"[*] Executing pipeline command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    # Check generated files
    assert os.path.exists("output/hosts.json"), "hosts.json missing"
    assert os.path.exists("output/ports.json"), "ports.json missing"
    assert os.path.exists("output/services.json"), "services.json missing"
    assert os.path.exists("output/vulns.json"), "vulns.json missing"
    assert os.path.exists("output/dirs.json"), "dirs.json missing"
    assert os.path.exists("output/report.html"), "report.html missing"
    assert os.path.exists("output/audit.log"), "audit.log missing"

    with open("output/services.json", "r", encoding="utf-8") as f:
        services_data = f.read()
        assert "Apache" in services_data or "2.4.49" in services_data or "http" in services_data
        print("[+] Verified services.json contains detected web service.")

    with open("output/vulns.json", "r", encoding="utf-8") as f:
        vulns_data = f.read()
        assert "CVE-2021-41773" in vulns_data
        print("[+] Verified vulns.json contains matched CVE-2021-41773 vulnerability!")

    with open("output/dirs.json", "r", encoding="utf-8") as f:
        dirs_data = f.read()
        assert "admin" in dirs_data or ".env" in dirs_data
        print("[+] Verified dirs.json contains discovered web directories (.env, admin, etc.)!")

    with open("output/report.html", "r", encoding="utf-8") as f:
        report_data = f.read()
        assert "Ağ Recon & Güvenlik Raporu" in report_data
        assert "CVE-2021-41773" in report_data
        print("[+] Verified report.html contains full executive report with CVEs and findings!")

    server.shutdown()
    print("[SUCCESS] All End-to-End pipeline checks passed successfully!")


if __name__ == "__main__":
    test_full_pipeline()
