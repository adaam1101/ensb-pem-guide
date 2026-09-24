import http.server
import json
import os
import sys

PORT = 8085
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

DATA_FILE = os.path.join(BASE_DIR, "data.json")
PASS_FILE = os.path.join(BASE_DIR, "admin_pass.txt")

def get_admin_pass():
    if os.path.exists(PASS_FILE):
        try:
            with open(PASS_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return "admin123"
    return "admin123"

def set_admin_pass(new_p):
    with open(PASS_FILE, "w", encoding="utf-8") as f:
        f.write(new_p.strip())

class EnsHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/api/data" or self.path.startswith("/api/data?"):
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, "rb") as f:
                    content = f.read()
            else:
                content = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        super().do_GET()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception as e:
            self._send_json({"error": "Bad JSON: " + str(e)}, 400)
            return

        if self.path == "/api/auth":
            pw = data.get("password", "")
            if pw == get_admin_pass():
                self._send_json({"authenticated": True})
            else:
                self._send_json({"authenticated": False, "error": "Wrong password"}, 401)
            return

        if self.path == "/api/save":
            pw = data.get("password", "")
            if pw != get_admin_pass():
                self._send_json({"error": "Unauthorized: Password incorrect"}, 401)
                return

            payload = data.get("data")
            if not isinstance(payload, dict):
                self._send_json({"error": "Missing data dict"}, 400)
                return

            try:
                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
                self._send_json({"success": True, "message": "Saved to data.json"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if self.path == "/api/change-password":
            cur = data.get("currentPassword", "")
            new_p = data.get("newPassword", "")
            if cur != get_admin_pass():
                self._send_json({"error": "Current password incorrect"}, 401)
                return
            if not new_p or len(new_p) < 4:
                self._send_json({"error": "Password too short"}, 400)
                return
            set_admin_pass(new_p)
            self._send_json({"success": True})
            return

        self._send_json({"error": "Not found"}, 404)

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), EnsHandler)
    print(f"ENSB Server running on port {PORT}...")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
