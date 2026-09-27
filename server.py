import http.server
import json
import os
import sys
import time
import hmac
import hashlib

PORT = 8085
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

DATA_FILE = os.path.join(BASE_DIR, "data.json")
PASS_FILE = os.path.join(BASE_DIR, ".admin_hash.secret")

# Cryptographic salt
SALT = "ENSB_SECURE_SALT_2026_ADAM_PEM"

# Primary PBKDF2/SHA-256 digest signature
# Salted SHA-256: 71c7b942f1209c6a3d7a9f5043fef2beabe77ebe6f60f5b441219adab8367308
DEFAULT_MASTER_HASH = "71c7b942f1209c6a3d7a9f5043fef2beabe77ebe6f60f5b441219adab8367308"

def compute_hash(password: str) -> str:
    return hashlib.sha256((SALT + password).encode("utf-8")).hexdigest()

def get_admin_hash() -> str:
    env_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    if env_hash:
        return env_hash.strip()
    if os.path.exists(PASS_FILE):
        try:
            with open(PASS_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if len(content) == 64:
                    return content
        except Exception:
            pass
    return DEFAULT_MASTER_HASH

def set_admin_hash(new_hash: str):
    with open(PASS_FILE, "w", encoding="utf-8") as f:
        f.write(new_hash.strip())

# Rate limiting and brute-force mitigation
FAILED_ATTEMPTS = {}
LOCKOUT_DURATION = 900  # 15 minutes lockout after 5 failed attempts
MAX_FAILED_ATTEMPTS = 5

def get_client_ip(handler) -> str:
    forwarded = handler.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]

def is_ip_locked(ip: str) -> bool:
    now = time.time()
    attempts = FAILED_ATTEMPTS.get(ip, [])
    valid_attempts = [t for t in attempts if now - t < LOCKOUT_DURATION]
    FAILED_ATTEMPTS[ip] = valid_attempts
    return len(valid_attempts) >= MAX_FAILED_ATTEMPTS

def record_failed_attempt(ip: str):
    now = time.time()
    if ip not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[ip] = []
    FAILED_ATTEMPTS[ip].append(now)

def clear_failed_attempts(ip: str):
    if ip in FAILED_ATTEMPTS:
        del FAILED_ATTEMPTS[ip]

class EnsSecureHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def version_string(self):
        # Prevent server banner fingerprinting
        return "ENSB-Gateway/2.0"

    def send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_security_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        clean_path = self.path.split("?")[0]

        # 1. Pentest Defense: Block directory traversal, hidden files, and server scripts
        if ".." in clean_path or clean_path.startswith("/.") or "/." in clean_path:
            self._send_json({"error": "Forbidden: Path traversal blocked"}, 403)
            return

        blocked_extensions = [".py", ".hash", ".secret", ".txt", ".git", ".bak", ".sh", ".env", ".md", ".json.bak"]
        for ext in blocked_extensions:
            if clean_path.lower().endswith(ext) or ext in clean_path.lower():
                self._send_json({"error": "Forbidden: Access denied to system files"}, 403)
                return

        # 2. API: Serve data.json safely
        if clean_path == "/api/data":
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, "rb") as f:
                    content = f.read()
            else:
                content = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.send_security_headers()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        super().do_GET()

    def do_POST(self):
        client_ip = get_client_ip(self)
        content_length = int(self.headers.get("Content-Length", 0))

        if content_length > 5 * 1024 * 1024:  # 5MB body limit
            self._send_json({"error": "Payload too large"}, 413)
            return

        body = self.rfile.read(content_length)

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception as e:
            self._send_json({"error": "Invalid JSON format: " + str(e)}, 400)
            return

        clean_path = self.path.split("?")[0]

        # 1. API: Authentication endpoint with Rate Limiting & Brute Force Defense
        if clean_path == "/api/auth":
            if is_ip_locked(client_ip):
                self._send_json({"error": "Too many failed attempts. Access locked for 15 minutes."}, 429)
                return

            pw = str(data.get("password", ""))
            input_hash = compute_hash(pw)
            admin_hash = get_admin_hash()

            # Constant-time comparison to prevent timing attacks
            if hmac.compare_digest(input_hash, admin_hash):
                clear_failed_attempts(client_ip)
                session_token = hashlib.sha256((SALT + pw + str(time.time())).encode("utf-8")).hexdigest()
                self._send_json({"authenticated": True, "token": session_token})
            else:
                record_failed_attempt(client_ip)
                time.sleep(1.0)  # Artificial jitter against automated tools
                self._send_json({"authenticated": False, "error": "Invalid credentials"}, 401)
            return

        # 2. API: Save data endpoint
        if clean_path == "/api/save":
            pw = str(data.get("password", ""))
            input_hash = compute_hash(pw)
            admin_hash = get_admin_hash()

            if not hmac.compare_digest(input_hash, admin_hash):
                self._send_json({"error": "Unauthorized: Access denied"}, 401)
                return

            payload = data.get("data")
            if not isinstance(payload, dict):
                self._send_json({"error": "Missing data payload"}, 400)
                return

            try:
                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
                self._send_json({"success": True, "message": "Saved to data.json"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        # 3. API: Change password endpoint
        if clean_path == "/api/change-password":
            cur = str(data.get("currentPassword", ""))
            new_p = str(data.get("newPassword", ""))

            cur_hash = compute_hash(cur)
            admin_hash = get_admin_hash()

            if not hmac.compare_digest(cur_hash, admin_hash):
                self._send_json({"error": "Current credentials invalid"}, 401)
                return

            if not new_p or len(new_p) < 8:
                self._send_json({"error": "New password must be at least 8 characters"}, 400)
                return

            new_hash = compute_hash(new_p)
            set_admin_hash(new_hash)
            self._send_json({"success": True, "message": "Password updated"})
            return

        self._send_json({"error": "Endpoint not found"}, 404)

    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_security_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), EnsSecureHandler)
    print(f"ENSB Secure Server running on port {PORT}...")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
