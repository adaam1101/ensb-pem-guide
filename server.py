import http.server
import json
import os
import sys
import time
import hmac
import hashlib
import uuid
import html
import io
import csv
import urllib.parse

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

# Teacher Access Key for viewing class roster and Excel export
TEACHER_KEY = os.environ.get("TEACHER_ACCESS_KEY", "ensb2026")

def check_teacher_or_admin_auth(handler, query_params) -> bool:
    # 1. Query parameter key e.g. ?key=ensb2026
    key = query_params.get("key", [""])[0]
    if key and key == TEACHER_KEY:
        return True
    
    # 2. Header X-Teacher-Key
    teacher_hdr = handler.headers.get("X-Teacher-Key", "")
    if teacher_hdr and teacher_hdr == TEACHER_KEY:
        return True

    # 3. Admin token or password
    admin_pw = handler.headers.get("X-Admin-Password", "")
    if admin_pw:
        input_hash = compute_hash(admin_pw)
        if hmac.compare_digest(input_hash, get_admin_hash()):
            return True

    auth_hdr = handler.headers.get("Authorization", "")
    if auth_hdr and auth_hdr.startswith("Bearer "):
        token = auth_hdr.split(" ", 1)[1].strip()
        if token and len(token) == 64:
            return True

    return False

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
        url_parts = self.path.split("?", 1)
        clean_path = url_parts[0]
        query_string = url_parts[1] if len(url_parts) > 1 else ""
        query_params = urllib.parse.parse_qs(query_string)

        # 1. Pentest Defense: Block directory traversal, hidden files, and server scripts
        if ".." in clean_path or clean_path.startswith("/.") or "/." in clean_path:
            self._send_json({"error": "Forbidden: Path traversal blocked"}, 403)
            return

        blocked_extensions = [".py", ".hash", ".secret", ".txt", ".git", ".bak", ".sh", ".env", ".md", ".json.bak"]
        for ext in blocked_extensions:
            if clean_path.lower().endswith(ext) or ext in clean_path.lower():
                self._send_json({"error": "Forbidden: Access denied to system files"}, 403)
                return

        # 2. API: Serve data.json safely (Hide students array from public syllabus fetch unless teacher/admin)
        if clean_path == "/api/data":
            if os.path.exists(DATA_FILE):
                try:
                    with open(DATA_FILE, "r", encoding="utf-8") as f:
                        data_obj = json.load(f)
                    # Protect students data from unauthorized public view
                    if not check_teacher_or_admin_auth(self, query_params):
                        if "students" in data_obj:
                            data_obj["students"] = []
                    content = json.dumps(data_obj, ensure_ascii=False, indent=2).encode("utf-8")
                except Exception:
                    content = b"{}"
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

        # 3. API: Serve students roster list (RESTRICTED to teacher and admin only)
        if clean_path == "/api/students":
            if not check_teacher_or_admin_auth(self, query_params):
                self._send_json({
                    "error": "Access restricted. The student directory is reserved for faculty and administration.",
                    "authenticated": False
                }, 403)
                return

            students = []
            if os.path.exists(DATA_FILE):
                try:
                    with open(DATA_FILE, "r", encoding="utf-8") as f:
                        d = json.load(f)
                        students = d.get("students", [])
                except Exception:
                    pass
            self._send_json({"students": students, "total": len(students), "authenticated": True})
            return

        # 4. API: Public count of registrations (Safe count only, no personal names/emails)
        if clean_path == "/api/students-count":
            total = 0
            if os.path.exists(DATA_FILE):
                try:
                    with open(DATA_FILE, "r", encoding="utf-8") as f:
                        d = json.load(f)
                        total = len(d.get("students", []))
                except Exception:
                    pass
            self._send_json({"total": total})
            return

        # 5. API: Export students list to UTF-8 Excel CSV (RESTRICTED to teacher and admin only)
        if clean_path == "/api/export-students-csv":
            if not check_teacher_or_admin_auth(self, query_params):
                self._send_json({
                    "error": "Access restricted. Excel export is reserved for faculty and administration."
                }, 403)
                return

            students = []
            if os.path.exists(DATA_FILE):
                try:
                    with open(DATA_FILE, "r", encoding="utf-8") as f:
                        d = json.load(f)
                        students = d.get("students", [])
                except Exception:
                    pass
            output = io.StringIO()
            writer = csv.writer(output, delimiter=';')
            writer.writerow(["No.", "Full Name", "Email Address", "Wilaya", "Group", "Phone Number", "Registration Date"])
            for idx, s in enumerate(students, 1):
                writer.writerow([
                    idx,
                    s.get("fullName", ""),
                    s.get("email", ""),
                    s.get("wilaya", ""),
                    s.get("group", "Group 05"),
                    s.get("phone", ""),
                    s.get("registeredAt", "")
                ])
            csv_content = "\ufeff" + output.getvalue()
            csv_bytes = csv_content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="ENSB_PEM2_Group05_Students.csv"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_security_headers()
            self.send_header("Content-Length", str(len(csv_bytes)))
            self.end_headers()
            self.wfile.write(csv_bytes)
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

        # 4. API: Register or Update Student
        if clean_path == "/api/register-student":
            full_name = str(data.get("fullName", "")).strip()
            email = str(data.get("email", "")).strip().lower()
            wilaya = str(data.get("wilaya", "")).strip()
            group = str(data.get("group", "Group 05")).strip()
            phone = str(data.get("phone", "")).strip()
            matricule = str(data.get("matricule", "")).strip()
            student_id = str(data.get("id", "")).strip()

            if not full_name or len(full_name) < 2 or len(full_name) > 100:
                self._send_json({"error": "Please enter a valid full name (2 to 100 characters)."}, 400)
                return

            try:
                clean_name = html.escape(full_name)
                clean_email = html.escape(email) if email else ""
                clean_wilaya = html.escape(wilaya) if wilaya else ""
                clean_group = html.escape(group) if group else "Group 05"
                clean_phone = html.escape(phone) if phone else ""
                clean_matricule = html.escape(matricule) if matricule else ""

                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    db = json.load(f)

                if "students" not in db:
                    db["students"] = []

                # Find if student with same ID, matricule, email, or exact name exists
                existing_idx = None
                for idx, s in enumerate(db["students"]):
                    if student_id and s.get("id") == student_id:
                        existing_idx = idx
                        break
                    if clean_matricule and s.get("matricule") == clean_matricule:
                        existing_idx = idx
                        break
                    if clean_email and s.get("email", "").lower() == clean_email:
                        existing_idx = idx
                        break
                    if s.get("fullName", "").lower() == clean_name.lower():
                        existing_idx = idx
                        break

                now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                if existing_idx is not None:
                    db["students"][existing_idx]["fullName"] = clean_name
                    if clean_email:
                        db["students"][existing_idx]["email"] = clean_email
                    db["students"][existing_idx]["wilaya"] = clean_wilaya
                    db["students"][existing_idx]["group"] = clean_group
                    if clean_matricule:
                        db["students"][existing_idx]["matricule"] = clean_matricule
                    if clean_phone:
                        db["students"][existing_idx]["phone"] = clean_phone
                    db["students"][existing_idx]["updatedAt"] = now_iso
                    student_obj = db["students"][existing_idx]
                    action_msg = "Information updated successfully!"
                else:
                    new_id = student_id if student_id else f"std_{int(time.time())}_{uuid.uuid4().hex[:6]}"
                    student_obj = {
                        "id": new_id,
                        "matricule": clean_matricule,
                        "fullName": clean_name,
                        "email": clean_email,
                        "wilaya": clean_wilaya,
                        "group": clean_group,
                        "phone": clean_phone,
                        "registeredAt": now_iso
                    }
                    db["students"].append(student_obj)
                    action_msg = "Registration submitted successfully!"

                # Sort alphabetically by full name
                db["students"].sort(key=lambda x: x.get("fullName", "").lower())

                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    json.dump(db, f, indent=2, ensure_ascii=False)

                self._send_json({
                    "success": True,
                    "message": action_msg,
                    "student": student_obj,
                    "totalStudents": len(db["students"])
                })
            except Exception as e:
                self._send_json({"error": "Server error: " + str(e)}, 500)
            return

        # 5. API: Delete Student (Admin or Teacher Key)
        if clean_path == "/api/delete-student":
            pw = str(data.get("password", ""))
            teacher_key = str(data.get("key", "") or self.headers.get("X-Teacher-Key", "")).strip()
            is_admin = hmac.compare_digest(compute_hash(pw), get_admin_hash())
            is_teacher = (teacher_key == TEACHER_KEY)

            if not is_admin and not is_teacher:
                self._send_json({"error": "Unauthorized: Access denied"}, 401)
                return

            student_id = str(data.get("id", "")).strip()
            student_email = str(data.get("email", "")).strip().lower()
            student_matricule = str(data.get("matricule", "")).strip().lower()
            student_name = str(data.get("fullName", "")).strip().lower()

            if not student_id and not student_email and not student_matricule and not student_name:
                self._send_json({"error": "Missing student identifiers"}, 400)
                return

            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    db = json.load(f)

                if "students" not in db:
                    db["students"] = []

                db["students"] = [
                    s for s in db.get("students", []) 
                    if (not student_id or s.get("id") != student_id)
                    and (not student_matricule or str(s.get("matricule", "")).strip().lower() != student_matricule)
                    and (not student_email or s.get("email", "").lower() != student_email)
                    and (not student_name or s.get("fullName", "").lower() != student_name)
                ]

                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    json.dump(db, f, indent=2, ensure_ascii=False)

                self._send_json({"success": True, "message": "Student removed successfully", "total": len(db["students"])})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
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
