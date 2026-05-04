import os
import sqlite3
import json
import base64
import uuid
import hashlib
import datetime
import logging
import threading
import time
from typing import Any, Callable, cast
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import jwt
from argon2 import PasswordHasher

# Basic logging
logging.basicConfig(level=logging.INFO)

# Configuration
hostName = "localhost"
serverPort = 8080
DB_PATH = "jwks_server.db"

# Admin token (simple gate for local testing). Set ADMIN_TOKEN in env for protection.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "devtoken")

# Argon2 parameters (tunable)
ARGON2_TIME = 2
ARGON2_MEMORY_KB = 65536  # 64 MiB in KiB
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

# Derive a 32-byte AES key from environment variable NOT_MY_KEY
env_key = os.environ.get("NOT_MY_KEY", "default_not_my_key")
AES_KEY = hashlib.sha256(env_key.encode("utf-8")).digest()  # 32 bytes

# Initialize Argon2 hasher (argon2-cffi)
ph = PasswordHasher(
    time_cost=ARGON2_TIME,
    memory_cost=ARGON2_MEMORY_KB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=ARGON2_HASH_LEN,
    salt_len=ARGON2_SALT_LEN,
)


# Helper: AES-GCM encrypt/decrypt
def encrypt_bytes(plaintext: bytes) -> str:
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return base64.urlsafe_b64encode(nonce + ct).decode("utf-8")


def decrypt_bytes(b64: str) -> bytes:
    aesgcm = AESGCM(AES_KEY)
    data = base64.urlsafe_b64decode(b64.encode("utf-8"))
    nonce = data[:12]
    ct = data[12:]
    return aesgcm.decrypt(nonce, ct, None)


# DB helpers
def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kid TEXT NOT NULL UNIQUE,
        encrypted_pem TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    cur.close()
    conn.close()


# Create and store RSA keys (encrypted) if not present
def ensure_keys_in_db() -> None:
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id FROM keys WHERE kid = ?", ("goodKID",))
    if cur.fetchone() is None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        enc = encrypt_bytes(pem)
        cur.execute("INSERT INTO keys (kid, encrypted_pem) VALUES (?, ?)", ("goodKID", enc))

    cur.execute("SELECT id FROM keys WHERE kid = ?", ("expiredKID",))
    if cur.fetchone() is None:
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        expired_pem = expired_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        enc2 = encrypt_bytes(expired_pem)
        cur.execute("INSERT INTO keys (kid, encrypted_pem) VALUES (?, ?)", ("expiredKID", enc2))

    conn.commit()
    cur.close()
    conn.close()


# Helper to get public numbers for JWKS from the given kid
def get_public_numbers_from_kid(kid: str = "goodKID"):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT encrypted_pem FROM keys WHERE kid = ?", (kid,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    pem = decrypt_bytes(row["encrypted_pem"])
    private_key = serialization.load_pem_private_key(pem, password=None)
    return private_key.public_key().public_numbers()


# Helper to get decrypted PEM by kid
def get_private_pem_by_kid(kid: str = "goodKID") -> bytes | None:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT encrypted_pem FROM keys WHERE kid = ?", (kid,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    return decrypt_bytes(row["encrypted_pem"])


# Utility: convert int to base64url (no padding)
def int_to_base64(value: int) -> str:
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


# Initialize DB and keys
init_db()
ensure_keys_in_db()


# Simple admin token check (header X-Admin-Token or ?token=)
def _check_admin_token(handler: BaseHTTPRequestHandler) -> bool:
    header_token = handler.headers.get("X-Admin-Token")
    if header_token:
        return header_token == ADMIN_TOKEN
    parsed = urlparse(handler.path)
    qs = parse_qs(parsed.query)
    token_list = qs.get("token", [])
    if token_list:
        return token_list[0] == ADMIN_TOKEN
    return False


# Rate limiter: per-IP token bucket
class TokenBucket:
    def __init__(self, capacity: float, refill_rate_per_sec: float):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate_per_sec)
        self.tokens = float(capacity)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            # refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False


# Global map: ip -> TokenBucket
_rate_buckets: dict[str, TokenBucket] = {}
_rate_lock = threading.Lock()
RATE_CAPACITY = 10.0
RATE_REFILL_PER_SEC = 10.0


def allow_request_for_ip(ip: str) -> bool:
    with _rate_lock:
        bucket = _rate_buckets.get(ip)
        if bucket is None:
            bucket = TokenBucket(RATE_CAPACITY, RATE_REFILL_PER_SEC)
            _rate_buckets[ip] = bucket
    return bucket.consume(1.0)


class MyServer(BaseHTTPRequestHandler):
    def _read_json_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    def _send_json(self, obj, status=200):
        data = json.dumps(obj).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        # Registration endpoint
        if parsed_path.path == "/register":
            body = self._read_json_body()
            username = body.get("username")
            email = body.get("email")
            if not username:
                self._send_json({"error": "username is required"}, status=400)
                return

            # Generate secure password (UUIDv4)
            password = uuid.uuid4().hex
            # Hash with Argon2
            try:
                password_hash = ph.hash(password)
            except Exception:
                logging.exception("Argon2 hashing failed")
                self._send_json({"error": "hashing failed"}, status=500)
                return

            # Store user
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                    (username, password_hash, email)
                )
                conn.commit()
                status_code = 201  # Created
            except sqlite3.IntegrityError:
                conn.close()
                logging.warning("Attempt to register duplicate username or email: %s / %s", username, email)
                self._send_json({"error": "username or email already exists"}, status=409)
                return
            finally:
                try:
                    cur.close()
                    conn.close()
                except Exception:
                    pass

            # Return plaintext password to user (one-time)
            self._send_json({"password": password}, status=status_code)
            return

        # Auth endpoint: generate JWT and log request
        if parsed_path.path == "/auth":
            client_ip = self.client_address[0]
            # Rate limit per IP
            if not allow_request_for_ip(client_ip):
                # Too many requests
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                # Suggest a short retry-after (1 second)
                self.send_header("Retry-After", "1")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "too many requests"}).encode("utf-8"))
                return

            body = self._read_json_body()
            username = body.get("username", "username")

            # Determine which kid to use (query param 'expired' toggles)
            kid = "goodKID"
            exp_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            if 'expired' in params:
                kid = "expiredKID"
                exp_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

            token_payload = {
                "user": username,
                "exp": exp_time
            }

            pem = get_private_pem_by_kid(kid)
            if pem is None:
                self._send_json({"error": "key not found"}, status=500)
                return

            try:
                encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers={"kid": kid})
            except Exception:
                logging.exception("JWT signing failed")
                self._send_json({"error": "jwt signing failed"}, status=500)
                return

            # Log the auth request into auth_logs and update last_login
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            user_id = row["id"] if row else None

            if user_id is not None:
                try:
                    cur.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
                except Exception:
                    logging.exception("Failed to update last_login for user id %s", user_id)

            cur.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (client_ip, user_id))
            conn.commit()
            cur.close()
            conn.close()

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        # Unknown POST
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        # Root page
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h1>JWKS Server</h1><p>Use <a href='/.well-known/jwks.json'>/.well-known/jwks.json</a> or <a href='/register'>/register</a> or <a href='/admin/users?token=devtoken'>/admin/users</a> or <a href='/admin/auth_logs?token=devtoken'>/admin/auth_logs</a></p></body></html>")
            return

        # Favicon
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        # Browser registration page for manual testing
        if self.path == "/register":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Register - JWKS Server</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; }
    label { display:block; margin-top: .5rem; }
    input { width: 300px; padding: .4rem; }
    button { margin-top: .8rem; padding: .5rem 1rem; }
    pre { background:#f6f6f6; padding:1rem; border-radius:4px; }
  </style>
</head>
<body>
  <h1>Register</h1>
  <form id="regForm" onsubmit="return false;">
    <label>Username
      <input id="username" name="username" required />
    </label>
    <label>Email
      <input id="email" name="email" type="email" />
    </label>
    <button id="submitBtn">Register</button>
  </form>

  <h2>Result</h2>
  <div id="result">No request yet.</div>

  <script>
    document.getElementById('submitBtn').addEventListener('click', async function () {
      const username = document.getElementById('username').value.trim();
      const email = document.getElementById('email').value.trim();
      if (!username) {
        alert('username is required');
        return;
      }
      const payload = { username: username, email: email || null };
      const resEl = document.getElementById('result');
      resEl.textContent = 'Sending...';
      try {
        const resp = await fetch('/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const text = await resp.text();
        let parsed;
        try { parsed = JSON.parse(text); } catch (e) { parsed = text; }
        resEl.innerHTML = '<strong>HTTP ' + resp.status + '</strong><pre>' + JSON.stringify(parsed, null, 2) + '</pre>';
      } catch (err) {
        resEl.textContent = 'Request failed: ' + err;
      }
    });
  </script>
</body>
</html>
""")
            return

        # Admin users HTML (protected)
        if self.path.startswith("/admin/users"):
            if not _check_admin_token(self):
                self._send_json({"error": "unauthorized"}, status=401)
                return

            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "SELECT id, username, email, date_registered, last_login, password_hash FROM users ORDER BY id DESC")
            rows = cur.fetchall()
            cur.close()
            conn.close()

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

            self.wfile.write(
                b"<html><body><h1>Users (admin)</h1><p>Protected by token. To use JSON API, call /admin/users.json with token.</p><table border='1' cellpadding='6'><tr><th>id</th><th>username</th><th>email</th><th>date_registered</th><th>last_login</th><th>password_hash</th></tr>")
            for r in rows:
                uid = str(r['id'])
                uname = (r['username'] or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                email = (r['email'] or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                date_reg = str(r['date_registered'] or '')
                last_login = str(r['last_login'] or '')
                phash = (r['password_hash'] or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                row_html = f"<tr><td>{uid}</td><td>{uname}</td><td>{email}</td><td>{date_reg}</td><td>{last_login}</td><td><pre style='margin:0'>{phash}</pre></td></tr>"
                self.wfile.write(row_html.encode('utf-8'))
            self.wfile.write(b"</table></body></html>")
            return

        # Admin users JSON (protected)
        if self.path.startswith("/admin/users.json"):
            if not _check_admin_token(self):
                self._send_json({"error": "unauthorized"}, status=401)
                return

            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "SELECT id, username, email, date_registered, last_login, password_hash FROM users ORDER BY id DESC")
            rows = cur.fetchall()
            cur.close()
            conn.close()

            out = []
            for r in rows:
                out.append({
                    "id": r["id"],
                    "username": r["username"],
                    "email": r["email"],
                    "date_registered": r["date_registered"],
                    "last_login": r["last_login"],
                    "password_hash": r["password_hash"],
                })
            self._send_json({"users": out}, status=200)
            return

        # Admin auth logs HTML (protected)
        if self.path.startswith("/admin/auth_logs"):
            if not _check_admin_token(self):
                self._send_json({"error": "unauthorized"}, status=401)
                return

            try:
                qs = parse_qs(urlparse(self.path).query)
                limit = int(qs.get("limit", ["50"])[0])
            except Exception:
                limit = 50

            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                SELECT a.id, a.request_ip, a.request_timestamp, a.user_id, u.username
                FROM auth_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.id DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            cur.close()
            conn.close()

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()

            self.wfile.write(
                b"<html><body><h1>Auth Logs (admin)</h1><p>Protected by token. To use JSON API, call /admin/auth_logs.json with token.</p>")
            self.wfile.write(b"<p>Recent authentication attempts. Use <code>?limit=100</code> to show more.</p>")
            self.wfile.write(
                b"<table border='1' cellpadding='6'><tr><th>id</th><th>request_ip</th><th>request_timestamp</th><th>user_id</th><th>username</th></tr>")
            for r in rows:
                rid = str(r["id"])
                rip = (r["request_ip"] or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                rts = str(r["request_timestamp"] or "")
                uid = str(r["user_id"] or "")
                uname = (r["username"] or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                row_html = f"<tr><td>{rid}</td><td>{rip}</td><td>{rts}</td><td>{uid}</td><td>{uname}</td></tr>"
                self.wfile.write(row_html.encode("utf-8"))
            self.wfile.write(b"</table></body></html>")
            return

        # Admin auth logs JSON (protected)
        if self.path.startswith("/admin/auth_logs.json"):
            if not _check_admin_token(self):
                self._send_json({"error": "unauthorized"}, status=401)
                return

            try:
                qs = parse_qs(urlparse(self.path).query)
                limit = int(qs.get("limit", ["50"])[0])
            except Exception:
                limit = 50

            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                SELECT a.id, a.request_ip, a.request_timestamp, a.user_id, u.username
                FROM auth_logs a
                LEFT JOIN users u ON a.user_id = u.id
                ORDER BY a.id DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
            cur.close()
            conn.close()

            out = []
            for r in rows:
                out.append({
                    "id": r["id"],
                    "request_ip": r["request_ip"],
                    "request_timestamp": r["request_timestamp"],
                    "user_id": r["user_id"],
                    "username": r["username"],
                })
            self._send_json({"auth_logs": out}, status=200)
            return

        # JWKS endpoint
        if self.path == "/.well-known/jwks.json":
            numbers = get_public_numbers_from_kid("goodKID")
            if numbers is None:
                self._send_json({"error": "jwks not available"}, status=500)
                return
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.n),
                        "e": int_to_base64(numbers.e),
                    }
                ]
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        # Unknown GET
        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    # Cast the handler to the callable signature expected by type checkers
    HandlerType = Callable[[Any, Any, HTTPServer], BaseHTTPRequestHandler]
    handler_callable = cast(HandlerType, MyServer)

    webServer = HTTPServer((hostName, serverPort), handler_callable)
    try:
        print(f"Starting server at http://{hostName}:{serverPort}")
        print("Admin token (set ADMIN_TOKEN env to change):", ADMIN_TOKEN)
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
