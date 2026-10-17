"""
VaultAPI (hardened) — a tiny JWT-protected API. Educational lab only.

Fixes applied over the original:
  1. Secret is a long random value loaded from the environment (not hardcoded).
  2. Passwords are stored as salted slow hashes, never plaintext.
  3. Tokens carry iat/exp and expire.
  4. decode() pins the algorithm AND requires the claims we depend on.
  5. Errors are generic to the client; detail is logged server-side.
"""
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt  # PyJWT
from flask import Flask, request, jsonify, render_template_string
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# --- Fix #1: strong secret, loaded from env; never commit this value ----------
# Set it before running, e.g. (PowerShell):
#   $env:JWT_SECRET = python -c "import secrets; print(secrets.token_urlsafe(64))"
# For convenience in a throwaway lab we fall back to a random per-process secret,
# which means tokens stop being valid when the server restarts — that's fine here.
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_urlsafe(64)
ALGO = "HS256"
TOKEN_TTL = timedelta(minutes=15)

# --- Fix #2: store salted password hashes, not plaintext ----------------------
USERS = {
    "alice": {"pw_hash": generate_password_hash("password123"), "role": "user"},
    "bob":   {"pw_hash": generate_password_hash("qwerty2024"),  "role": "user"},
}

FLAG = "FLAG{f0rged_my_w4y_t0_4dm1n_jwt}"

PAGE = """
<!doctype html><html><head><meta charset="utf-8"><title>VaultAPI</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:28px auto;padding:0 16px;background:#0e1116;color:#e8edf3}
h1{margin:0 0 2px}.sub{color:#8b949e;margin:0 0 16px;font-size:14px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:720px){.grid{grid-template-columns:1fr}}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px}
.card h3{margin:0 0 8px;font-size:15px}
input,textarea{width:100%;box-sizing:border-box;padding:8px;margin:4px 0 10px;background:#0d1117;border:1px solid #30363d;color:#e8edf3;border-radius:6px;font-family:ui-monospace,monospace;font-size:12px}
textarea{min-height:60px;resize:vertical}
button{background:#238636;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px}
button.alt{background:#1f6feb}
pre{background:#0b0e13;border:1px solid #222;border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px;max-height:200px}
.lbl{font-size:12px;color:#8b949e}code{background:#0d1117;padding:1px 5px;border-radius:4px}
</style></head><body>
<h1>🔐 VaultAPI</h1>
<p class="sub">Creds: <code>alice : password123</code> &middot; <code>bob : qwerty2024</code> &middot;
Hardened build: the secret is now random &amp; high-entropy, so forging is no longer feasible.</p>
<div class="grid">

  <div class="card"><h3>1 · Login</h3>
    <input id="lu" value="alice"><input id="lp" type="text" value="password123">
    <button onclick="login()">Get token</button>
    <pre id="lout">—</pre>
  </div>

  <div class="card"><h3>2 · Inspect / Decode a JWT</h3>
    <span class="lbl">Paste a token to see its header &amp; payload (no secret needed).</span>
    <textarea id="din" placeholder="paste JWT"></textarea>
    <button class="alt" onclick="decode()">Decode</button>
    <pre id="dout">—</pre>
  </div>

  <div class="card"><h3>3 · Test /me and /admin</h3>
    <span class="lbl">Paste a token and hit the protected endpoints.</span>
    <textarea id="tin" placeholder="paste JWT"></textarea>
    <button onclick="hit('/me')">GET /me</button>
    <button class="alt" onclick="hit('/admin')">GET /admin</button>
    <pre id="tout">—</pre>
  </div>

</div>
<script>
const g=id=>document.getElementById(id);
function b64urlDecode(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return atob(s);}
async function login(){
  const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:g('lu').value,password:g('lp').value})});
  const t=await r.text();g('lout').textContent="["+r.status+"]\\n"+t;
}
function decode(){
  try{const [h,p]=g('din').value.trim().split('.');
    g('dout').textContent="HEADER:\\n"+b64urlDecode(h)+"\\n\\nPAYLOAD:\\n"+b64urlDecode(p);
  }catch(e){g('dout').textContent="bad token: "+e;}
}
async function hit(path){
  try{const r=await fetch(path,{headers:{'Authorization':'Bearer '+g('tin').value.trim()}});
    const t=await r.text();g('tout').textContent="["+r.status+"]\\n"+t;
  }catch(e){g('tout').textContent="ERR "+e;}
}
</script>
</body></html>
"""


@app.route("/")
def home():
    return render_template_string(PAGE)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    u = data.get("username", "")
    p = data.get("password", "")
    rec = USERS.get(u)
    # Fix #2: constant-time hash comparison; same generic error either way.
    if not rec or not check_password_hash(rec["pw_hash"], p):
        return jsonify({"error": "invalid credentials"}), 401
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": u,
            "role": rec["role"],
            "iat": now,                 # Fix #3: issued-at
            "exp": now + TOKEN_TTL,     # Fix #3: expiry
        },
        JWT_SECRET,
        algorithm=ALGO,
    )
    return jsonify({"token": token})


def read_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, "missing bearer token"
    token = auth[7:]
    try:
        # Fix #4: pin the algorithm (blocks alg:none and HS/RS confusion) and
        # require the claims we rely on, so a token missing exp/role is rejected.
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "sub", "role"]},
        )
        return claims, None
    except Exception:
        # Fix #5: log detail server-side, return something generic to the client.
        app.logger.warning("token rejected", exc_info=True)
        return None, "invalid or expired token"


@app.route("/me")
def me():
    claims, err = read_token()
    if err:
        return jsonify({"error": err}), 401
    return jsonify({"claims": claims})


@app.route("/admin")
def admin():
    claims, err = read_token()
    if err:
        return jsonify({"error": err}), 401
    if claims.get("role") != "admin":
        # Fix #5: don't echo the caller's role back.
        return jsonify({"error": "forbidden: admin role required"}), 403
    return jsonify({"message": "Welcome, admin.", "flag": FLAG})


if __name__ == "__main__":
    # Lab server. In production, run behind a real WSGI server over HTTPS,
    # and never bind port 80 as root just for an app like this.
    app.run(host="127.0.0.1", port=80)
