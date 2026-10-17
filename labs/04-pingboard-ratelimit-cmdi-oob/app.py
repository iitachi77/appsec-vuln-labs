"""
PingBoard — uptime & webhook monitoring.  Educational exam lab only (⭐⭐⭐⭐⭐).
No credentials are given. Find your way in, then get a shell. Output is NOT returned.
"""
import os
import time
import subprocess
import jwt
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# ✅ SOLVED by Ahmad 2026-10-17 (7.8/10). Flag: FLAG{bl1nd_cmd1_00b_3xf1l_r4t3l1m1t_byp4ss}
JWT_SECRET = os.urandom(32).hex()     # strong, random per boot (not guessable — don't bother)
ADMIN_PIN = "4921"                    # 4-digit support PIN (brute me)

# Naive rate limiter: 5 attempts per client, keyed by X-Forwarded-For (trusted) or remote addr.
attempts = {}

def client_key():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?")

def rate_limited():
    k = client_key()
    attempts[k] = attempts.get(k, 0) + 1
    return attempts[k] > 5


def is_admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    try:
        return jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"]).get("role") == "admin"
    except Exception:
        return False


@app.route("/api/login", methods=["POST"])
def login():
    if rate_limited():
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    d = request.get_json(force=True, silent=True) or {}
    if d.get("username") == "admin" and d.get("pin") == ADMIN_PIN:
        token = jwt.encode({"sub": "admin", "role": "admin"}, JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})
    return jsonify({"error": "Invalid PIN."}), 401


@app.route("/api/monitors", methods=["POST"])
def add_monitor():
    if not is_admin():
        return jsonify({"error": "forbidden: admin only"}), 403
    d = request.get_json(force=True, silent=True) or {}
    host = d.get("host", "")
    # VULNERABLE: host is placed into a shell command. Output is NOT returned (blind).
    try:
        subprocess.run("ping -c 1 -W 1 " + host, shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
        reachable = True
    except Exception:
        reachable = False
    # Only a boolean is returned — never the command output.
    return jsonify({"monitor": "created", "status": "reachable" if reachable else "unreachable"})


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>PingBoard</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>
:root{--bg:#0b1020;--card:#121a2f;--ink:#e6ecfb;--muted:#8b97b5;--line:#243150;--brand:#4c6ef5;--ok:#37b24d;--bad:#f03e3e}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--ink)}
.wrap{max-width:720px;margin:0 auto;padding:40px 18px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:22px;margin-bottom:6px}
.brand .d{width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,#4c6ef5,#74c0fc)}
.sub{color:var(--muted);margin:0 0 24px;font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin:16px 0}
.card h3{margin:0 0 12px;font-size:15px}
label{font-size:12px;color:var(--muted);font-weight:600}
input{width:100%;padding:10px 12px;margin:6px 0 14px;background:#0b1326;border:1px solid var(--line);color:var(--ink);border-radius:8px;font-size:14px;font-family:ui-monospace,monospace}
button{background:var(--brand);color:#fff;border:0;padding:10px 16px;border-radius:8px;font-weight:600;cursor:pointer}
pre{background:#0b1326;border:1px solid var(--line);border-radius:8px;padding:12px;white-space:pre-wrap;word-break:break-all;font-size:13px}
.muted{color:var(--muted);font-size:13px}.ok{color:var(--ok)}.bad{color:var(--bad)}
</style></head><body><div class="wrap">
<div class="brand"><span class="d"></span> PingBoard</div>
<p class="sub">Uptime & webhook monitoring for your infrastructure.</p>

<div class="card"><h3>🔐 Admin sign-in</h3>
<p class="muted">Operators sign in with their 4-digit support PIN.</p>
<label>Username</label><input id="u" value="admin">
<label>Support PIN</label><input id="pin" placeholder="••••">
<button onclick="login()">Sign in</button>
<pre id="lout" style="margin-top:12px">—</pre></div>

<div class="card"><h3>📡 Add monitor</h3>
<p class="muted">Add a host to monitor. We'll ping it and report reachability.</p>
<label>Host / IP</label><input id="host" placeholder="example.com">
<button onclick="addmon()">Create monitor</button>
<pre id="mout" style="margin-top:12px">—</pre></div>
</div>
<script>
let TOKEN="";
const $=s=>document.getElementById(s);
async function login(){
  const r=await fetch("/api/login",{method:"POST",headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$("u").value,pin:$("pin").value})});
  const j=await r.json();$("lout").textContent="["+r.status+"] "+JSON.stringify(j);
  if(j.token){TOKEN=j.token;$("lout").textContent+="\\n[+] signed in.";}
}
async function addmon(){
  const r=await fetch("/api/monitors",{method:"POST",headers:{'Content-Type':'application/json','Authorization':'Bearer '+TOKEN},body:JSON.stringify({host:$("host").value})});
  $("mout").textContent="["+r.status+"] "+JSON.stringify(await r.json());
}
</script></body></html>"""


@app.route("/")
def home():
    return Response(PAGE, mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)
