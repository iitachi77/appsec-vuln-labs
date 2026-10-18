"""
MERIDIAN — B2B Invoicing & Analytics SaaS.  Educational exam lab only (5 stars).
Realistic storefront-grade GUI; underneath, a 4-stage chain built ENTIRELY from
classic, well-known web vulns (no exotic tricks):

   1) Blind boolean SQL injection (UNION blocked by a WAF) on a public invoice lookup
        -> leak the JWT signing secret from the `config` table
   2) JWT forge (HS256 with the leaked secret)
        -> authenticate as a real user without their password
   3) IDOR / BOLA on workspace settings (no ownership check)
        -> leak the internal "Ops" workspace render token
   4) Filtered server-side template injection (Jinja2) on the report renderer
        -> RCE -> read /flag.txt

Target: http://localhost:9005
"""
import os
import re
import sqlite3
import jwt
from flask import Flask, request, jsonify, render_template_string, g

app = Flask(__name__)

JWT_SECRET = "m3r1d14n_" + os.urandom(8).hex()   # random per boot; must be LEAKED via SQLi
DB = ":memory:"
_conn = None


def db():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        seed(_conn)
    return _conn


def seed(c):
    c.executescript("""
    CREATE TABLE config    (key TEXT, value TEXT);
    CREATE TABLE users     (id INTEGER PRIMARY KEY, email TEXT, password TEXT, role TEXT, wid INTEGER);
    CREATE TABLE workspaces(id INTEGER PRIMARY KEY, name TEXT, plan TEXT);
    CREATE TABLE settings  (wid INTEGER, render_enabled INTEGER, render_token TEXT, note TEXT);
    CREATE TABLE invoices  (id INTEGER PRIMARY KEY, ref TEXT, wid INTEGER, amount REAL, status TEXT);
    """)
    c.execute("INSERT INTO config VALUES ('jwt_secret', ?)", (JWT_SECRET,))
    c.execute("INSERT INTO config VALUES ('app_version', '3.4.1')")
    users = [
        (1, "ops@meridian.io",   "x", "admin",   1),
        (7, "alice@contoso.com", "x", "user",    7),
        (8, "bob@contoso.com",   "x", "user",    7),
        (9, "dana@globex.com",   "x", "manager", 9),
    ]
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?)", users)
    c.executemany("INSERT INTO workspaces VALUES (?,?,?)", [
        (1, "Meridian Ops (internal)", "internal"),
        (7, "Contoso Ltd", "pro"),
        (9, "Globex Inc", "pro"),
    ])
    RENDER_TOKEN = "rtok_" + os.urandom(6).hex()
    c.executemany("INSERT INTO settings VALUES (?,?,?,?)", [
        (1, 1, RENDER_TOKEN, "internal report renderer — Jinja templates"),
        (7, 0, "rtok_disabled_7", "upgrade to internal plan to enable rendering"),
        (9, 0, "rtok_disabled_9", "rendering disabled"),
    ])
    c.executemany("INSERT INTO invoices VALUES (?,?,?,?,?)", [
        (1001, "INV-1001", 7, 4200.00, "PAID"),
        (1002, "INV-1002", 7,  980.50, "OPEN"),
        (1003, "INV-1003", 9, 15300.0, "PAID"),
    ])
    c.commit()


# ---------------- WAF (stage-1 difficulty, not a wall) ----------------
WAF_BLOCK = re.compile(r"(?i)\b(union|information_schema|load_file|into\s+outfile)\b")

def waf(s):
    return bool(WAF_BLOCK.search(s or ""))


# ---------------- JWT helper ----------------
def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


# ================= STAGE 1: Blind boolean SQLi =================
@app.route("/api/invoice/lookup")
def invoice_lookup():
    ref = request.args.get("ref", "")
    if waf(ref):
        return jsonify({"ok": False, "error": "Request blocked by WAF."}), 403
    # VULNERABLE: raw string concatenation. UNION is WAF-blocked -> boolean-blind only.
    q = "SELECT id, ref, status FROM invoices WHERE ref = '" + ref + "'"
    try:
        row = db().execute(q).fetchone()
    except Exception:
        # Errors are swallowed -> no error-based oracle, forcing BOOLEAN blind.
        return jsonify({"ok": True, "found": False})
    if row:
        return jsonify({"ok": True, "found": True, "status": row["status"]})
    return jsonify({"ok": True, "found": False})


# ================= STAGE 2 target: login (issues HS256 JWT) =================
@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json(force=True, silent=True) or {}
    row = db().execute("SELECT * FROM users WHERE email=? AND password=?",
                       (d.get("email"), d.get("password"))).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "Invalid credentials."}), 401
    token = jwt.encode({"sub": row["email"], "role": row["role"], "wid": row["wid"]},
                       JWT_SECRET, algorithm="HS256")
    return jsonify({"ok": True, "token": token})


@app.route("/api/me")
def me():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "unauthenticated"}), 401
    return jsonify({"ok": True, "user": u})


# ================= STAGE 3: IDOR / BOLA on workspace settings =================
@app.route("/api/workspaces/<int:wid>/settings")
def ws_settings(wid):
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "unauthenticated"}), 401
    # VULNERABLE: authenticated, but NO check that wid == u['wid']. Any user reads any workspace.
    row = db().execute("SELECT * FROM settings WHERE wid=?", (wid,)).fetchone()
    ws = db().execute("SELECT * FROM workspaces WHERE id=?", (wid,)).fetchone()
    if not row or not ws:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "workspace": ws["name"], "plan": ws["plan"],
                    "render_enabled": bool(row["render_enabled"]),
                    "render_token": row["render_token"], "note": row["note"]})


# ================= STAGE 4: Filtered SSTI on report renderer =================
# Block obvious RCE keywords as contiguous substrings -> forces `~` string-concat gadget.
SSTI_BLOCK = ["globals", "os", "popen", "system", "subprocess", "import",
              "eval", "exec", "builtins", "mro", "subclasses", "getattr", "flag"]

@app.route("/api/reports/render", methods=["POST"])
def render_report():
    token = request.headers.get("X-Render-Token", "")
    d = request.get_json(force=True, silent=True) or {}
    wid = d.get("wid")
    tmpl = d.get("template", "")
    row = db().execute("SELECT * FROM settings WHERE wid=? AND render_enabled=1", (wid,)).fetchone()
    if not row or token != row["render_token"]:
        return jsonify({"ok": False, "error": "invalid or disabled render token"}), 403
    low = tmpl.lower()
    for bad in SSTI_BLOCK:
        if bad in low:
            return jsonify({"ok": False, "error": f"template keyword '{bad}' is not allowed"}), 400
    # VULNERABLE: user-controlled template rendered server-side (Jinja2) -> SSTI -> RCE.
    try:
        out = render_template_string("REPORT> " + tmpl)
    except Exception as e:
        return jsonify({"ok": False, "error": f"render error: {e}"}), 500
    return jsonify({"ok": True, "rendered": out})


# ---------------- Realistic GUI ----------------
@app.route("/")
def home():
    return render_template_string(PAGE)


PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Meridian — Invoicing &amp; Analytics</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0f1420;--panel:#161d2b;--panel2:#1d2636;--ink:#e7ecf3;--mut:#8a97a8;--line:#28313f;
      --acc:#4f8cff;--acc2:#36d399;--amb:#f4bf50}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--ink)}
a{color:inherit;text-decoration:none}
.top{display:flex;align-items:center;justify-content:space-between;padding:14px 26px;border-bottom:1px solid var(--line);background:#121826;position:sticky;top:0;z-index:5}
.brand{display:flex;align-items:center;gap:11px;font-weight:700;font-size:18px;letter-spacing:-.2px}
.brand svg{display:block}
.nav{display:flex;gap:22px;color:var(--mut);font-size:14px;font-weight:500}
.nav a:hover{color:var(--ink)}
.cta{background:var(--acc);color:#fff;padding:8px 16px;border-radius:8px;font-weight:600;font-size:13.5px}
.hero{padding:64px 26px;max-width:1080px;margin:0 auto;display:grid;grid-template-columns:1.1fr .9fr;gap:40px;align-items:center}
@media(max-width:860px){.hero{grid-template-columns:1fr;padding:38px 20px}}
.hero h1{font-size:40px;line-height:1.08;margin:0 0 14px;letter-spacing:-1px}
.hero h1 span{color:var(--acc)}
.hero p{color:var(--mut);font-size:16px;max-width:460px;margin:0 0 22px}
.pill{display:inline-flex;gap:8px;align-items:center;background:var(--panel2);border:1px solid var(--line);color:var(--mut);padding:6px 13px;border-radius:999px;font-size:12.5px;margin-bottom:18px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--acc2)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 20px 50px rgba(0,0,0,.35)}
.card h3{margin:0 0 4px;font-size:15px}.card .sub{color:var(--mut);font-size:12.5px;margin:0 0 16px}
label{display:block;font-size:12px;color:var(--mut);margin:12px 0 5px;font-weight:500}
input,textarea{width:100%;background:var(--panel2);border:1px solid var(--line);border-radius:9px;color:var(--ink);padding:11px 12px;font-size:13.5px;font-family:inherit}
textarea{min-height:70px;font-family:ui-monospace,monospace;font-size:12.5px}
button{margin-top:16px;width:100%;background:var(--acc);color:#fff;border:0;border-radius:9px;padding:12px;font-weight:600;font-size:14px;cursor:pointer}
button:hover{filter:brightness(1.08)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;max-width:1080px;margin:10px auto 50px;padding:0 26px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}
.stat b{font-size:26px;display:block;letter-spacing:-.5px}.stat span{color:var(--mut);font-size:12.5px}
.sec{max-width:1080px;margin:0 auto 60px;padding:0 26px}
.sec h2{font-size:22px;letter-spacing:-.4px}.sec .lead{color:var(--mut);margin:2px 0 20px}
.tools{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:860px){.tools{grid-template-columns:1fr}}
.out{margin-top:12px;background:#0b0f18;border:1px solid var(--line);border-radius:9px;padding:11px;font-family:ui-monospace,monospace;font-size:12px;color:var(--acc2);white-space:pre-wrap;word-break:break-all;min-height:20px}
footer{border-top:1px solid var(--line);padding:30px 26px;color:var(--mut);font-size:12.5px;text-align:center}
.grid-bg{background:radial-gradient(1200px 400px at 70% -10%,rgba(79,140,255,.14),transparent)}
</style></head>
<body class="grid-bg">

<div class="top">
  <div class="brand">
    <svg width="26" height="26" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#4f8cff"/>
      <path d="M8 22V10l8 7 8-7v12" fill="none" stroke="#fff" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/></svg>
    Meridian
  </div>
  <div class="nav">
    <a href="#product">Product</a><a href="#tools">Dashboard</a><a href="#pricing">Pricing</a><a href="#docs">Docs</a>
  </div>
  <a class="cta" href="#tools">Open dashboard</a>
</div>

<div class="hero">
  <div>
    <div class="pill"><span class="dot"></span> Trusted by 2,400+ finance teams</div>
    <h1>Invoicing &amp; analytics,<br><span>in one clean workspace.</span></h1>
    <p>Meridian unifies billing, reporting and reconciliation so your finance team ships
       month-end in hours, not weeks. Real-time dashboards, branded invoices, audit-ready exports.</p>
    <a class="cta" href="#tools" style="display:inline-block">Get started free</a>
  </div>
  <div class="card">
    <h3>Sign in to your workspace</h3>
    <p class="sub">Welcome back. Enter your Meridian credentials.</p>
    <label>Work email</label>
    <input id="email" placeholder="you@company.com" value="alice@contoso.com">
    <label>Password</label>
    <input id="pw" type="password" placeholder="••••••••">
    <button onclick="login()">Sign in</button>
    <div class="out" id="loginout"></div>
  </div>
</div>

<div class="stats">
  <div class="stat"><b>$48.2M</b><span>Invoiced this quarter</span></div>
  <div class="stat"><b>99.98%</b><span>Platform uptime</span></div>
  <div class="stat"><b>12,900</b><span>Active workspaces</span></div>
</div>

<div class="sec" id="tools">
  <h2>Workspace tools</h2>
  <p class="lead">Public invoice status · workspace settings · report renderer.</p>
  <div class="tools">
    <div class="card">
      <h3>Invoice status lookup</h3>
      <p class="sub">Check any invoice by its public reference (no login needed).</p>
      <label>Invoice reference</label>
      <input id="ref" value="INV-1001">
      <button onclick="lookup()">Check status</button>
      <div class="out" id="lkout"></div>
    </div>
    <div class="card">
      <h3>Report renderer <span style="color:var(--amb);font-size:11px">· internal</span></h3>
      <p class="sub">Render a branded report template for your workspace.</p>
      <label>Workspace ID</label><input id="rwid" value="7">
      <label>Template</label><textarea id="rtmpl">Hello {{ 7*7 }} — monthly summary</textarea>
      <button onclick="render()">Render report</button>
      <div class="out" id="rout"></div>
    </div>
  </div>
</div>

<footer>© 2026 Meridian Financial Technologies (fictional). All rights reserved. · Status · Security · API Docs</footer>

<script>
const $=id=>document.getElementById(id);
let TOKEN=localStorage.getItem("mtok")||"";
async function login(){
  const r=await fetch("/api/login",{method:"POST",headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:$("email").value,password:$("pw").value})});
  const j=await r.json();
  if(j.ok){TOKEN=j.token;localStorage.setItem("mtok",TOKEN);$("loginout").textContent="Signed in. Session token stored.";}
  else $("loginout").textContent="⚠ "+j.error;
}
async function lookup(){
  const r=await fetch("/api/invoice/lookup?ref="+encodeURIComponent($("ref").value));
  $("lkout").textContent=JSON.stringify(await r.json());
}
async function render(){
  const r=await fetch("/api/reports/render",{method:"POST",
    headers:{'Content-Type':'application/json','X-Render-Token':localStorage.getItem("rtok")||'',
             'Authorization':'Bearer '+TOKEN},
    body:JSON.stringify({wid:parseInt($("rwid").value),template:$("rtmpl").value})});
  $("rout").textContent=JSON.stringify(await r.json());
}
</script>
</body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)
