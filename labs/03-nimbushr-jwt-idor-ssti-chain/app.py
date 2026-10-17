"""
NimbusHR — internal employee portal.  Educational exam lab only.
A realistic HR SaaS front-end over an API with a chain of real-world flaws.
"""
import jwt  # PyJWT
from flask import Flask, request, jsonify, render_template_string, Response

app = Flask(__name__)

JWT_SECRET = "chocolate"   # weak HMAC secret

USERS = {
    "alice": {"password": "Password123", "role": "employee"},
    "bob":   {"password": "Summer2024!", "role": "employee"},
}

# Employee records (served by /api/users/<id>).
RECORDS = {
    1: {"id": 1, "username": "admin", "name": "Selin Arslan", "role": "hr_admin",
        "title": "Head of HR", "department": "Human Resources", "email": "selin.arslan@nimbushr.io",
        "location": "Istanbul HQ", "manager": "—", "started": "2019-03-04",
        "note": "HR administrator — full access"},
    5: {"id": 5, "username": "alice", "name": "Alice Moreau", "role": "employee",
        "title": "Marketing Specialist", "department": "Marketing", "email": "alice.moreau@nimbushr.io",
        "location": "Remote (FR)", "manager": "Selin Arslan", "started": "2023-09-11"},
    6: {"id": 6, "username": "bob", "name": "Bob Chen", "role": "employee",
        "title": "Backend Engineer", "department": "Engineering", "email": "bob.chen@nimbushr.io",
        "location": "Istanbul HQ", "manager": "Selin Arslan", "started": "2022-01-17"},
}

DIRECTORY = [
    {"id": 5, "name": "Alice Moreau", "title": "Marketing Specialist", "department": "Marketing"},
    {"id": 6, "name": "Bob Chen", "title": "Backend Engineer", "department": "Engineering"},
]

TIMEOFF = [
    {"type": "Annual Leave", "from": "2026-10-20", "to": "2026-10-24", "status": "Approved"},
    {"type": "Sick Leave", "from": "2026-09-30", "to": "2026-09-30", "status": "Approved"},
    {"type": "Annual Leave", "from": "2026-12-22", "to": "2026-12-31", "status": "Pending"},
]

BLOCK = ["os", "popen", "system", "subprocess", "import", "eval", "exec",
         "config", "mro", "subclasses", "builtin", "open", "globals_"]


def read_jwt():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


# ───────────────────────── API ─────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json(force=True, silent=True) or {}
    u = USERS.get(d.get("username", ""))
    if not u or u["password"] != d.get("password", ""):
        return jsonify({"error": "Invalid username or password."}), 401
    token = jwt.encode({"sub": d["username"], "role": u["role"]}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.route("/api/me")
def me():
    c = read_jwt()
    if not c:
        return jsonify({"error": "unauthorized"}), 401
    uid = {"alice": 5, "bob": 6, "admin": 1}.get(c.get("sub"), 5)
    return jsonify({"claims": c, "record": RECORDS.get(uid, {})})


@app.route("/api/dashboard")
def dashboard():
    c = read_jwt()
    if not c:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({
        "headcount": 128, "open_roles": 6, "pending_timeoff": 3, "announcements": 2,
        "activity": [
            "Selin Arslan approved your Annual Leave (Oct 20–24).",
            "New company handbook v3 published.",
            "Q4 performance review cycle opens Nov 1.",
        ],
    })


@app.route("/api/directory")
def directory():
    c = read_jwt()
    if not c:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"employees": DIRECTORY})


@app.route("/api/users/<int:uid>")
def get_user(uid):
    c = read_jwt()
    if not c:
        return jsonify({"error": "unauthorized"}), 401
    r = RECORDS.get(uid)                       # IDOR / BOLA: no ownership check
    if not r:
        return jsonify({"error": "not found"}), 404
    return jsonify(r)


@app.route("/api/timeoff")
def timeoff():
    c = read_jwt()
    if not c:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"requests": TIMEOFF})


@app.route("/admin/reports")
def reports():
    c = read_jwt()
    if not c or c.get("role") != "hr_admin":
        return jsonify({"error": "forbidden: hr_admin role required"}), 403
    return jsonify({"templates": ["Headcount Summary", "Time-off Ledger", "New-Hire Onboarding"]})


@app.route("/admin/reports/render")
def render_report():
    c = read_jwt()
    if not c or c.get("role") != "hr_admin":
        return jsonify({"error": "forbidden: hr_admin role required"}), 403
    t = request.args.get("template", "")
    low = t.lower()
    for b in BLOCK:
        if b in low:
            return jsonify({"error": f"Template validation failed: disallowed token '{b}'."}), 400
    try:
        out = render_template_string("Report output: " + t)   # SSTI
    except Exception as e:
        return jsonify({"error": f"render error: {e}"}), 500
    return jsonify({"rendered": out})


# ───────────────────────── Front-end (SPA) ─────────────────────────

@app.route("/")
def home():
    return Response(FRONTEND, mimetype="text/html")


FRONTEND = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NimbusHR — People Platform</title>
<style>
:root{--bg:#f4f6fb;--card:#fff;--ink:#1f2733;--muted:#6b7686;--line:#e6eaf1;--brand:#3b5bdb;--brand2:#5c7cfa;--ok:#2b8a3e;--warn:#e67700}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--ink)}
a{color:var(--brand);text-decoration:none}
/* login */
#login{min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#eef2ff,#f8fafc)}
.lbox{background:#fff;border:1px solid var(--line);border-radius:16px;padding:34px;width:360px;box-shadow:0 10px 40px rgba(31,39,51,.08)}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:20px;margin-bottom:4px}
.logo .dot{width:26px;height:26px;border-radius:8px;background:linear-gradient(135deg,var(--brand),var(--brand2))}
.sub{color:var(--muted);font-size:13px;margin:0 0 18px}
label{font-size:12px;color:var(--muted);font-weight:600}
input,textarea{width:100%;padding:10px 12px;margin:6px 0 14px;border:1px solid var(--line);border-radius:9px;font-size:14px;font-family:inherit;background:#fff;color:var(--ink)}
textarea{min-height:90px;resize:vertical;font-family:ui-monospace,monospace;font-size:13px}
.btn{background:var(--brand);color:#fff;border:0;padding:11px 16px;border-radius:9px;font-weight:600;cursor:pointer;font-size:14px}
.btn:hover{background:#2f4bc4}.btn.ghost{background:#eef2ff;color:var(--brand)}
.err{color:#c92a2a;font-size:13px;min-height:18px}
.hint{color:var(--muted);font-size:12px;margin-top:10px;border-top:1px dashed var(--line);padding-top:10px}
/* app shell */
#app{display:none;grid-template-columns:230px 1fr;min-height:100vh}
.side{background:#141b2d;color:#c7d0e0;padding:18px 14px;display:flex;flex-direction:column;gap:4px}
.side .logo{color:#fff;margin-bottom:18px;font-size:18px}
.nav{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:9px;color:#aeb8cc;cursor:pointer;font-size:14px;font-weight:500}
.nav:hover{background:#1e2740;color:#fff}.nav.active{background:var(--brand);color:#fff}
.nav .ic{width:18px;text-align:center}
.side .spacer{flex:1}
.main{padding:0}
.topbar{height:60px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 24px}
.topbar .search{flex:1;max-width:420px}.topbar input{margin:0}
.who{display:flex;align-items:center;gap:10px;font-size:14px}
.av{width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;display:grid;place-items:center;font-weight:700}
.content{padding:24px;max-width:1000px}
h1{font-size:22px;margin:0 0 4px}.pg-sub{color:var(--muted);margin:0 0 20px;font-size:14px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
@media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}#app{grid-template-columns:1fr}.side{display:none}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.card .k{color:var(--muted);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.card .v{font-size:26px;font-weight:800;margin-top:6px}
.panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:18px}
.panel h3{margin:0 0 12px;font-size:15px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:11px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr.clk{cursor:pointer}tr.clk:hover{background:#f7f9fe}
.pill{font-size:12px;padding:3px 9px;border-radius:999px;font-weight:600}
.pill.g{background:#e6fcf5;color:#0ca678}.pill.y{background:#fff4e6;color:#e8590c}.pill.b{background:#edf2ff;color:#3b5bdb}
.kv{display:grid;grid-template-columns:150px 1fr;gap:8px 16px;font-size:14px}.kv .lbl{color:var(--muted)}
.list{list-style:none;padding:0;margin:0}.list li{padding:10px 0;border-bottom:1px solid var(--line);font-size:14px;color:#3a4453}
pre.out{background:#0f1626;color:#d7e2f5;border-radius:10px;padding:14px;white-space:pre-wrap;word-break:break-all;font-size:13px;margin-top:12px}
.muted{color:var(--muted);font-size:13px}
.hidden{display:none}
</style></head><body>

<!-- LOGIN -->
<div id="login">
  <div class="lbox">
    <div class="logo"><span class="dot"></span> NimbusHR</div>
    <p class="sub">Sign in to the People Platform</p>
    <label>Username</label><input id="u" value="alice" autofocus>
    <label>Password</label><input id="p" type="password" value="">
    <button class="btn" style="width:100%" onclick="doLogin()">Sign in</button>
    <div class="err" id="lerr"></div>
    <div class="hint">Demo employee account: <b>alice / Password123</b></div>
  </div>
</div>

<!-- APP -->
<div id="app">
  <aside class="side">
    <div class="logo"><span class="dot" style="display:inline-block;width:22px;height:22px;border-radius:7px;background:linear-gradient(135deg,#5c7cfa,#748ffc);vertical-align:middle"></span> NimbusHR</div>
    <div class="nav active" data-v="dashboard"><span class="ic">▣</span> Dashboard</div>
    <div class="nav" data-v="directory"><span class="ic">👥</span> Directory</div>
    <div class="nav" data-v="profile"><span class="ic">🪪</span> My Profile</div>
    <div class="nav" data-v="timeoff"><span class="ic">🌴</span> Time Off</div>
    <div class="nav hidden" id="navReports" data-v="reports"><span class="ic">📊</span> Reports</div>
    <div class="spacer"></div>
    <div class="nav" onclick="logout()"><span class="ic">⎋</span> Sign out</div>
  </aside>
  <div class="main">
    <div class="topbar">
      <div class="search"><input id="globalsearch" placeholder="Search people, documents…"></div>
      <div class="who"><span id="whoName" class="muted"></span><div class="av" id="whoAv">?</div></div>
    </div>
    <div class="content" id="view"></div>
  </div>
</div>

<script>
const API="";
let TOKEN=localStorage.getItem("nimbus_token")||"";
const $=s=>document.querySelector(s);
function jwtRole(t){try{return JSON.parse(atob(t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).role}catch(e){return null}}
function jwtSub(t){try{return JSON.parse(atob(t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).sub}catch(e){return null}}
async function api(path,opts={}){opts.headers=Object.assign({'Authorization':'Bearer '+TOKEN},opts.headers||{});const r=await fetch(API+path,opts);let j;try{j=await r.json()}catch(e){j={}}return{status:r.status,body:j}}

async function doLogin(){
  $("#lerr").textContent="";
  const r=await fetch("/api/login",{method:"POST",headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$("#u").value,password:$("#p").value})});
  const j=await r.json();
  if(j.token){TOKEN=j.token;localStorage.setItem("nimbus_token",TOKEN);enterApp()}
  else $("#lerr").textContent=j.error||"Login failed";
}
function logout(){localStorage.removeItem("nimbus_token");TOKEN="";location.reload()}

function enterApp(){
  $("#login").style.display="none";$("#app").style.display="grid";
  const sub=jwtSub(TOKEN)||"user",role=jwtRole(TOKEN);
  $("#whoName").textContent=sub+(role?(" · "+role):"");
  $("#whoAv").textContent=(sub[0]||"?").toUpperCase();
  $("#navReports").classList.toggle("hidden", role!=="hr_admin");
  document.querySelectorAll(".nav[data-v]").forEach(n=>n.onclick=()=>go(n.dataset.v));
  go("dashboard");
}
function setActive(v){document.querySelectorAll(".nav").forEach(n=>n.classList.toggle("active",n.dataset.v===v))}

async function go(v){
  setActive(v);
  if(v==="dashboard")return viewDashboard();
  if(v==="directory")return viewDirectory();
  if(v==="profile")return viewProfile(null);
  if(v==="timeoff")return viewTimeoff();
  if(v==="reports")return viewReports();
}

async function viewDashboard(){
  const {body}=await api("/api/dashboard");
  $("#view").innerHTML=`<h1>Dashboard</h1><p class="pg-sub">Welcome back, ${jwtSub(TOKEN)}.</p>
  <div class="cards">
    <div class="card"><div class="k">Headcount</div><div class="v">${body.headcount??'—'}</div></div>
    <div class="card"><div class="k">Open Roles</div><div class="v">${body.open_roles??'—'}</div></div>
    <div class="card"><div class="k">Pending Time-off</div><div class="v">${body.pending_timeoff??'—'}</div></div>
    <div class="card"><div class="k">Announcements</div><div class="v">${body.announcements??'—'}</div></div>
  </div>
  <div class="panel"><h3>Recent activity</h3><ul class="list">${(body.activity||[]).map(a=>`<li>${a}</li>`).join('')}</ul></div>`;
}

async function viewDirectory(){
  const {body}=await api("/api/directory");
  const rows=(body.employees||[]).map(e=>`<tr class="clk" onclick="viewProfile(${e.id})"><td>${e.name}</td><td>${e.title}</td><td>${e.department}</td><td>#${e.id}</td></tr>`).join('');
  $("#view").innerHTML=`<h1>Employee Directory</h1><p class="pg-sub">Browse the team. Click anyone to open their profile.</p>
  <div class="panel"><table><thead><tr><th>Name</th><th>Title</th><th>Department</th><th>ID</th></tr></thead><tbody>${rows}</tbody></table></div>
  <p class="muted">Tip: profiles load from <code>/api/users/&lt;id&gt;</code>.</p>`;
}

async function viewProfile(id){
  if(id===null){const sub=jwtSub(TOKEN);id={alice:5,bob:6,admin:1}[sub]||5}
  const {status,body}=await api("/api/users/"+id);
  if(status!==200){$("#view").innerHTML=`<h1>Profile</h1><div class="panel">Could not load user #${id}: ${body.error||status}</div>`;return}
  $("#view").innerHTML=`<h1>${body.name||body.username}</h1><p class="pg-sub">${body.title||''} ${body.department?('· '+body.department):''}</p>
  <div class="panel"><div class="kv">
    <div class="lbl">User ID</div><div>#${body.id}</div>
    <div class="lbl">Username</div><div>${body.username||'—'}</div>
    <div class="lbl">Role</div><div><span class="pill ${body.role==='hr_admin'?'b':'g'}">${body.role||'—'}</span></div>
    <div class="lbl">Email</div><div>${body.email||'—'}</div>
    <div class="lbl">Location</div><div>${body.location||'—'}</div>
    <div class="lbl">Manager</div><div>${body.manager||'—'}</div>
    <div class="lbl">Started</div><div>${body.started||'—'}</div>
    ${body.note?`<div class="lbl">Note</div><div>${body.note}</div>`:''}
  </div></div>
  <p class="muted">Viewing user #${body.id}. Change the ID in the request to view another record.</p>`;
}

async function viewTimeoff(){
  const {body}=await api("/api/timeoff");
  const rows=(body.requests||[]).map(r=>`<tr><td>${r.type}</td><td>${r.from}</td><td>${r.to}</td><td><span class="pill ${r.status==='Approved'?'g':'y'}">${r.status}</span></td></tr>`).join('');
  $("#view").innerHTML=`<h1>Time Off</h1><p class="pg-sub">Your leave requests and balances.</p>
  <div class="cards"><div class="card"><div class="k">Annual balance</div><div class="v">14 <span style="font-size:14px;color:var(--muted)">days</span></div></div>
  <div class="card"><div class="k">Sick balance</div><div class="v">8 <span style="font-size:14px;color:var(--muted)">days</span></div></div></div>
  <div class="panel"><h3>Requests</h3><table><thead><tr><th>Type</th><th>From</th><th>To</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

async function viewReports(){
  $("#view").innerHTML=`<h1>Report Builder</h1><p class="pg-sub">Generate HR reports from a template. Use template variables, e.g. <code>{{ 2026 - 2019 }}</code> years of service.</p>
  <div class="panel"><h3>Custom report template</h3>
    <textarea id="tpl">Headcount report generated for FY{{ 2020 + 6 }}.</textarea>
    <button class="btn" onclick="genReport()">Generate report</button>
    <span class="muted" style="margin-left:10px">Templates are validated before rendering.</span>
    <pre class="out hidden" id="rout"></pre>
  </div>`;
}
async function genReport(){
  const tpl=$("#tpl").value;
  const {status,body}=await api("/admin/reports/render?template="+encodeURIComponent(tpl));
  const o=$("#rout");o.classList.remove("hidden");
  o.textContent=(status===200)?(body.rendered||JSON.stringify(body)):("⚠ "+(body.error||status));
}

// boot
if(TOKEN){enterApp()}
</script>
</body></html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
