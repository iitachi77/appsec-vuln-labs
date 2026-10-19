// Taskly — a small team task board.  Educational lab only.
// Looks like a normal product; underneath is a PROTOTYPE POLLUTION flaw in the
// "update preferences" feature (a vulnerable recursive merge), which escalates a
// normal user to admin and unlocks the admin panel.
const express = require("express");
const app = express();
app.use(express.json());

const FLAG = process.env.FLAG || "FLAG{placeholder}";

// ---- in-memory state ----
const user = { name: "alice", role: "user", prefs: { theme: "light", density: "cozy" } };
const board = {
  todo:  [{ t: "Draft Q4 report", by: "alice" }, { t: "Review PR #214", by: "bob" }],
  doing: [{ t: "Invoice export", by: "alice" }],
  done:  [{ t: "Fix login bug", by: "carol" }],
};

// VULNERABLE: recursive merge that walks attacker-controlled keys, including __proto__.
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (typeof target[key] !== "object" || target[key] === null) target[key] = {};
      merge(target[key], source[key]);          // recurses into __proto__ -> pollutes Object.prototype
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ---- API ----
app.get("/api/me", (req, res) => res.json({ name: user.name, role: user.role, prefs: user.prefs }));

// update your preferences (the sink)
app.post("/api/preferences", (req, res) => {
  merge(user.prefs, req.body || {});
  res.json({ ok: true, prefs: user.prefs });
});

// admin-only: builds a fresh permissions object per request and checks it.
// If Object.prototype was polluted with isAdmin=true, this empty object inherits it.
app.get("/api/admin/flag", (req, res) => {
  const perms = {};                              // no own "isAdmin" property
  if (perms.isAdmin === true) {
    return res.json({ ok: true, flag: FLAG });
  }
  return res.status(403).json({ ok: false, error: "Admins only." });
});

app.post("/api/reset", (req, res) => {
  // clean the prototype between attempts (lab convenience)
  delete Object.prototype.isAdmin;
  user.prefs = { theme: "light", density: "cozy" };
  res.json({ ok: true });
});

app.get("/", (req, res) => res.type("html").send(PAGE));

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Taskly</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#f4f5f7;--panel:#fff;--ink:#172b4d;--mut:#5e6c84;--line:#e4e8ee;--acc:#0c66e4;--acc2:#e9f2ff}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--ink)}
.top{display:flex;align-items:center;justify-content:space-between;padding:12px 24px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand{font-weight:700;font-size:18px;display:flex;align-items:center;gap:9px}
.brand .d{width:22px;height:22px;background:var(--acc);border-radius:6px;display:inline-block;position:relative}
.brand .d:after{content:"";position:absolute;inset:6px 5px auto 5px;height:2.5px;background:#fff;border-radius:2px;box-shadow:0 5px 0 #fff}
.who{font-size:13px;color:var(--mut)}
.wrap{max-width:1080px;margin:0 auto;padding:22px 24px}
.cols{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
@media(max-width:800px){.cols{grid-template-columns:1fr}}
.col{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}
.col h3{margin:0 0 10px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}
.card{background:#fff;border:1px solid var(--line);border-radius:9px;padding:11px 12px;margin-bottom:9px;font-size:14px;box-shadow:0 1px 1px rgba(9,30,66,.08)}
.card .by{color:var(--mut);font-size:12px;margin-top:4px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin-top:18px}
.panel h2{font-size:15px;margin:0 0 4px}.panel p{color:var(--mut);font-size:13px;margin:0 0 12px}
label{display:block;font-size:12px;color:var(--mut);margin:10px 0 5px}
input,select{width:100%;max-width:280px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;font-size:14px;font-family:inherit}
button{margin-top:14px;background:var(--acc);color:#fff;border:0;border-radius:8px;padding:10px 18px;font-weight:600;font-size:14px;cursor:pointer}
.out{margin-top:12px;background:#0b1b33;color:#7ee787;border-radius:8px;padding:10px;font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;min-height:18px}
.locked{display:flex;align-items:center;gap:8px;color:var(--mut);font-size:13px}
</style></head><body>
<div class="top">
  <div class="brand"><span class="d"></span> Taskly</div>
  <div class="who">Signed in as <b>alice</b> (user)</div>
</div>
<div class="wrap">
  <div class="cols">
    <div class="col"><h3>To do</h3>
      <div class="card">Draft Q4 report<div class="by">alice</div></div>
      <div class="card">Review PR #214<div class="by">bob</div></div></div>
    <div class="col"><h3>In progress</h3>
      <div class="card">Invoice export<div class="by">alice</div></div></div>
    <div class="col"><h3>Done</h3>
      <div class="card">Fix login bug<div class="by">carol</div></div></div>
  </div>

  <div class="panel">
    <h2>Preferences</h2>
    <p>Update your workspace preferences. Saved to your profile.</p>
    <label>Theme</label>
    <select id="theme"><option>light</option><option>dark</option><option>sepia</option></select>
    <label>Density</label>
    <select id="density"><option>cozy</option><option>compact</option></select>
    <button onclick="savePrefs()">Save preferences</button>
    <div class="out" id="prefout"></div>
  </div>

  <div class="panel">
    <h2>Admin panel 🔒</h2>
    <p class="locked">Restricted to administrators.</p>
    <button onclick="adminFlag()">Open admin panel</button>
    <div class="out" id="adminout"></div>
  </div>
</div>
<script>
const $=id=>document.getElementById(id);
async function savePrefs(){
  const body={theme:$("theme").value,density:$("density").value};
  const r=await fetch("/api/preferences",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  $("prefout").textContent=JSON.stringify(await r.json());
}
async function adminFlag(){
  const r=await fetch("/api/admin/flag");
  $("adminout").textContent=JSON.stringify(await r.json());
}
</script>
</body></html>`;

app.listen(80, "0.0.0.0", () => console.log("Taskly on :80"));
