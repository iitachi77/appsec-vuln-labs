import os
import base64
import json  # FIXED: Imported json to replace unsafe pickle deserialization
import jwt
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# FIXED: Load the JWT signing secret securely from an environment variable instead of writing it to disk
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("Critical Error: JWT_SECRET environment variable is not set.")


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


# ---------- STAGE 1 FIX: Eliminated XXE by switching from XML to JSON ----------
@app.route("/api/import", methods=["POST"])
def import_json():
    # FIXED: Use request.get_json() instead of parsing untrusted XML data, removing XXE attack surface completely
    d = request.get_json(silent=True)
    if not d or "invoices" not in d:
        return jsonify({"ok": False, "error": "send valid JSON with an invoices array"}), 400
    
    rows = []
    for inv in d.get("invoices", []):
        rows.append({
            "ref": str(inv.get("ref", "")).strip(),
            "note": str(inv.get("note", "")).strip()
        })
    return jsonify({"ok": True, "imported": len(rows), "invoices": rows})


# ---------- STAGE 2 target: login (issues HS256 JWT) ----------
@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json(force=True, silent=True) or {}
    if d.get("username") == "viewer" and d.get("password") == "viewer":
        return jsonify({"ok": True, "token": jwt.encode({"sub": "viewer", "role": "viewer"},
                                                        JWT_SECRET, algorithm="HS256")})
    return jsonify({"ok": False, "error": "invalid"}), 401


@app.route("/api/me")
def me():
    u = current_user()
    return (jsonify({"ok": True, "user": u}) if u
            else (jsonify({"ok": False, "error": "unauth"}), 401))


# ---------- STAGE 3 FIX: Replaced unsafe pickle with safe JSON parsing ----------
@app.route("/api/admin/restore", methods=["POST"])
def restore():
    u = current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"ok": False, "error": "admin only"}), 403
    d = request.get_json(force=True, silent=True) or {}
    state = d.get("state", "")
    try:
        # FIXED: Replaced pickle.loads() with json.loads() to completely prevent Insecure Deserialization RCE
        decoded_bytes = base64.b64decode(state)
        obj = json.loads(decoded_bytes.decode("utf-8"))
    except Exception as e:
        return jsonify({"ok": False, "error": f"restore error: {e}"}), 400
    return jsonify({"ok": True, "restored": str(obj)[:300]})


@app.route("/")
def home():
    return render_template_string(PAGE)


PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ledgerly</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0f1317;--panel:#171c22;--panel2:#1e252d;--ink:#e8edf2;--mut:#8b97a4;--line:#28313b;--acc:#2ecc9b}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--ink)}
.top{display:flex;justify-content:space-between;align-items:center;padding:14px 26px;background:#131820;border-bottom:1px solid var(--line)}
.brand{font-weight:700;font-size:18px;display:flex;align-items:center;gap:9px}.brand .d{width:22px;height:22px;border-radius:6px;background:var(--acc);display:inline-block}
.wrap{max-width:960px;margin:0 auto;padding:24px 26px}
.row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:18px}
@media(max-width:800px){.row{grid-template-columns:1fr}}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}.kpi b{font-size:26px;display:block}.kpi span{color:var(--mut);font-size:12.5px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}
.panel h2{font-size:15px;margin:0 0 4px}.panel p{color:var(--mut);font-size:13px;margin:0 0 12px}
textarea{width:100%;min-height:120px;font-family:ui-monospace,monospace;font-size:12.5px;background:var(--panel2);border:1px solid var(--line);border-radius:9px;color:var(--ink);padding:11px}
button{margin-top:10px;background:var(--acc);color:#06281e;border:0;border-radius:9px;padding:10px 18px;font-weight:700;font-size:14px;cursor:pointer}
.out{margin-top:12px;background:#0a0f0c;color:#6ff0bf;border-radius:9px;padding:11px;font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;min-height:18px}
</style></head><body>
<div class="top"><div class="brand"><span class="d"></span> Ledgerly</div><div style="color:var(--mut);font-size:13px">v2.8 · acme finance</div></div>
<div class="wrap">
  <div class="row"><div class="kpi"><b>$1.2M</b><span>Invoiced (Q3)</span></div><div class="kpi"><b>3,418</b><span>Invoices</span></div><div class="kpi"><b>12</b><span>Pending approvals</span></div></div>
  <div class="panel">
    <h2>Import invoices (JSON)</h2>
    <p>Upload your invoice batch in the secure Ledgerly JSON format.</p>
    <textarea id="json-input">{
  "invoices": [
    {"ref": "INV-900", "note": "Q3 retainer"}
  ]
}</textarea>
    <button onclick="imp()">Import</button>
    <div class="out" id="out"></div>
  </div>
</div>
<script>
async function imp(){
  const r=await fetch("/api/import",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:document.getElementById("json-input").value
  });
  document.getElementById("out").textContent=JSON.stringify(await r.json(),null,2);
}
</script>
</body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)