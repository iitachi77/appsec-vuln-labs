"""
LEDGERLY — accounting & invoicing API.  Educational EXAM lab (5 stars).
No credentials. A 3-stage chain:
   1) XXE on the XML import  -> read a local file
   2) leak the JWT signing secret (stored on disk) -> forge an admin token
   3) the admin "restore" endpoint deserializes with pickle -> RCE -> /flag.txt
"""
import os
import base64
import pickle
import jwt
from flask import Flask, request, jsonify, render_template_string
from lxml import etree

app = Flask(__name__)

# the signing secret is generated at boot and written to disk (an attacker must LEAK it, not guess it)
SECRET_DIR = "/tmp/ledgerly"
SECRET_PATH = os.path.join(SECRET_DIR, "secret.key")
os.makedirs(SECRET_DIR, exist_ok=True)
JWT_SECRET = "ldg_" + os.urandom(16).hex()
with open(SECRET_PATH, "w") as f:
    f.write(JWT_SECRET)


def current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return jwt.decode(auth[7:], JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None


# ---------- STAGE 1: XXE ----------
@app.route("/api/import", methods=["POST"])
def import_xml():
    xml = request.get_data()
    if not xml:
        return jsonify({"ok": False, "error": "send XML"}), 400
    try:
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
        root = etree.fromstring(xml, parser)
    except Exception as e:
        return jsonify({"ok": False, "error": f"parse error: {e}"}), 400
    rows = []
    for inv in root.findall(".//invoice"):
        rows.append({"ref": (inv.findtext("ref") or "").strip(),
                     "note": (inv.findtext("note") or "").strip()})
    return jsonify({"ok": True, "imported": len(rows), "invoices": rows})


# ---------- STAGE 2 target: login (issues HS256 JWT) ----------
@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json(force=True, silent=True) or {}
    # only a demo 'viewer' account exists; admin must be FORGED with the leaked secret
    if d.get("username") == "viewer" and d.get("password") == "viewer":
        return jsonify({"ok": True, "token": jwt.encode({"sub": "viewer", "role": "viewer"},
                                                         JWT_SECRET, algorithm="HS256")})
    return jsonify({"ok": False, "error": "invalid"}), 401


@app.route("/api/me")
def me():
    u = current_user()
    return (jsonify({"ok": True, "user": u}) if u
            else (jsonify({"ok": False, "error": "unauth"}), 401))


# ---------- STAGE 3: admin restore -> insecure deserialization ----------
@app.route("/api/admin/restore", methods=["POST"])
def restore():
    u = current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"ok": False, "error": "admin only"}), 403
    d = request.get_json(force=True, silent=True) or {}
    state = d.get("state", "")
    try:
        # VULNERABLE: pickle.loads on attacker-controlled data -> RCE
        obj = pickle.loads(base64.b64decode(state))
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
<!-- TODO(devops): rotate the signing key and move it out of /tmp/ledgerly/secret.key before go-live -->
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
    <h2>Import invoices (XML)</h2>
    <p>Upload your invoice batch in the Ledgerly XML format.</p>
    <textarea id="xml"><invoices><invoice><ref>INV-900</ref><note>Q3 retainer</note></invoice></invoices></textarea>
    <button onclick="imp()">Import</button>
    <div class="out" id="out"></div>
  </div>
</div>
<script>
async function imp(){const r=await fetch("/api/import",{method:"POST",headers:{"Content-Type":"application/xml"},body:document.getElementById("xml").value});document.getElementById("out").textContent=JSON.stringify(await r.json(),null,2);}
</script>
</body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)
