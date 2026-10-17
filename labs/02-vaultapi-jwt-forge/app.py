"""
VaultAPI — a tiny JWT-protected API. Educational lab only.
Log in to get a token; the admin area holds a flag.
"""
import jwt  # PyJWT
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# The HMAC secret used to sign/verify all tokens. (Find a way to recover it...)
JWT_SECRET = "trustno1"
ALGO = "HS256"

USERS = {
    "alice": {"password": "password123", "role": "user"},
    "bob":   {"password": "qwerty2024",  "role": "user"},
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
Objective: reach <code>/admin</code> (admin-only) &mdash; no admin login exists, so forge your way in.</p>
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

  <div class="card"><h3>3 · Forge a token 🔑</h3>
    <span class="lbl">Once you've cracked the secret, sign your own token (HS256, in-browser).</span>
    <textarea id="fp" placeholder='payload JSON'>{"sub":"alice","role":"admin"}</textarea>
    <input id="fs" placeholder="HMAC secret (cracked)">
    <button onclick="forge()">Sign token</button>
    <pre id="fout">—</pre>
  </div>

  <div class="card"><h3>4 · Test /me and /admin</h3>
    <span class="lbl">Paste a token and hit the protected endpoints.</span>
    <textarea id="tin" placeholder="paste JWT"></textarea>
    <button onclick="hit('/me')">GET /me</button>
    <button class="alt" onclick="hit('/admin')">GET /admin</button>
    <pre id="tout">—</pre>
  </div>

</div>
<script>
const g=id=>document.getElementById(id);
const enc=new TextEncoder();
function b64urlBytes(b){let s=btoa(String.fromCharCode(...b));return s.replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
function b64urlStr(s){return b64urlBytes(enc.encode(s));}
function b64urlDecode(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return atob(s);}
async function show(el,p){try{const r=await p;const t=await r.text();g(el).textContent="["+r.status+"]\\n"+t;}catch(e){g(el).textContent="ERR "+e;}}

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
async function forge(){
  try{
    const secret=g('fs').value, payload=g('fp').value;
    const head=b64urlStr(JSON.stringify({alg:"HS256",typ:"JWT"}));
    const pay=b64urlStr(JSON.stringify(JSON.parse(payload)));
    const data=head+"."+pay;
    const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
    const sig=new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode(data)));
    const tok=data+"."+b64urlBytes(sig);
    g('fout').textContent=tok; g('tin').value=tok;
  }catch(e){g('fout').textContent="forge error: "+e;}
}
function hit(path){show('tout',fetch(path,{headers:{'Authorization':'Bearer '+g('tin').value.trim()}}));}
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
    if not rec or rec["password"] != p:
        return jsonify({"error": "invalid credentials"}), 401
    token = jwt.encode({"sub": u, "role": rec["role"]}, JWT_SECRET, algorithm=ALGO)
    return jsonify({"token": token})


def read_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, "missing bearer token"
    token = auth[7:]
    try:
        # Only HS256 is accepted (the 'none' algorithm is NOT allowed here).
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return claims, None
    except Exception as e:
        return None, str(e)


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
        return jsonify({"error": "forbidden: admin role required", "your_role": claims.get("role")}), 403
    return jsonify({"message": "Welcome, admin.", "flag": FLAG})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
