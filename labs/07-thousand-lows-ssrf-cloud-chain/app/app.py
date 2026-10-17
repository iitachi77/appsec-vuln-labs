"""
ReportForge — internal report microservice (RUNNABLE / exploitable build).
Same vulnerabilities as the review copy; wired so the full chain actually works.
Loads YAML templates from a config store (S3 stand-in) using its instance creds.
"""
import os
import traceback

import yaml
import requests
from flask import Flask, request, jsonify, render_template_string

import socket
import ipaddress
from urllib.parse import urlsplit

import uuid, logging
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

STORE_URL = os.environ.get("STORE_URL", "http://configstore:9000")
CONFIG_BUCKET = os.environ.get("CONFIG_BUCKET", "reportforge-config-prod")
CONFIG_SECRET = os.environ.get("CONFIG_SECRET", "")   # the instance role's secret
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")       # REMEDIATION: gate the admin-only /reload

TEMPLATES = {}


def fetch_key(key):
    r = requests.get(f"{STORE_URL}/{CONFIG_BUCKET}/{key}",
                     headers={"X-Amz-Secret": CONFIG_SECRET}, timeout=5)
    return r.content


DASH = """
<!doctype html><html><head><meta charset="utf-8"><title>ReportForge</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:30px auto;padding:0 16px;background:#0e1116;color:#e8edf3}
h1{margin:0 0 2px} .sub{color:#8b949e;margin:0 0 18px;font-size:14px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px}
.card h3{margin:0 0 10px;font-size:15px}
input,textarea{width:100%;box-sizing:border-box;padding:8px;margin:4px 0 10px;background:#0d1117;
 border:1px solid #30363d;color:#e8edf3;border-radius:6px;font-family:ui-monospace,monospace;font-size:13px}
textarea{min-height:70px;resize:vertical}
button{background:#238636;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px}
button.alt{background:#1f6feb}
pre{background:#0b0e13;border:1px solid #222;border-radius:8px;padding:10px;overflow:auto;
 white-space:pre-wrap;word-break:break-word;font-size:12px;max-height:230px}
.lbl{font-size:12px;color:#8b949e}
code{background:#0d1117;padding:1px 5px;border-radius:4px}
</style></head><body>
<h1>📄 ReportForge</h1>
<p class="sub">Internal report service &middot; config store: <code>http://localhost:9000</code> &middot;
bucket: <code>reportforge-config-prod</code></p>
<div class="grid">

  <div class="card"><h3>🔗 Import / Preview a URL</h3>
    <span class="lbl">Fetches the URL server-side and previews it.</span>
    <input id="u" placeholder="https://example.com" value="http://169.254.169.254/latest/meta-data/">
    <button onclick="imp()">Preview</button>
    <pre id="impout">—</pre>
  </div>

  <div class="card"><h3>🗂️ Config Store Upload (PUT)</h3>
    <span class="lbl">Writes an object to the bucket. Requires the role secret.</span>
    <input id="k" placeholder="key e.g. pwn.yaml" value="pwn.yaml">
    <textarea id="c" placeholder="object content (YAML)"></textarea>
    <input id="sec" placeholder="X-Amz-Secret (credential)">
    <button class="alt" onclick="put()">Upload</button>
    <pre id="putout">—</pre>
  </div>

  <div class="card"><h3>♻️ Reload Templates</h3>
    <span class="lbl">Loads &amp; parses every template (admin only).</span>
    <input id="atok" placeholder="X-Admin-Token" value="rf-admin-7y3">
    <button onclick="reload()">Reload</button>
    <button class="alt" onclick="tpls()">List loaded</button>
    <pre id="reout">—</pre>
  </div>

  <div class="card"><h3>📝 Render Report</h3>
    <span class="lbl">Renders a loaded template.</span>
    <input id="tk" placeholder="template key" value="monthly-report.yaml">
    <textarea id="tv" placeholder='values JSON e.g. {"revenue":"100"}'>{}</textarea>
    <button onclick="render()">Render</button>
    <pre id="rout">—</pre>
  </div>

</div>
<script>
const g=id=>document.getElementById(id);
async function show(el,p){try{const r=await p;const t=await r.text();g(el).textContent="["+r.status+"]\\n"+t;}catch(e){g(el).textContent="ERR "+e;}}
function imp(){show('impout',fetch('/import?url='+encodeURIComponent(g('u').value)));}
function reload(){show('reout',fetch('/reload',{headers:{'X-Admin-Token':g('atok').value}}));}
function tpls(){show('reout',fetch('/templates'));}
function render(){show('rout',fetch('/render',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({template:g('tk').value,values:JSON.parse(g('tv').value||'{}')})}));}
function put(){show('putout',fetch('http://localhost:9000/reportforge-config-prod/'+encodeURIComponent(g('k').value),
  {method:'PUT',headers:{'X-Amz-Secret':g('sec').value},body:g('c').value}));}
</script>
</body></html>
"""


@app.route("/")
def home():
    return DASH


@app.route("/templates")
def list_templates():
    return jsonify({"loaded": list(TEMPLATES.keys())})


@app.route("/reload")
def reload_templates():
    # REMEDIATION (Broken Access Control / CWE-306): a state-changing endpoint must
    # not be anonymous. Require an admin token. (Production = real session/role auth.)
    if request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    keys = requests.get(f"{STORE_URL}/{CONFIG_BUCKET}", timeout=5).json()["keys"]
    for k in keys:
        # REMEDIATION (Deserialization RCE / CWE-502): use safe_load, NOT
        # yaml.load(Loader=yaml.Loader). Upgrading PyYAML does NOT fix this on its
        # own — yaml.Loader is the UNSAFE full loader in every version. safe_load
        # forbids !!python/object/apply, which kills the deserialization RCE.
        try:
            TEMPLATES[k] = yaml.safe_load(fetch_key(k))
        except yaml.YAMLError:
            # Don't crash (or expose details) on a malformed/hostile template.
            continue
    return jsonify({"reloaded": list(TEMPLATES.keys())})

"""
#Old /import endpoint (SSRF sink) — kept for reference, but not used in the new dashboard.
@app.route("/import")
def import_template():
    # SSRF: fetches any URL and returns the body as a preview.
    url = request.args.get("url", "")
    if not url:
        return "provide ?url=", 400
    r = requests.get(url, timeout=5)
    return r.text[:5000]
"""
#the new /import endpoint is now implemented in the dashboard HTML/JS, which calls the same SSRF sink but is not exposed as a separate route.

#creating a function to check if the URL is safe (not internal/private) before fetching it
def is_safe(url):
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(p.hostname, None)}
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(ip).is_global for ip in ips)

#Including the is_safe check in the /import endpoint to prevent SSRF to internal/private IPs.
@app.route("/import")
def import_template():
    url = request.args.get("url", "")
    if not is_safe(url):
        return "URL not allowed", 400
    r = requests.get(url, timeout=5, allow_redirects=False)
    return r.text[:5000], 200, {"Content-Type": "text/plain"}


@app.route("/render", methods=["POST"])
def render_report():
    body = request.get_json(force=True, silent=True) or {}
    key = body.get("template", "")
    values = body.get("values", {})
    tpl = TEMPLATES.get(key)
    if tpl is None:
        return jsonify({"error": "unknown template; call /reload first"}), 404
    title = str(tpl.get("title", "Report")) if isinstance(tpl, dict) else str(tpl)
    # REMEDIATION (SSTI / CWE-1336): never concatenate data into the template SOURCE.
    # Pass it as a context variable so Jinja autoescapes it instead of evaluating it.
    html = render_template_string(
        "<h1>{{ title }}</h1><ul>{% for k,v in values.items() %}"
        "<li>{{k}}: {{v}}</li>{% endfor %}</ul>",
        title=title, values=values,
    )
    return html

"""
@app.errorhandler(Exception)
def handle_error(e):
    return (jsonify({"error": str(e), "trace": traceback.format_exc(),
                     "config_bucket": CONFIG_BUCKET, "store_url": STORE_URL}), 500)
"""
#the user must see only generic error messages, not the full traceback or internal details, to avoid information leakage.


@app.errorhandler(Exception)
def handle_error(e):
    if isinstance(e, HTTPException):
        return e
    error_id = uuid.uuid4().hex[:8]
    logging.exception("Unhandled error %s", error_id)
    return jsonify({"error": "Internal server error", "id": error_id}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
