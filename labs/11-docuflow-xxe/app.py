"""
DocuFlow — contact import service.  Educational lab only.
Looks like an enterprise tool; underneath, the XML import parser resolves
external entities -> XXE (XML External Entity injection) -> local file read.
"""
import os
from flask import Flask, request, jsonify, render_template_string
from lxml import etree

app = Flask(__name__)
FLAG_PATH = "/flag.txt"   # the flag lives here on the server


@app.route("/api/import", methods=["POST"])
def import_contacts():
    xml = request.get_data()
    if not xml:
        return jsonify({"ok": False, "error": "Send an XML body."}), 400
    try:
        # VULNERABLE: this parser loads DTDs and resolves external entities,
        # so a crafted <!DOCTYPE ... <!ENTITY ...>> can read local files.
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
        root = etree.fromstring(xml, parser)
    except Exception as e:
        return jsonify({"ok": False, "error": f"XML parse error: {e}"}), 400

    contacts = []
    for c in root.findall(".//contact"):
        name = (c.findtext("name") or "").strip()
        email = (c.findtext("email") or "").strip()
        contacts.append({"name": name, "email": email})
    return jsonify({"ok": True, "imported": len(contacts), "contacts": contacts})


@app.route("/")
def home():
    return render_template_string(PAGE)


PAGE = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DocuFlow</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#f5f6f8;--panel:#fff;--ink:#1c2430;--mut:#687385;--line:#e6e9ee;--acc:#1e8e6a;--acc2:#e7f6f0}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--ink)}
.top{display:flex;align-items:center;justify-content:space-between;padding:13px 26px;background:var(--panel);border-bottom:1px solid var(--line)}
.brand{font-weight:700;font-size:18px;display:flex;align-items:center;gap:9px}
.brand .d{width:22px;height:22px;border-radius:6px;background:var(--acc);display:inline-block}
.who{font-size:13px;color:var(--mut)}
.wrap{max-width:900px;margin:0 auto;padding:24px 26px}
.row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:18px}
@media(max-width:800px){.row{grid-template-columns:1fr}}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
.kpi b{font-size:26px;display:block}.kpi span{color:var(--mut);font-size:12.5px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}
.panel h2{font-size:15px;margin:0 0 4px}.panel p{color:var(--mut);font-size:13px;margin:0 0 12px}
textarea{width:100%;min-height:150px;font-family:ui-monospace,monospace;font-size:12.5px;border:1px solid var(--line);border-radius:9px;padding:11px}
button{margin-top:12px;background:var(--acc);color:#fff;border:0;border-radius:9px;padding:11px 20px;font-weight:600;font-size:14px;cursor:pointer}
.out{margin-top:12px;background:#0b1b16;color:#7ee7b6;border-radius:9px;padding:11px;font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;min-height:18px}
.hint{color:var(--mut);font-size:12px;margin-top:10px}
.hint code{background:#f0f2f5;padding:1px 6px;border-radius:5px}
</style></head><body>
<div class="top"><div class="brand"><span class="d"></span> DocuFlow</div><div class="who">workspace: acme-corp</div></div>
<div class="wrap">
  <div class="row">
    <div class="kpi"><b>8,412</b><span>Documents</span></div>
    <div class="kpi"><b>1,097</b><span>Contacts</span></div>
    <div class="kpi"><b>42</b><span>Imports this week</span></div>
  </div>
  <div class="panel">
    <h2>Bulk import contacts (XML)</h2>
    <p>Paste your contacts export below. We support the standard DocuFlow XML contact format.</p>
    <textarea id="xml"><contacts>
  <contact><name>Jane Smith</name><email>jane@acme.io</email></contact>
  <contact><name>Omar Ali</name><email>omar@acme.io</email></contact>
</contacts></textarea>
    <button onclick="imp()">Import</button>
    <div class="out" id="out"></div>
    <div class="hint">POST your XML to <code>/api/import</code>. Parsed contacts are echoed back in the response.</div>
  </div>
</div>
<script>
async function imp(){
  const r=await fetch("/api/import",{method:"POST",headers:{"Content-Type":"application/xml"},body:document.getElementById("xml").value});
  document.getElementById("out").textContent=JSON.stringify(await r.json(),null,2);
}
</script>
</body></html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)
