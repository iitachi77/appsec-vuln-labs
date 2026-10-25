# 📄 LAB 19 — "DocuFlow": XML External Entity (XXE) Injection

**Type:** Web App Pentest + Secure Code Review · **Class:** XXE (new class for you) · **Difficulty:** ⭐⭐⭐½
**Target:** http://localhost:9009 · **Approach:** black-box · ✅ **Solved ~7/10** (first XXE; valid JSON fix)

> A classic every pentester must own. The enterprise world runs on XML — SOAP, SAML, office docs,
> feeds, data imports — and parsers that resolve external entities turn "upload a file" into
> "read the server's files."

## How to run
**Native (reliable — your Ubuntu box):**
```bash
cd lab19-xxe
pip install flask lxml
echo 'FLAG{xxe_3xt3rn4l_3nt1ty_f1l3_r34d}' | sudo tee /flag.txt
sudo python3 app.py        # serves on :80  (or edit port to 9009)
```
**Docker:**
```bash
docker compose up -d        # http://localhost:9009
```

## Primer (30 seconds — since it's new)
XML lets a document declare **entities** — reusable variables — in a `<!DOCTYPE>`. An **external**
entity can point at a URI, including a local file:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```
If the server's parser **resolves external entities**, then anywhere you write `&xxe;` in the XML, the
parser substitutes the *contents of that file*. If the app then **echoes that value back**, you've
read a file off the server. That's XXE.

## Part 1 — Break it (exploit)
DocuFlow imports contacts from XML and **echoes the parsed `name`/`email` back** in the response.
Find the file-read. Read `/flag.txt`.

In your writeup: the sink (which parser, why it's vulnerable), your exact payload, and the flag.

> Hint: declare an external entity pointing at the file, then reference it inside a field the app
> reflects back to you.

## Part 2 — Secure it (blue team) 🛡️
Patch `app.py` so XXE dies and legitimate imports still work. Save `app_fixed.py`. Root-cause thinking:
- The fix is **not** blacklisting `SYSTEM`/`file://` strings — why is that a losing game?
- What's the *structural* fix? (Disable DTD processing / external-entity resolution entirely, e.g. an
  `lxml` parser with `resolve_entities=False, no_network=True, load_dtd=False`; better yet, use
  **`defusedxml`**, the library built precisely to make Python XML parsing safe by default.)
- Bonus: XXE can also do **SSRF** (`<!ENTITY xxe SYSTEM "http://169.254.169.254/...">`) and blind/OOB
  exfiltration — note why the same fix kills all of it.

Deliverable: `app_fixed.py` + one paragraph on the root cause.

---
*Deliberately vulnerable. Educational use only.*
