# Flowspace — SQLi → JWT Forge → IDOR → Filtered SSTI → RCE

> A realistic team-workspace SaaS taken from a self-registered member account to full
> remote code execution, by chaining **four** distinct, load-bearing weaknesses.

**Difficulty:** ★★★★★ · **Vuln classes:** SQL injection · JWT forgery · IDOR/BOLA · Server-Side Template Injection (filtered)

---

## The application

`Flowspace` is a project-tracker SaaS — dashboard, projects, tasks, search, activity,
team, billing, integrations, an admin console and a "Report Vault" — ~1,400 lines across
19 pages and a JSON API. It looks like a normal product; the exploit path is buried in the
surface area. The flag lives **only** in the server process environment (`$FLAG`): the only
thing that can read it is **code execution** on the box.

The design is deliberately airtight — **every link is load-bearing.** There is no file-read
shortcut and no single bug reaches the flag. Two secrets gate the final sink, they live in
**two different stores**, and each is reached by a **different** bug:

| Stage | Bug | Yields | Why it can't be skipped |
|------:|-----|--------|-------------------------|
| 1 | **SQL injection** on `/api/reports/tasks` | the JWT signing secret (from the DB `settings` table) | key is strong/random — can't be guessed; alg is pinned so `alg:none` won't work |
| 2 | **JWT forgery** | an `role:admin` session | Vault endpoints reject non-admin tokens (403) |
| 3 | **IDOR** on `/api/integrations/<id>` | the webhook **HMAC** signing secret (from a flat file, *not* the DB) | the Vault export also requires a valid `X-Vault-Signature` HMAC over the body |
| 4 | **Filtered SSTI** on `/api/admin/vault/export` | **RCE → `$FLAG`** | needs admin JWT **and** the HMAC secret; the template sink is guarded by a char/keyword blocklist |

The two secrets are in disjoint stores (JWT key in the **database**, HMAC key in a **file**),
reachable by two different bugs — so the full chain is genuinely required.

## Run it

```bash
docker compose up -d --build        # -> http://localhost:9011
docker compose down                 # when finished
```
or natively:
```bash
pip install -r requirements.txt
FLAG='FLAG{...}' python3 app.py      # -> http://localhost:9011
```

The flag is injected via the `FLAG` environment variable; the JWT and webhook secrets are
generated fresh on every boot, so they must be **leaked**, not guessed.

## Contents

| File | What it is |
|------|------------|
| [`app.py`](app.py) | the vulnerable application |
| [`app_fixed.py`](app_fixed.py) | the patched build — **root-cause** fixes for all four bugs, features preserved |
| [`WRITEUP.md`](WRITEUP.md) | the polished exploit chain + remediation |
| [`Methodology.md`](Methodology.md) | my raw solve notes — black-box (DAST) first, then source review (SAST), then the combined report |
| `Photos/` | evidence screenshots referenced in the methodology |

## Key takeaways

- **The simplest primitive wins — but only if it exists.** Unlike a file-read chain, nothing
  here lets you jump straight to the objective; the gating is cryptographic and
  authorization-based, so the chain is mandatory.
- **Pinning the JWT algorithm is necessary but not sufficient** — the real protection is the
  signing key never being reachable by a data-layer bug.
- **A blocklist is the wrong fix for SSTI** — Jinja has too many equivalent spellings, and the
  solve assembles every forbidden character at evaluation time. The right fix is to stop
  treating user input as a template at all (render fixed templates, pass user text as data).
- **Moving a secret out of the database isn't enough on its own** — a *different* bug (IDOR)
  still reached the file-stored secret; the fix is object-level authorization plus never
  returning the secret over the API.

> Intentionally vulnerable, for education only. All brands are fictional.
