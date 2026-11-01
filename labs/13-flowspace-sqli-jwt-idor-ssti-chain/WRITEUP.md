# Flowspace — SQLi → JWT Forge → IDOR → Filtered SSTI → RCE

| | |
|---|---|
| **Vulnerabilities** | SQL injection · JWT forgery (leaked signing key) · IDOR/BOLA · Server-Side Template Injection (filter-bypassed) |
| **Impact** | Full remote code execution; disclosure of a secret (`$FLAG`) readable only via RCE |
| **Difficulty** | ★★★★★ |
| **Approach** | Black-box (DAST) to capture, white-box (SAST) to confirm root cause |

## The application

Flowspace is a team-workspace SaaS (projects, tasks, billing, integrations, an admin
console and a "Report Vault"). A member account is free to self-register. The flag exists
**only** in the server's process environment, so the objective is really *"achieve code
execution."* Four distinct weaknesses stand between a fresh member and that goal, and each
one is a prerequisite for the next.

## Stage 1 — SQL injection → leak the JWT signing key

Mapping the app surfaces three candidate injection points. `login` and `search` are
parameterized dead-ends; the report filter is not:

```
GET /api/reports/tasks?status=open
```

The `status` parameter is concatenated straight into the query, and the error branch even
reflects the raw SQL — ideal for a boolean/blind extraction. Dumping the database yields the
`settings` table:

```
| jwt_secret   | fsk_ea6fd6548cacedf0354d6d2493a54003560cb89f4df7f0bd |
```

The JWT session-signing key is stored in the database. That is the entire point of Stage 1.

```sql
status = ' UNION SELECT 1,(SELECT value FROM settings WHERE key='jwt_secret'),'x
```

## Stage 2 — Forge an admin session

Sessions are HS256 JWTs. The algorithm is pinned server-side (so `alg:none`/alg-confusion is
out), but with the real signing key in hand, a perfectly valid admin token is trivial — keep
the token's structure, change `role` to `admin`, sign with the leaked key:

```json
{"sub":"6","email":"test@mail.com","name":"test","role":"admin","ws":2, ...}
```

Dropped into the `session` cookie, the admin console and the **Report Vault** appear.

## Stage 3 — IDOR → leak the webhook HMAC secret

The Vault export won't run on an admin token alone — it also demands a valid
`X-Vault-Signature` (an HMAC over the request body). That signing secret is **not** in the
database (Stage 1's SQLi can't reach it). The integrations page gives the lead:

> Secrets are hidden. Integrations are fetched from `/api/integrations/<id>`.

They are not hidden. The endpoint has no object-level authorization and returns the record
as-is, including the secret, for **any** id:

```
GET /api/integrations/1
→ "signing_secret": "whk_8dad10c4d5f7df09462c3c82886402a9eb384f8c469c1d74"
```

That is the HMAC key the Vault uses to authenticate export requests.

## Stage 4 — Filtered SSTI → RCE

The export endpoint renders an operator-supplied `template` server-side with Jinja2 — a
classic SSTI sink — but it is guarded by a blocklist (`.`, `_`, `[`, `]`, `~`, `-`, and
keywords like `os`, `class`, `globals`…). Off-the-shelf payloads bounce:

```json
{"error":"template contains a blocked token: '.'"}
```

The bypass is to never let a forbidden character appear in the literal source: assemble them
at evaluation time (e.g. building each needed character with `'%c'|format(N)` and joining
with `~`, reaching attributes via the `|attr()` filter). A generator script produces a
filter-clean payload that reaches `os.popen`, and the request is signed with the Stage-3
HMAC secret over the exact body:

```
X-Vault-Signature = HMAC_SHA256(webhook_secret, raw_body)
```

→ command execution on the server, and `$FLAG` is recovered:

```
FLAG{ch4in_1d0r_sql1_jwt_hm4c_ss7i_rce}
```

## Why every link is required

- **Skip the SQLi** — no `jwt_secret`; the key is random, so no token can be forged. Stuck as a member.
- **Skip the forge** — the Vault endpoints reject any non-admin token with 403.
- **Skip the IDOR** — even as admin, the export rejects a missing/invalid `X-Vault-Signature` (403).
- **Skip the SSTI** — admin + a valid signature only renders a template; you still need code execution to read the env-only flag.

Two secrets, two different stores (JWT key in the **DB**, HMAC key in a **file**), reached by
two different bugs. There is no primitive that reaches both, and none that reaches the flag
directly — so the full chain is mandatory.

## Root-cause remediation (implemented in `app_fixed.py`)

| # | Bug | Fix (root cause, not a band-aid) |
|---|-----|----------------------------------|
| 1 | SQLi | Bind `status` as a parameter (`?`); stop reflecting SQL/errors to the client. Kills the class, not just the payload. |
| 2 | Forged admin | Remove `jwt_secret` from the database — keep the key in process/env only. (Pinning the alg is necessary but not sufficient; the real save is the key being unreachable.) |
| 3 | IDOR | Enforce object-level authorization (`workspace_id == caller`), and strip `signing_secret` from every API response via a field whitelist. Moving the secret to a file was *not* enough on its own — a different bug still reached it. |
| 4 | SSTI | Stop compiling user input as a template. The client sends **data** (title + body); the server renders a fixed, developer-owned, autoescaped template. A blocklist is the wrong control — there are too many equivalent spellings. |

All fixes preserve every feature; only the four sinks change behaviour. Verified: after
patching, the injection returns no secret, the DB no longer contains `jwt_secret`,
`/api/integrations/<id>` returns 404 cross-workspace and never includes the secret, and the
Vault renders user text literally instead of executing it.

## Transferable lessons

1. Keep untrusted input as **inert data**, never as something an engine will act on — true for
   SQL (parameters), for templates (data not code), and for tokens (don't expose the key).
2. **Necessary ≠ sufficient.** Pinning a JWT algorithm and moving a secret out of the DB are
   both good — and both useless if the key can still be reached another way.
3. **Denylists lose.** The defender must enumerate every bad spelling; the attacker needs one
   the defender missed. Remove the dangerous mechanism instead.
