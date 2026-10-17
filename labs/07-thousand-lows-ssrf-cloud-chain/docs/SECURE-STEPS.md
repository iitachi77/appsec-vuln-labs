# EXAM 01 — Remediation Walkthrough (Blue Team)

How each link in the chain was fixed, and the two lessons that matter most.

---

## Fix table

| # | Finding | Category | Fix (what & where) | Breaks chain? |
|---|---------|----------|--------------------|:---:|
| 1 | Verbose error leak | code | `errorhandler` returns a generic message + error id; full trace logged server-side only (`app/app.py`) | recon only |
| 2 | SSRF in `/import` | code | `is_safe()` resolves the host and requires `is_global` (rejects link-local/private/loopback) + `allow_redirects=False` (`app/app.py`) | ✅ **yes** |
| 3 | IMDSv1 accepted | cloud | `http_tokens = "required"` + hop-limit 1 (`infra/instance.tf`) | ✅ **yes** |
| 4 | Over-privileged IAM role | cloud | Removed `s3:PutObject` — the app only reads (`infra/instance.tf`) | ✅ **yes** |
| 5 | `yaml.load(Loader=yaml.Loader)` RCE | code + dep | `yaml.safe_load()` + `try/except` (`app/app.py`) | ✅ **yes (the sink)** |
| 6 | No auth on `/reload` | code | Require `X-Admin-Token` (`app/app.py`) | hardening |
| 7 | SSTI via `title` concat | code | Pass `title` as a Jinja *context* var, not into the template source | hardening |
| 8 | `debug=True`, old PyYAML | code/dep | `debug=False`; PyYAML `6.0.2` | hardening |

## The two defenses that each severed the chain
Because the attack is a chain, you don't have to fix everything to stop *this* RCE — breaking
**any one** of the reachability links is enough:
- **Fix the SSRF** → attacker can't reach IMDS → no creds → no write → sink unreachable.
- **Enforce IMDSv2** → the GET-only SSRF can't complete the token handshake → no creds.
- **Drop `s3:PutObject`** → even with creds, attacker can't plant a template → sink unreachable.

**But defense-in-depth says fix the sink too** (`safe_load`), because reachability can change
(a new feature, an insider, a different SSRF next year). A latent critical is a loaded gun with
the safety on — remove the round, don't just trust the safety.

---

## Lesson 1 — Upgrading a dependency ≠ fixing the vulnerability
The RCE was **not** "old PyYAML." Proof: on the *patched* PyYAML 6.0.2, the unsafe loader still runs code:
```python
# PyYAML 6.0.2
yaml.load(payload, Loader=yaml.Loader)   # → executes !!python/object/apply  (STILL RCE)
yaml.safe_load(payload)                  # → ConstructorError (blocked)  ✅
```
The bug was the **code's choice of loader**. When SCA flags a library, always ask:
*"is the problem the version, or the way we use it?"* Here it was the usage — so the fix is in code.

## Lesson 2 — Severity lives in the chain, not the line
Six findings that each looked like "LOW, it's internal / it's just config / only a GET" combined
into Critical RCE. Rate findings by **what they unlock when chained**, and never dismiss a "low"
that sits on the path to a dangerous sink.

---

## Verification (secured build)
```
SSRF → metadata        : 400 URL not allowed      ✅ blocked
/reload (no token)     : 401 unauthorized         ✅ blocked
malicious YAML + reload: skipped by safe_load      ✅ no RCE (payload inert)
benign template        : renders normally          ✅ still works
```
