# Lab 08 — VaultAPI: Forging a JWT to Admin

**Category:** API / Authentication Security · JWT · (OWASP API2: Broken Authentication)
**Difficulty:** ⭐⭐ Intermediate
**Skills:** JWT structure, offline HMAC secret cracking, token forging, privilege escalation

---

## Scenario
VaultAPI issues **JSON Web Tokens (JWT)** signed with HS256. You have two normal user logins, but
**no admin account** — and the flag is at `/admin`, which requires `role: admin`. So you can't log
in as admin… you have to *become* admin another way.

## Objective
Get the flag from `GET /admin`.

## Endpoints
```
POST /login    {"username","password"}      -> returns a JWT
GET  /me       Authorization: Bearer <jwt>  -> your claims
GET  /admin    Authorization: Bearer <jwt>  -> admin only (flag)
```
Credentials you have: `alice : password123`  |  `bob : qwerty2024`

## Background (new domain — the essentials)
A JWT is three base64url parts: `header.payload.signature`.
- **header** = `{"alg":"HS256","typ":"JWT"}`
- **payload** = your claims, e.g. `{"sub":"alice","role":"user"}`
- **signature** = `HMAC-SHA256(header + "." + payload, SECRET)`

The server trusts whatever is in the payload **as long as the signature verifies.** So if you can
change `role` to `admin` *and* produce a valid signature, you're admin. Producing a valid signature
means you need the **secret** — which, for HS256, is just an HMAC key you can attack **offline**.

> The `none` algorithm is **not** accepted here, so you can't skip the signature. You must recover
> the secret. (The server's secret is weak — that's the vulnerability.)

## How to run
```bash
cd "CTF-Labs/lab08-jwt"
docker compose up -d        # ~10s to install
```
API at http://localhost:8083 · Tear down: `docker compose down`

## Approach
1. **Log in** as `alice`, capture the JWT.
2. **Crack the HMAC secret offline.** On Kali you have the tools:
   - `hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt`
   - or `john` / `jwt_tool <token> -C -d rockyou.txt`
3. **Forge a new token** with `"role":"admin"`, signed with the recovered secret (`jwt_tool`,
   or a 3-line Python `jwt.encode(...)`).
4. Send it to `/admin`.

## Part 2 — SECURE THE CODE (blue team) 🔧
After you've forged your way in, fix `app.py` so forging is impossible. Edit it, restart
(`docker compose restart vaultapi`), and prove your own exploit now fails. Minimum fixes:

1. **Strong secret, not hardcoded.** Replace `"trustno1"` with a high-entropy key (≥32 bytes,
   e.g. `secrets.token_hex(32)`) loaded from an environment variable / secret manager — never in source.
2. **Add expiry + claims validation.** Set `exp` on sign; verify `exp` (and ideally `iss`/`aud`) on decode.
3. **Keep algorithm pinning.** `algorithms=["HS256"]` is already correct — understand *why* a missing
   or wide `algorithms` list (allowing `none`, or `HS256` + `RS256`) is dangerous.
4. **(Discuss) Asymmetric signing.** Why `RS256`/`EdDSA` is safer than a shared HMAC secret for
   multi-service setups, and how it prevents the alg-confusion attack.

Then **re-test your crack/forge** — a strong random secret makes the offline attack computationally
infeasible, so the same payload should now fail to verify.

## Reflection questions (for your writeup)
1. Why is a *weak* HMAC secret catastrophic for HS256 — and what key length/entropy fixes it?
2. Why does accepting the `none` algorithm completely break JWT auth?
3. What's the `RS256 → HS256` algorithm-confusion attack, and how does it relate to this?
4. Beyond a strong secret, name two more JWT hardening measures.

---
*Educational lab. Only ever attack tokens/systems you own or are authorized to test.*
