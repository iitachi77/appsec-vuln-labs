# Lab 08 — JWT Secret Cracking & Remediation

**Target:** VaultAPI, a small Flask app issuing HS256 JWTs.
**Objective:** Reach the admin-only `/admin` endpoint (no admin login exists) and recover the flag, then harden the app against the attack.

---

## 1. Recon

Reviewed the application source and mapped the surface:

- `POST /login` — returns a signed JWT for valid credentials (`alice`/`bob`, both `role: user`).
- `GET /me` — echoes the decoded claims for a valid token.
- `GET /admin` — requires `role: admin`; returns the flag.
- JWTs signed with **HS256** (a symmetric HMAC algorithm — the same secret signs and verifies).

**Key observation:** there is no admin account. The only way in is to produce a token with `role: admin` that the server accepts — i.e. forge one. Forging an HS256 token requires knowing the signing secret.

---

## 2. Vulnerability

The signing secret was a weak, dictionary-word value (`trustno1`) hardcoded in the source.

Because HS256 is symmetric, a captured token can be verified **offline** against any candidate secret: recompute the HMAC and compare signatures. No interaction with the server is needed, so the attempt rate is effectively unlimited and no rate-limiting or lockout applies. A weak secret therefore falls to an offline dictionary attack.

---

## 3. Exploitation

### 3.1 Obtain a legitimate token
Logged in as `alice` via `POST /login` to get a valid HS256 token to crack against.

### 3.2 Crack the secret
Ran a dictionary attack (`cracker.py`) that tries each wordlist entry as the HS256 key, using PyJWT's `jwt.decode()` — which raises `InvalidSignatureError` on a wrong key and succeeds on the right one.

```
secret recovered: trustno1
```

With `rockyou.txt` this resolves almost instantly, since `trustno1` is a well-known weak password near the top of the list.

> Faster alternative for larger wordlists: `hashcat -m 16500 <token> rockyou.txt` (JWT mode).

### 3.3 Forge an admin token
Using the recovered secret, signed a new token with an elevated role:

```python
import jwt
jwt.encode({"sub": "alice", "role": "admin"}, "trustno1", algorithm="HS256")
```

(The app's in-browser "Forge a token" box does the same thing client-side.)

### 3.4 Capture the flag
Sent the forged token to `/admin`:

```
Authorization: Bearer <forged-token>
```

The server verified the signature with the same weak secret, accepted `role: admin`, and returned the flag:

```
FLAG{f0rged_my_w4y_t0_4dm1n_jwt}
```

---

## 4. Root cause

| # | Issue | Why it matters |
|---|-------|----------------|
| 1 | Weak, hardcoded signing secret | Enables offline dictionary attack → token forgery (**the break**) |
| 2 | Plaintext password storage | Full account compromise if the store leaks |
| 3 | Tokens never expire | A leaked/forged token is valid forever |
| 4 | Decode didn't require expected claims | Tokens missing `exp` treated as eternal |
| 5 | Verbose error responses | Leaks internals (e.g. echoes caller's role) for recon |

The app did two things correctly that are worth preserving: the decode step **pinned `algorithms=["HS256"]`** (blocking the `alg: none` and HS/RS key-confusion attacks) and **verified the signature** rather than trusting the payload.

---

## 5. Remediation

Implemented in `vaultapi_fixed.py`:

1. **Strong secret from the environment.** Replaced `trustno1` with a high-entropy value (`secrets.token_urlsafe(64)`, ~512 bits) loaded from `JWT_SECRET`. No wordlist contains it, so the offline attack becomes computationally infeasible — this alone closes the exploited path.
2. **Hashed passwords.** Stored salted slow hashes via `generate_password_hash` / `check_password_hash` (Werkzeug).
3. **Token expiry.** Added `iat` and `exp` (15-minute TTL); PyJWT enforces `exp` on decode.
4. **Stricter decode.** Kept the pinned algorithm and added `options={"require": ["exp","iat","sub","role"]}` so incomplete tokens are rejected.
5. **Generic errors.** Log detail server-side; return non-descriptive messages to the client and stop echoing the caller's role.

Also removed the in-browser "Forge a token" helper from the hardened UI, as its only purpose was to exploit the weak secret.

**Verification:** re-running the cracker against the hardened build exhausts the wordlist with no match, confirming the secret is no longer recoverable.

---

## 6. Takeaways

- With a symmetric JWT algorithm, the signing secret **is** the entire trust boundary — it must be long and random, treated like a private key, and kept out of source control.
- Attacks on HMAC secrets happen offline, so server-side rate limiting offers no protection; entropy is the only defense.
- Always validate the token fully: pin the algorithm, verify the signature, and require the claims you depend on.
