# VaultAPI — Forging a JWT to Admin

| | |
|---|---|
| **Vulnerability** | JWT signed with a weak, guessable HMAC secret |
| **Impact** | Privilege escalation to admin |
| **Difficulty** | ★★★ |
| **Approach** | Black-box |

## The application

VaultAPI is a small JSON API. Logging in as a normal user (`alice`) returns a JWT that carries the
user's role; the `/admin` endpoint requires `role: admin`.

```bash
docker compose up -d        # http://localhost:8083
```

## Discovery

The token is a standard HS256 JWT. Two shortcuts are closed off:

- the `none` algorithm is **rejected**, so I can't strip the signature;
- the server validates the signature properly, so I can't just edit the payload.

That leaves the signing secret. HS256's security rests entirely on the secret being
high-entropy — and this one (`trustno1`) is a wordlist entry, so it falls to an offline attack.

## Exploitation

Capture alice's token and crack the HMAC secret offline. I wrote a small PyJWT dictionary attack
(`cracker.py`) that tries each candidate secret until one verifies the signature:

```python
# cracker.py — try each wordlist entry as the HS256 secret
for secret in wordlist:
    try:
        jwt.decode(token, secret, algorithms=["HS256"]); print("FOUND:", secret); break
    except jwt.InvalidSignatureError:
        continue
# FOUND: trustno1
```

(`hashcat -m 16500` or `jwt_tool` work equally well.) With the secret, I forge a valid token with
`role: admin` and call the admin endpoint:

```python
jwt.encode({"user": "alice", "role": "admin"}, "trustno1", algorithm="HS256")
```

```
FLAG{f0rged_my_w4y_t0_4dm1n_jwt}
```

## Root-cause fix

The signature was never the problem — the **secret** was. My patched version:

- loads a **long, random secret** (256-bit+) from the environment, never hard-coded;
- keeps the algorithm pinned to HS256 and **rejects `none`** (a control worth preserving, not
  removing);
- adds `iat` / `exp` and validates expiry, so stolen tokens don't live forever;
- hashes stored passwords (they were plaintext) and stops echoing the role back to the client.

Verified by re-running the cracker against the new secret — no match.

## Key lesson

A JWT is only as strong as its signing key. "It's signed" means nothing if the key is a dictionary
word. Fix the root (entropy + secret management), and while you're in the code, fix the *secondary*
issues a cracked token exposes (no expiry, plaintext passwords) rather than just the headline bug.
