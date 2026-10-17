# 📝 EXAM 02 — "NimbusHR": Full-Chain to RCE

**Type:** Live multi-stage exam · **Difficulty:** ⭐⭐⭐⭐ Hard · **Mode: hint-light, figure it out**
**Chain:** Broken Authentication → Broken Access Control → Injection (RCE)
**Par:** ~90–120 min

---

## Scenario
`NimbusHR` is an internal employee portal API. You have a normal employee's login. Somewhere in
here is an `/flag.txt` you can only read with **remote code execution**. No single bug gets you
there — you'll chain **three** distinct flaws, each unlocking the next.

## What you have
- A normal employee account: **`alice : Password123`**
- API base: **http://localhost:9002**
- Endpoints (enumerate them): `POST /api/login`, `GET /api/me`, `GET /api/users/<id>`,
  `GET /admin/reports`, `GET /admin/reports/render`

## Objective
Read `/flag.txt` via RCE.

## How to run
```bash
cd "CTF-Labs/exam02-chain"
docker compose up -d        # ~10s
```
Tear down: `docker compose down`

## The chain (high level — the *how* is yours to find)
1. **Get in, then get up.** You're an employee. The admin area wants a different role. How are
   sessions issued, and how strong is what protects them? (You have the tools for this on Kali.)
2. **Know what to become.** Forging a role means knowing the *exact* privileged role string. The API
   is a little too willing to tell you about other accounts.
3. **Pop the admin feature.** The admin report engine renders templates — but there's a WAF that
   blocks the obvious. The obvious payload won't pass. The WAF only inspects *one* parameter.

> This is a 4-star: **no step-by-step.** Enumerate, chain, and when a payload is blocked, ask *what
> exactly is being filtered, and what isn't.*

## Deliverable (write it yourself — your own words)
A report with:
1. **Enumeration** — the endpoints and what each exposes.
2. **Stage 1** — the auth flaw + how you escalated (commands/payload).
3. **Stage 2** — the access-control flaw + what it leaked that you needed.
4. **Stage 3** — the injection, the WAF, and your bypass (explain *why* it works).
5. **Proof** — the flag + the exact requests.
6. **Remediation** — the root-cause fix for **each** link (and why a WAF/filter wasn't the fix).

## Remediation to address in Part 6
- **Stage 1:** what makes the token forgeable, and the real fix (think secret strength + where it lives).
- **Stage 2:** the missing check on `/api/users/<id>`.
- **Stage 3:** why rendering user input is the bug (not the WAF), and the correct fix.

---
*Deliberately vulnerable. Educational use only. Only test systems you own or are authorized to test.*
