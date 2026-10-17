# 📝 EXAM 03 — "PingBoard": Blind Chain to RCE

**Type:** Live multi-stage exam · **Difficulty:** ⭐⭐⭐⭐⭐ Very Hard · **Mode: no hand-holding**
**You get:** nothing. No credentials, no account, no map. · **Par:** ~2–3 hours

---

## Scenario
`PingBoard` is an uptime-monitoring SaaS. You have **no credentials.** Somewhere there is a
`/flag.txt` you can only read with **remote code execution** — and at the critical step, the
application returns you **nothing**. You'll have to **bring your own channel.**

## Objective
Read `/flag.txt`.

## How to run
```bash
cd "CTF-Labs/exam03-5star"
docker compose up -d        # first run installs ping/curl + flask (~30s)
```
Target: **http://localhost:9003** · Tear down: `docker compose down`

## Rules of engagement (this is a 5-star)
- **Enumerate everything yourself.** No endpoint list, no creds, no payloads.
- Three obstacles stand between you and the flag. Each is a different class. Two of them are on
  your own "weak points" list — that's deliberate.
- When a defense blocks you, ask *how* it's implemented, not just *that* it blocks you.
- When the app gives you **no output**, that's not a dead end — it's a hint about *how* you'll get
  your data out.

## The one piece of infrastructure you need
The money step is **blind** — the result never comes back in the HTTP response. To receive it,
stand up your **own listener** and have the target reach it **out-of-band**:
```bash
# on your host / Kali:
python3 -m http.server 8000
```
> From inside this Docker lab, your host is reachable at **`host.docker.internal`** (Docker
> Desktop). So the target can call back to `http://host.docker.internal:8000/...`. (On a real
> engagement this would be your public collaborator/VPS, or DNS exfil.)

## Deliverable (your own words — even if it's "ez")
1. **Enumeration** — what you found and how.
2. **Obstacle 1** — getting in (the flaw + how you beat it).
3. **Obstacle 2** — the injection (where, and why output is blind).
4. **Obstacle 3** — your **OOB exfiltration** (the exact channel + payload, and *why* it works).
5. **Proof** — the flag + the requests.
6. **Remediation** — the root-cause fix for **each** of the three flaws.

---
## ✅ SOLVED — 2026-10-17 · Score 7.8/10
Ahmad cleared the full chain (black-box, no source): XFF rate-limit bypass → PIN 4921 → blind cmdi in `/api/monitors` → OOB exfil via webhook.site (`$(cat /flag.txt|base64)` in callback path). Flag: `FLAG{bl1nd_cmd1_00b_3xf1l_r4t3l1m1t_byp4ss}`. Obstacles 2&3 solo; obstacle 1 (XFF) taught from scratch. Part-2 fixes: rate-limit→`remote_addr` (correct); cmdi→arg-list `shell=False` (after correcting a "string+shell=False" broken-but-accidentally-safe first attempt). Full debrief: `LESSON.html`. Written report still owed.

---
*Deliberately vulnerable. Educational use only. Only ever test systems you own or are authorized to test.*
