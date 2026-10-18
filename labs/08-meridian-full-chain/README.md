# 📊 EXAM 04 — "Meridian": The Full Chain

**Type:** Live multi-stage exam · **Difficulty:** ⭐⭐⭐⭐⭐ Very Hard (harder than Exam 03) · **Mode: no hand-holding**
**You get:** a realistic B2B SaaS and nothing else. No creds, no map, no source. · **Par:** ~2–3 h

> 🎯 **This one is a range day, not a classroom.** Every obstacle is a vuln class you have
> **already beaten** in this camp — nothing exotic, nothing you haven't seen. The difficulty is
> in the **length of the chain, the depth of enumeration, a WAF + a keyword filter that demand
> *your* known bypasses, and zero hints.** Flex the muscles. Prove they're real.

---

## Scenario
`Meridian` is a B2B invoicing & analytics SaaS. It has a public invoice-status lookup, a login,
workspace settings, and an "internal" report renderer. Somewhere there is a `/flag.txt` you can
only read with **remote code execution** — and getting there takes **four linked steps**, each
feeding the next.

## Objective
Read `/flag.txt`.

## How to run
```bash
cd "CTF-Labs/exam04-5star"
docker compose up -d        # first run installs flask + pyjwt (~15s)
```
Target: **http://localhost:9005** · Tear down: `docker compose down`
*(The signing secret and internal tokens are regenerated on every boot — you must extract them live.)*

## Rules of engagement (5-star)
- **Enumerate everything yourself.** No endpoint list beyond what the GUI reveals. No payloads.
- **Four obstacles, four different classes.** Each unlocks the next — stage *N+1* is unreachable
  until you've cleared stage *N*.
- When a request is **blocked**, ask *how* the block is implemented — then defeat it with a
  technique you already own. (There is a WAF. There is also a keyword filter. Neither is a wall.)
- The money step returns output — but only after you've **earned the key** that unlocks it.

## Part 1 — Break it (exploit)
Chain your way from an anonymous visitor to RCE and read the flag. In your writeup, for **each**
of the four obstacles: name the class, show the exact request/payload, and explain *why* it worked.

## Part 2 — Secure it (blue team) 🛡️
For **every** stage, write the **root-cause** fix (not a filter, not a band-aid) and save a patched
`app_fixed.py`. I'll re-run the full chain against it — each stage must be **dead**, and the app
must **still work** (legit lookup, legit login, legit render). Remember your own rule:
> *keep untrusted input as **data**, never **code** — remove the dangerous mechanism, don't filter around it.*
> *and a fix that breaks the feature gets reverted.*

## Deliverable (your own words — even if it's "ez")
1. **Enumeration** — the surface you found.
2. **Obstacle 1 → 4** — class, payload, and the *why* for each.
3. **Proof** — the flag + the key requests.
4. **Remediation** — the root-cause fix for all four, as `app_fixed.py` + a short paragraph each.

---
*Deliberately vulnerable. Educational use only. Fictional brand. Only ever test systems you own or are authorized to test.*
