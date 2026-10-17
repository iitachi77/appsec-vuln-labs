# 🗒️ LAB 15 — "Notely": Remember Me

**Type:** Web App Pentest + Secure Code Review · **Difficulty:** ⭐⭐⭐⭐ · **Warm-up before Exam 04**
**Target:** http://localhost:9006 · **Par:** ~25–40 min exploit + ~15 min fix

---

## Scenario
`Notely` is a friendly little notes & to-do app. It prides itself on a "seamless" experience:
your **theme, density, and display name are remembered automatically** between visits — no login
required. Convenience like that has to be *stored* somewhere… and *restored* somehow.

Open the site, land on your dashboard, and look closely at **how** the app remembers you.

## Objective
Read `/flag.txt` on the server.

## How to run
```bash
cd "CTF-Labs/lab15-notely"
docker compose up -d        # installs flask (~15s)
```
Target: **http://localhost:9006** · Tear down: `docker compose down`

## Part 1 — Break it (exploit)
Something client-side is being trusted far too much on the way back in. In your writeup:
1. **Where** is your "remembered" state stored, and **what format** is it in? (Decode it — what do the first bytes tell you?)
2. **Name the vulnerability class** and why restoring that state is dangerous.
3. Your **exact gadget / payload** and how you got the flag's contents to come back to you.
4. **Proof** — the flag + the request that produced it.

> Shape-of-the-hint (not the answer): the app *restores* your preferences. Ask what function
> turns those stored bytes back into a Python object — and what an attacker can do if they
> control those bytes. Blind by default: think about how to make the **output** come back.

## Part 2 — Secure it (blue team) 🛡️
Patch `app.py` so the exploit dies, save it as `app_fixed.py`, and I'll re-run the gadget against
it — it must **fail**, and the app must **still remember legit preferences**. Answer first:

> Is the fix to "validate the object after loading it," or to **stop using the dangerous
> deserializer on untrusted input entirely**? What's the *right* way to persist small bits of
> client state so tampering can't become code execution?

Deliverable: `app_fixed.py` + a short paragraph — root cause, your fix, and *why* it kills the
class (not just this payload). Remember: **keep untrusted input as data, never let it become code.**

---
*Deliberately vulnerable. Educational use only. Fictional brand. Only ever test systems you own or are authorized to test.*
