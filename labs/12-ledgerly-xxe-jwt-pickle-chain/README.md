# 💰 EXAM 05 — "Ledgerly": XXE → JWT Forge → Pickle RCE

**Type:** Live multi-stage exam · **Difficulty:** ⭐⭐⭐⭐⭐ Very Hard · **Mode: no hand-holding**
**You get:** a demo `viewer:viewer` account and nothing else. · **Par:** ~2–3 h

## Scenario
`Ledgerly` is an accounting & invoicing API. There's a `/flag.txt` you can only read with **remote
code execution**. Three linked stages stand between you and it — each unlocks the next.

## How to run
**Native (reliable — your Ubuntu box):**
```bash
cd exam05-ledgerly
pip install flask lxml pyjwt
echo 'FLAG{xx3_t0_jwt_f0rg3_t0_p1ckl3_rc3_ch41n}' | sudo tee /flag.txt
sudo python3 app.py        # :80
```
**Docker:** `docker compose up -d` → http://localhost:9010

## Objective
Read `/flag.txt`.

## Rules of engagement (5-star)
- **Enumerate everything yourself** — no endpoint list, no payloads, no hints.
- Three stages, three different classes. Stage *N+1* is unreachable until you clear stage *N*.
- The `viewer` account is a near-useless starting point — the real access must be **forged**, and the
  key to forge it is **not guessable**; you have to *read it off the server* first.
- When you find a sink that turns your data back into a live object, that's your way to code execution.

## Part 1 — Break it (exploit)
Chain your way to RCE. In your writeup, for **each** stage: name the class, show the exact
request/payload, and explain *why* it worked. Then the flag + the key requests.

## Part 2 — Secure it (blue team) 🛡️
Root-cause fix for **all three**, saved as `app_fixed.py` (I'll re-run the chain — each stage must be
dead, and the app must still work):
- The XML import (what structural setting kills external entities?).
- The signing key handling (where should a secret live; why is reading-it-off-disk the whole break?).
- The restore endpoint (why is `pickle` on untrusted input never safe, and what replaces it?).

---
*Deliberately vulnerable. Educational use only. Only ever test systems you own or are authorized to test.*
