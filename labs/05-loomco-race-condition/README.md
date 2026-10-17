# 🧥 LAB 14 — "LOOM & CO": The Welcome Gift

**Type:** Web App Pentest + Secure Code Review · **Class:** Race Condition (TOCTOU) · **Difficulty:** ⭐⭐⭐½
**Target:** http://localhost:9004 · **Par:** ~25–40 min exploit + ~20 min fix

---

## Scenario
`LOOM & CO` is a small fashion label's online store. Browse it — it looks like any
real storefront: catalog, cart drawer, store credit, a "Welcome" gift-card promo.

Marketing ran a launch offer: a **$100 welcome gift card (`WELCOME100`)**, redeemable
**once per customer**. There is also one piece the brand is very protective of — the
**Aurelia Wool Coat, Limited Edition, $999** — and your wallet starts at **$120.00**.

You want that coat. The gift card gives you $100. The math doesn't work.

...unless the "redeem once" rule isn't as *once* as they think.

## Objective
Walk out with the **Limited Edition Aurelia Wool Coat**. Its receipt carries a
gift note — that note is your **flag** (`FLAG{...}`).

## How to run
```bash
cd "CTF-Labs/lab14-ecommerce"
docker compose up -d        # first run pip-installs Flask (~20s)
```
Open **http://localhost:9004** · Reset state anytime: `POST /api/reset` · Tear down: `docker compose down`

## Endpoints (black-box map — the rest is yours to probe)
| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/api/catalog`          | products + current credit |
| GET  | `/api/credit`           | current credit + gift-card status |
| POST | `/api/redeem-giftcard`  | `{"code":"WELCOME100"}` → +$100, "once" |
| POST | `/api/checkout`         | `{"product_id":N}` → buy with store credit |
| POST | `/api/reset`            | reset the wallet to $120 / unused card |

---

## Part 1 — Break it (exploit)
The promo is meant to add $100 **exactly once**. Your job is to make it add **a lot
more than once**, stack enough store credit to afford the $999 coat, then check out.

Questions to answer in your writeup (your own words — even if it's "ez"):
1. **Name the bug class** and the exact lines/logic that make it exploitable.
2. **Why does timing matter?** What's the window, and what's the server doing during it?
3. Your **exact PoC** — how you fired it, how much concurrency you needed, the credit you reached.
4. **Proof** — the flag + the checkout request that produced it.

> Hint (only the shape, not the answer): the server checks "has this card been used?"
> and marks it used — but *not at the same instant*. Think about what "threaded" means.

## Part 2 — Secure it (blue team) 🛡️
This is the half that matters most for AppSec. **Patch `app.py` so the exploit dies** —
save your fixed version as `app_fixed.py` in this folder and I'll verify it:

- I'll re-run the **same** race PoC against your fix. It must **never** credit more than $100.
- Then I'll run a quick **correctness check** (a single legitimate redemption must still work).

Before you write the patch, answer this one — it's the whole point of the lab:

> **Is `time.sleep(0.25)` the bug?** If you "fix" it by deleting the sleep, is the code
> actually safe — or did you just make the race *harder to hit* while leaving it there?
> What is the **root cause**, and what's the *structural* fix (not a timing tweak)?

Deliverable for Part 2: `app_fixed.py` + one short paragraph naming the root cause and
*why* your fix eliminates the class (not just this instance).

---
*Deliberately vulnerable. Educational use only. Fictional brand. Only ever test systems you own or are authorized to test.*
