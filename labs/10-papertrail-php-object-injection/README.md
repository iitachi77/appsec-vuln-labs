# 🐘 LAB 18 — "PaperTrail": PHP Object Injection → RCE

**Type:** Web App Pentest + Secure Code Review · **Class:** PHP Object Injection (`unserialize`)
**Difficulty:** ⭐⭐⭐½ · **Target:** http://localhost:9008 · **Relevance:** same vuln *family* as the
PHP2Shell session-unserializer CVE (CVE-2026-109619).

> ✅ **Verified working** — object injection → `__destruct` file-write → webshell → RCE, confirmed end-to-end.

> Staying current: when a PHP unserialize CVE like **PHP2Shell** drops, this is the mechanism
> underneath it — understand this and you understand why that class of bug is so dangerous.

## How to run
**Docker:**
```bash
cd "CTF-Labs/lab18-php-object-injection"
docker compose up -d        # http://localhost:9008
```
**No Docker (native PHP — more reliable):**
```bash
echo 'FLAG{php_0bj3ct_1nj3ct10n_un5er14l1z3_t0_rc3}' | sudo tee /flag.txt
php -S 0.0.0.0:9008 -t .    # from the lab folder
```

## Scenario
`PaperTrail` is an internal reporting dashboard. It "remembers" your display preferences without a
login by storing them in a cookie and **restoring them on every request**. Look closely at *how* that
cookie is restored.

## Part 1 — Break it (exploit)
Decode the `prefs` cookie — what format is it? Then find the sink that turns it back into data, and
the class in the code whose lifecycle methods you can abuse. Chain it to **remote code execution** and
read `/flag.txt`.

In your writeup: the sink, the gadget class and *which magic method* you abused, the exact payload,
and the flag.

> Hint (concept): PHP's `unserialize()` doesn't just parse data — it **instantiates objects**. An
> object you smuggle in runs its `__wakeup()`/`__destruct()` even if the app never "uses" it. Find a
> class whose destructor does something dangerous with its own properties.

## Part 2 — Secure it (blue team) 🛡️
Patch so the exploit dies and preferences still work. Save `app_fixed.php`. Think root cause:
- Should you *filter* the serialized string? Why is that a losing game?
- What's the right way to persist simple key/value state so an attacker can never instantiate an
  object? (Consider: `json_decode` instead of `unserialize`; `unserialize($s, ['allowed_classes' => false])`;
  and signing the cookie with an HMAC so it can't be tampered at all.)

## Part 3 — Stay current (the PHP2Shell tie-in) 🔄
This container runs **PHP 8.2.10** on purpose. PHP2Shell (CVE-2026-109618 / 109619) was fixed in
**8.2.35** (and 8.3.36 / 8.4.27 / 8.5.12, with backports for 8.1 / 8.0 / 7.4).
- Is this server vulnerable to PHP2Shell? How would you confirm the version (`php -v`)?
- What's the fix, and why do `.ini`/WAF tweaks *not* count as remediation?
- Write the one-paragraph "CVE response" you'd send your team when PHP2Shell drops.

---
*Deliberately vulnerable. Educational use only. Fictional brand.*
