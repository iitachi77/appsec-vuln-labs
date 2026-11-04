# Methodology — LumosBlog (Laravel Ignition RCE, CVE-2021-3129)

Black-box first (DAST), then source/config review (SAST/SCA).

## 1. Recon & mapping
- Target: `http://localhost:9012` (Dockerised Laravel 8).
- Homepage is a normal marketing page. The footer / posts reference an internal
  `/preview/<slug>` route.
- Hitting `/preview/nope` (an unknown slug) returns **HTTP 500** rendered as a full
  **Ignition** debug page — stack trace, file paths, framework version. Two immediate reads:
  **debug mode is on**, and **Ignition is present**.

## 2. Identify the vulnerability
- The Ignition debug handler registers `POST /_ignition/execute-solution`. Confirmed live:
  a well-formed request returns Ignition's own validation JSON (`"solution field is required"`),
  proving the controller runs (not behind CSRF, not a 404).
- Ignition version in range for **CVE-2021-3129** (`facade/ignition` ≤ 2.5.1).
- Class: **insecure deserialization / PHP object injection**. The `MakeViewVariableOptionalSolution`
  gives a file read→replace→write primitive; chained with log poisoning + `php://filter` convert
  wrappers it deserializes an attacker phar gadget → RCE.

## 3. Exploitation
- Used the public Ambionics PoC (`laravel-exploits` + `phpggc`) which automates:
  clear log → write gadget via `php://filter` convert → trigger phar deserialization.
- **Gadget selection (the key step):** read the installed versions first —
  **Monolog 2.11.1**, **Laravel 8.83.29** (`composer show`). The gadget's version range must
  bracket these; an out-of-range gadget deserializes but never reaches its sink
  ("exploit succeeded" with no effect). Selected an in-range gadget accordingly.
- **Blind RCE:** the command's stdout goes to the PHP worker, not the HTTP response. Confirmed
  execution and retrieved output by writing into the web root (`/app/public/…`) and fetching it
  over HTTP. Command runs as **root** (`uid=0(root)`).
- Captured `/flag.txt`: `FLAG{l4r4v3l_1gn1t10n_d3bug_m0d3_rc3_cv3_2021_3129}`.
- Note: Metasploit's module auto-check false-negatived the target; manual confirmation of the
  live endpoint + version justified overriding it.

## 4. Review (white-box root cause)
Treated the repo as a PR:
- **`.env`** — `APP_DEBUG=true` on an `APP_ENV=production` app. Debug-in-prod both leaks internals
  and activates the vulnerable Ignition surface. Fix: `APP_DEBUG=false`.
- **`composer.json` / `composer.lock`** — `facade/ignition` pinned to the vulnerable 2.5.1
  (fixed in 2.5.2; Laravel 9+ uses `spatie/laravel-ignition`). A pure **SCA** finding — a
  dependency scan catches it pre-deploy.
- **Process** — add a CI gate: `composer audit` + assert `APP_DEBUG=false` for prod builds.

## Transferable lessons
1. A debug flag is an **attack surface**, not just an info leak.
2. Deserialization gadgets are **version-locked** — read `composer.lock`, then pick the gadget.
3. Blind RCE needs an **output channel** (webroot write, HTTP exfil, reverse shell, DNS).
4. **Remove the mechanism** (debug off + patch the dep); don't filter around the route.
