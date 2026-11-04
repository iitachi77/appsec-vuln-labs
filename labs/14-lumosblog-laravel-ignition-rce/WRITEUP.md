# LumosBlog — Laravel Ignition Debug-Mode RCE (CVE-2021-3129)

| | |
|---|---|
| **Vulnerability** | Unauthenticated RCE via Laravel Ignition (debug mode) — PHP object injection / insecure deserialization |
| **CVE** | CVE-2021-3129 (`facade/ignition` ≤ 2.5.1) |
| **Root causes** | `APP_DEBUG=true` in a "production" deploy **+** a known-vulnerable dependency |
| **Impact** | Remote code execution as **root** in the container; full compromise |
| **Approach** | Black-box recon → public PoC exploitation → white-box config/dependency review |

## The application

LumosBlog is a small Laravel 8 site shipped to "staging" with two mistakes that are deadly
together: **debug mode left on** and a **pinned, out-of-date dependency**. The flag lives in
`/flag.txt` and is only reachable with code execution.

## Recon

- `GET /` — a normal marketing page.
- `GET /preview/{slug}` for an unknown slug throws an unhandled exception. With `APP_DEBUG=true`,
  Laravel serves the **Ignition** debug error page — a full stack trace that discloses the
  framework, file paths, environment, and the presence of Ignition itself.
- The debug handler also registers `POST /_ignition/execute-solution`, the endpoint the CVE abuses.

Two findings from recon alone: **debug mode is on in a prod-labelled app**, and **Ignition is
reachable**.

## The vulnerability

`facade/ignition` ≤ 2.5.1 exposes a "run solution" endpoint. The `MakeViewVariableOptionalSolution`
gives an attacker a **file read → regex-replace → file write** primitive against an arbitrary path.
Chained with **log poisoning** and PHP's `php://filter` convert wrappers, that primitive turns the
Laravel log file into executable PHP and triggers deserialization of an attacker-supplied **phar
gadget** — i.e. **PHP object injection / insecure deserialization → RCE.** (Reference: Ambionics,
"Laravel ≤ 8.4.2 debug mode RCE".)

## Exploitation (path)

The public PoC (Ambionics `laravel-exploits` + `phpggc`) automates the log-clear → `php://filter`
convert → phar-deserialize sequence. The attacker supplies a **gadget chain** to execute a command.

Three things that matter in practice — each a transferable lesson:

1. **The gadget must match the installed library version.** The target runs **Monolog 2.11.1** and
   **Laravel 8.83.29** (read from `composer.lock` / `composer show`). A gadget outside that range
   deserializes but silently no-ops ("exploit succeeded, nothing happened"). Pick a gadget whose
   version range brackets the installed library.
2. **The RCE is blind.** The executed command's stdout goes to the PHP worker, not the HTTP
   response. You need an output channel — e.g. write the result into the web root
   (`/app/public/…`) and fetch it over HTTP.
3. **Tool auto-checks lie.** Metasploit's module `check()` reported "not vulnerable" on a target
   that provably was; confirm manually (the live `execute-solution` endpoint + Ignition version),
   then override.

Result: command execution as **root** (confirmed `uid=0(root)`), and `/flag.txt` recovered:

```
FLAG{l4r4v3l_1gn1t10n_d3bug_m0d3_rc3_cv3_2021_3129}
```

## Root-cause remediation

This isn't fixed with a payload filter — there are two independent root causes, and both must go:

1. **Debug mode in production.** `APP_DEBUG=true` is the real sin: it both leaks internals *and*
   activates the vulnerable Ignition surface. Set **`APP_DEBUG=false`** in production. See
   `remediation/fixed.env`. (And note the tell: the app was labelled `APP_ENV=production` while
   running with debug on — a config contradiction a review should catch immediately.)
2. **Vulnerable dependency.** `facade/ignition` 2.5.1 is pinned; the fix landed in **2.5.2**. Upgrade
   it, and on Laravel 9+ migrate to the maintained **`spatie/laravel-ignition`**. This is a classic
   **SCA** finding — a dependency scanner (`composer audit`, Trivy, OWASP Dependency-Check) flags it
   before deploy. (Tellingly, modern Composer refuses to even *install* EOL Laravel 8 by default now
   because of its advisories — that block is exactly what should have stopped this shipping.)
3. **Process fix.** Make it un-shippable: a CI gate that runs `composer audit` and asserts
   `APP_DEBUG=false` for production builds. See `remediation/security-ci.yml`.

## Lessons

- **A debug flag is an attack surface, not just an info leak.** Debug-in-prod is one of the most
  common *and* most impactful real-world Laravel findings.
- **Deserialization exploits are version-locked** — read the target's `composer.lock`, then choose
  the gadget. "It ran but nothing happened" ≈ wrong gadget for the version.
- **Remove the mechanism, don't filter it:** turn debug off and patch the dependency — don't try to
  block the `_ignition` route and call it fixed.
