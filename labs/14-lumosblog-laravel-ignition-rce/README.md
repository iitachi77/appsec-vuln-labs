# LumosBlog — Laravel Ignition Debug-Mode RCE (CVE-2021-3129)

> A Laravel 8 site shipped to "staging" with **debug mode on** and a **known-vulnerable
> dependency** — driven to unauthenticated remote code execution as root.

**Difficulty:** ★★★★ · **Class:** insecure deserialization / PHP object injection (Ignition `execute-solution`) · **CVE:** 2021-3129

## The chain in one line
`APP_DEBUG=true` → Ignition error page + `/_ignition/execute-solution` → `MakeViewVariableOptionalSolution`
file-write primitive → log poisoning + `php://filter` → phar gadget deserialization → **RCE (root)**.

## Run it
```bash
docker compose up -d --build        # first build pulls Laravel + deps (a few minutes)
# target: http://localhost:9012
docker compose down
```
Sanity: `/` is the site; `/preview/nope` → a verbose Ignition debug page (debug mode is on).
The flag is in `/flag.txt`, reachable only via RCE.

## Contents
| File | What |
|------|------|
| `Dockerfile`, `docker-compose.yml`, `overlay/` | the runnable vulnerable app (Laravel 8 + `facade/ignition` 2.5.1, `APP_DEBUG=true`) |
| [`WRITEUP.md`](WRITEUP.md) | the full exploit path + root-cause remediation |
| [`Methodology.md`](Methodology.md) | recon → exploit → review notes |
| [`remediation/`](remediation/) | the fixed config (`fixed.env`) + a CI security gate (`security-ci.yml`) |

## Root causes (two, both required)
1. **Debug mode in production** — `APP_DEBUG=true` leaks internals *and* activates the vulnerable
   Ignition surface. The app is even labelled `APP_ENV=production` while debug is on.
2. **Vulnerable dependency** — `facade/ignition` 2.5.1 (fixed in 2.5.2; Laravel 9+ uses
   `spatie/laravel-ignition`). A textbook **SCA** finding.

## Key takeaways
- A **debug flag is an attack surface**, not just an info leak — debug-in-prod is a top real-world
  Laravel finding.
- **Deserialization gadgets are version-locked**: read `composer.lock`, then pick a gadget whose
  range brackets the installed library (Monolog 2.11 / Laravel 8.83 here). Wrong version → it
  deserializes but does nothing.
- **Remove the mechanism, don't filter it:** turn debug off and patch the dependency.

> Intentionally vulnerable, for education only. Brands fictional.
