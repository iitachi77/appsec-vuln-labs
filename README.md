# AppSec Vuln Labs

> Realistic, intentionally vulnerable web applications — **built, exploited, and fixed at the root cause.**

This repository is a hands-on portfolio of application-security work. Each lab is a small but
*realistic* app (not a toy "CTF-looking" page) that contains a real-world vulnerability class. For
every one I include three things:

1. **The app** — runnable with a single `docker compose up`.
2. **The exploit** — how the vulnerability is found and weaponized, in my own words.
3. **The root-cause fix** — a patched version, plus *why* the fix eliminates the whole class
   instead of filtering around one payload.

Several labs also include my raw **`Methodology.md`** — the unedited notes I took *while* solving,
dead ends and all. The polished `WRITEUP.md` shows the result; the methodology shows the thinking.

The goal is to show the full AppSec loop — **offense, defense, and secure coding** — the way the job
actually works, not just one side of it.

---

## About me

**Ahmad Al Refae** — Web Application Penetration Tester & aspiring Application Security Engineer.
eWPTv2 & eJPTv2 (INE Security), B.Sc. Digital Forensic Engineering. I find and validate
Critical/High-severity vulnerabilities in live production environments, and I care as much about the
*fix* as the *find*.

- GitHub: [@iitachi77](https://github.com/iitachi77)
- Focus: web & API security, secure code review, threat validation, root-cause remediation.
- **CTF:** placed **7th of ~100 competitors** and **2nd in the web-exploitation category** at a
  Fırat University CTF — top individual scorer on my team.

---

## The labs

| # | Lab | Vulnerability class | Difficulty | Writeup |
|---|-----|---------------------|:----------:|:-------:|
| 1 | [MemberZone](labs/01-memberzone-second-order-sqli/) | Second-order SQL injection | ★★★ | [writeup](labs/01-memberzone-second-order-sqli/WRITEUP.md) |
| 2 | [VaultAPI](labs/02-vaultapi-jwt-forge/) | JWT forgery (weak HMAC secret) | ★★★ | [writeup](labs/02-vaultapi-jwt-forge/WRITEUP.md) |
| 3 | [NimbusHR](labs/03-nimbushr-jwt-idor-ssti-chain/) | JWT → IDOR → filtered SSTI (chain) | ★★★★ | [writeup](labs/03-nimbushr-jwt-idor-ssti-chain/WRITEUP.md) |
| 4 | [PingBoard](labs/04-pingboard-ratelimit-cmdi-oob/) | Rate-limit bypass → blind command injection → OOB exfil | ★★★★★ | [writeup](labs/04-pingboard-ratelimit-cmdi-oob/WRITEUP.md) |
| 5 | [LOOM & CO](labs/05-loomco-race-condition/) | Race condition (TOCTOU) | ★★★★ | [writeup](labs/05-loomco-race-condition/WRITEUP.md) |
| 6 | [Notely](labs/06-notely-insecure-deserialization/) | Insecure deserialization (pickle) | ★★★★ | [writeup](labs/06-notely-insecure-deserialization/WRITEUP.md) |
| 7 | [Thousand Lows](labs/07-thousand-lows-ssrf-cloud-chain/) | SSRF → cloud IMDS → YAML deserialization (chain) | ★★★★ | [writeup](labs/07-thousand-lows-ssrf-cloud-chain/WRITEUP.md) |
| 8 | [Meridian](labs/08-meridian-full-chain/) | Blind SQLi → JWT forge → IDOR → filtered SSTI (chain) | ★★★★★ | [writeup](labs/08-meridian-full-chain/WRITEUP.md) |

## Skills demonstrated

- **Exploitation:** SQL injection (UNION, second-order, blind/boolean behind a WAF), JWT attacks
  (weak-secret crack & forge), IDOR / BOLA, server-side template injection (incl. filtered-bypass),
  OS command injection (blind + out-of-band exfil), race conditions, insecure deserialization,
  SSRF → cloud metadata credential theft.
- **Defense / secure coding:** parameterized queries, strong secret management, object-level
  authorization, sandboxed templating, atomic concurrency control, safe deserialization
  (signed JSON), IMDSv2, least privilege, egress controls.
- **Methodology:** black-box enumeration, white-box code review, chaining low-severity findings,
  and writing root-cause remediation — *remove the dangerous mechanism, don't filter around it.*

## Running a lab

Each lab is self-contained:

```bash
cd labs/06-notely-insecure-deserialization
docker compose up -d
# target: http://localhost:<port>   (see the lab's README)
docker compose down
```

## Disclaimer

Every application here is **intentionally vulnerable** and exists for education only. All brands are
fictional. See [DISCLAIMER.md](DISCLAIMER.md). Only ever test systems you own or are explicitly
authorized to test.

## License

[MIT](LICENSE) — use the material to learn.
