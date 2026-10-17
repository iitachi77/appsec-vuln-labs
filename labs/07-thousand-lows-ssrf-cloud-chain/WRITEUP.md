# Thousand Lows — Chaining "Low" Findings into RCE (SSRF → cloud IMDS → YAML deserialization)

| | |
|---|---|
| **Vulnerabilities** | Info disclosure · SSRF → cloud metadata credential theft · IMDSv1 · over-privileged IAM · unsafe YAML deserialization (plus a secondary SSTI) |
| **Impact** | Remote code execution |
| **Difficulty** | ★★★★ |
| **Approach** | White-box code + infra review, then full exploitation |

## The scenario

A report-generation service where a previous reviewer rated **every** finding as "Low." The point of
the lab: individually-low issues chain into a Critical. Three containers model the app, an S3-style
config store, and a cloud metadata service.

```bash
docker compose up -d        # app on http://localhost:8080
```

## The chain

**1. Information disclosure (Low).** A verbose error handler plus `debug=True` leaks the config
bucket name, region, and stack — telling me exactly what to target.

**2. SSRF → cloud IMDS (Low→High).** The `/import?url=` feature fetches any URL the user supplies,
with no allow-list. Because the instance runs IMDSv1 (`http_tokens=optional`), I point it at the
metadata endpoint and steal the instance role's temporary IAM credentials:

```
GET /import?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
→ AccessKeyId / SecretAccessKey / Token
```

**3. Over-privileged IAM + unsafe deserialization (→ RCE).** The stolen role has `s3:PutObject` on
the config bucket (least privilege violated). I upload a malicious YAML config, then hit the
no-auth `/reload`, which calls `yaml.load()` with an unsafe loader:

```yaml
title: !!python/object/apply:subprocess.check_output [["cat", "/flag.txt"]]
```

`/reload` deserializes it and `/render` echoes the `title` back — carrying the command output:

```
FLAG{l0w_vulns_ch41n3d_1nt0_full_rc3}
```

(There's a secondary path too: `/render` concatenates an attacker-controlled `title` into
`render_template_string`, an SSTI that also reaches RCE.)

## Root-cause fixes

The elegant part of this lab: **breaking any single link kills the whole chain** — an SSRF allow-list,
*or* enforcing IMDSv2, *or* removing `s3:PutObject` each stop it. But defense in depth fixes all:

- **SSRF:** allow-list the destinations; resolve and reject internal/link-local IPs; disallow
  redirects.
- **Cloud:** require **IMDSv2** (`http_tokens=required`) and drop the hop limit.
- **IAM:** least privilege — the app role should not have `s3:PutObject` on its own config.
- **Deserialization:** `yaml.safe_load()`. Note: *upgrading* PyYAML is **not** a fix —
  `yaml.load(Loader=yaml.Loader)` still executes on current versions. Upgrading a dependency ≠ fixing
  insecure *usage* of it.
- **Hardening:** authenticate `/reload`, remove `debug`/verbose errors, fix the SSTI (render data as
  context, not template source).

## Key lesson

Severity isn't additive — it's multiplicative when findings chain. Five "Lows" became an RCE. And the
recurring trap worth naming: **upgrading a vulnerable library does not fix insecure use of it** — you
must change the call (`load` → `safe_load`), not just the version number.
