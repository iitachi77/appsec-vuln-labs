# <Lab name> — <Vulnerability class>

<!--
  Writing guide (delete this comment before committing):
  - Write in YOUR OWN voice. Short, direct, technical. No fluff.
  - Show real payloads/code in fenced blocks. An interviewer skims these first.
  - The FIX section is what sets you apart — always root-cause, never "filter it".
  - Delete this template file once each lab has its own WRITEUP.md.
-->

| | |
|---|---|
| **Vulnerability** | <class, e.g. Second-order SQL injection> |
| **Impact** | <e.g. account takeover / RCE / credential theft> |
| **Difficulty** | ★★★ |
| **Approach** | <Black-box / White-box code review> |

## The application
<One short paragraph: what the app is, and the one feature that becomes the attack surface.>

```bash
docker compose up -d        # http://localhost:<port>
```

## Discovery
<How you found it. What you saw that tipped you off. Include the key request/response or code line.>

## Exploitation
<The exact steps and payloads that worked, with code blocks. End with the proof (the flag / the takeover).>

## Root-cause fix
<The patched code, and WHY it kills the whole class instead of one payload.
 State the principle: remove the dangerous mechanism / keep input as data, not code.>

## Key lesson
<One or two sentences: the transferable takeaway.>
