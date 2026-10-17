# 📝 EXAM 01 — "Death by a Thousand Lows": Chaining Low/Mid Vulns to RCE

**Type:** Timed exam (code + infra review — no running target)
**Category:** AppSec · vulnerability chaining · dependency + cloud + code
**Difficulty:** ⭐⭐⭐ Advanced
**Par:** ~60–90 min

---

## The scenario
**ReportForge** is an internal report-generation microservice on AWS EC2. The previous AppSec
engineer reviewed it and rated **every finding LOW or informational** — *"No High/Critical issues.
Ship it."* Each dismissal is written inline in the code as `[AppSec: ... Rated LOW.]`, with the
reasoning that made it *feel* safe ("it's internal", "it's just the config bucket", "only a GET",
"we control these bytes").

Files in scope:
- `app.py` — the Flask service (~120 lines)
- `requirements.txt` — pinned dependencies
- `infra/instance.tf` — the EC2 instance role + metadata options

## Your mission
The verdict was wrong. **Those "lows" chain together into a full Remote Code Execution.**

### Part 1 — Enumerate (list every weakness)
List each individual issue and the severity *the previous AppSec gave it*. Note which category each
is: **code**, **dependency**, or **cloud/infra**.

### Part 2 — Build the kill chain (the real exam)
Write the **step-by-step attack path** from an external attacker to **RCE on the instance**.
For each step: which weakness you use, what you send, and what you get. Make it concrete.
> Hint: no single bug here is RCE on its own. Ask at each step: *"what does this unlock that makes
> the **next** 'low' reachable?"* The chain crosses all three categories — dependency, cloud, code.

### Part 3 — Re-rate
Given the chain, what is the **real** severity of the whole, and what does that teach you about
rating findings in isolation? (One paragraph.)

### Part 4 — Secure it
For **each link in the chain**, give the concrete fix (code, dependency, or infra). Then answer:
**what is the *minimum* set of fixes that breaks the chain** (you don't always need to fix all of
them to stop the RCE)?

### Part 5 — EXPLOIT IT FOR REAL 🔓
This exam ships with a **live, fully-working target.** After you've reasoned out the chain, go
prove it: pop it end-to-end and exfiltrate the flag from `/flag.txt` (which only exists inside the
app container — so reading it *is* proof of RCE).

**Start the target:**
```bash
cd "CTF-Labs/exam01-low-to-rce"
docker compose up -d          # ~40s for the 3 containers to install + boot
```
- Public app: **http://localhost:8080**  (endpoints: `/`, `/import?url=`, `/reload`, `/render`, `/templates`)
- Config store API (S3 stand-in, internet-reachable like real S3): **http://localhost:9000**
- The metadata service lives **inside** the network at the authentic `169.254.169.254` — you can
  only reach it *through* the app. (It is not published to your host.)

Reset the config store to a clean state any time:
```bash
docker compose restart configstore
```
Tear everything down:
```bash
docker compose down
```

**Exploitation hints (if stuck):**
1. Make the app fetch something internal. What lives at `169.254.169.254` on a cloud box?
2. What do the stolen credentials let you *write* to — and what does the app later *read and parse*?
3. `yaml.load(..., Loader=yaml.Loader)` on data you control = ? (think `!!python/object/apply`)
4. The command's output needs to come back to you — which endpoint echoes a template's field?

## Deliverable
A short report: Part 1 table → Part 2 chain → Part 3 re-rating → Part 4 fixes → Part 5 proof
(the commands you ran + the flag). **Write it in your own words** (then I'll critique yours).

## Notes
- The config store and metadata service are lightweight stand-ins for real AWS S3 / IMDS, but the
  technique maps 1:1 to the real services.
- Allowed: your brain, `curl`, notes, and web search for CVE details on the dependency versions.
- Attempt it fully before asking for the solution. 🙂

---
*Educational. ReportForge is fictional and deliberately vulnerable.*
