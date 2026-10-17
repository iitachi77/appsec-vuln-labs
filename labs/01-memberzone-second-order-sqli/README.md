# Lab 04 — "MemberZone" (Second-Order SQL Injection)

**Category:** Web / OWASP A03 – Injection (second-order / stored)
**Difficulty:** ⭐⭐⭐ Advanced
**Skills:** Recognising stored-injection, thinking about *where data is used* not just where it enters, account takeover

---

## Scenario
MemberZone is a small membership portal: register, log in, change your password. There is an
`admin` account whose dashboard holds a `FLAG{...}`. **The admin password is randomised — you
cannot guess it, brute-force it, or read it directly.**

## Objective
Take over the `admin` account anyway, and read the flag from its dashboard.

## The twist (why this is "second-order")
Every query that touches *your* input directly uses **parameterised statements** — the login and
registration forms are not injectable in the usual way. Try the obvious first-order payloads and
you'll get nowhere.

The vulnerability is **second-order**: malicious input is *stored safely*, then later used in a
*different* query somewhere it is **not** safe. Your job is to find where your stored data gets
reused — and shape it so that, when it's reused, it rewrites the query to your advantage.

> Mental model shift: in first-order SQLi the injection fires **where the input enters**. In
> second-order SQLi it fires **where the stored data is later used**. Find that second place.

## Rules of engagement
- Target: `http://localhost:8081` — local only.
- Tools: browser, Burp, `curl`. This one rewards *thinking*, not tooling — sqlmap won't hand it to you.

## How to run
```bash
cd "CTF-Labs/lab04-second-order-sqli"
docker compose up --build -d
```
Open http://localhost:8081

Reset to a clean state at any time (new random admin password):
```bash
docker compose down && docker compose up -d
```
Tear down:
```bash
docker compose down
```

## Hints (peek only if stuck)
1. What value do you fully control that the app **stores** and then **reuses** later?
2. The "change password" feature updates *your* account. How does it decide *which* row is yours?
3. If your username were `something'-- `, what would an `UPDATE ... WHERE username = '…'` become?

## Reflection questions (for your writeup)
1. Why do parameterised queries on the login/registration forms NOT prevent this attack?
2. Exactly which stored value became the injection vector, and in which query did it detonate?
3. What is the correct fix — and why is "validate the username on registration" an incomplete answer?

---
*Deliberately vulnerable. Educational use only.*
