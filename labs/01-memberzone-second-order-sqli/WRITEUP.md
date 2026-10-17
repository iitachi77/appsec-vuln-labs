# MemberZone — Second-Order SQL Injection (account takeover)

| | |
|---|---|
| **Vulnerability** | Second-order (stored) SQL injection |
| **Impact** | Admin account takeover |
| **Difficulty** | ★★★ |
| **Approach** | Black-box + source review |

## The application

MemberZone is a small member portal (PHP + SQLite) with register, login, and change-password. Login
and registration both use parameterized queries, so the obvious injection points are clean — which is
exactly what makes this one interesting.

```bash
docker compose up -d        # http://localhost:8081
```

## Discovery

The injection isn't at the point where the data **enters** the app — it's where the data is later
**used**. The change-password feature builds its query by concatenating the *stored* username:

```php
// register / login: parameterized (safe)
// change password: the stored username is concatenated back into SQL
$sql = "UPDATE users SET password = :p WHERE username = '" . $stored_username . "'";
```

The username is treated as trusted "our own data" on the second use — but it's attacker-controlled
from registration. That's a **second-order** injection: the payload is stored safely, then detonates
when a later query interpolates it.

## Exploitation

Register a username that is itself SQL, then trigger the change-password flow so the stored value is
concatenated into the `UPDATE`:

1. Register user: `admin'-- ` (with a trailing space after `--`).
2. Log in as that user and change the password. The resulting query becomes:

```sql
UPDATE users SET password = :p WHERE username = 'admin'-- '
```

The `-- ` comments out the original `WHERE` binding, so the `UPDATE` now matches the real **admin**
row and overwrites *admin's* password with one I control.

3. Log in as `admin` with the new password.

```
FLAG{s3c0nd_0rd3r_sqli_st0r3d_th3n_str1k3s}
```

## Root-cause fix

Parameterize **every** query that touches user-influenced data — including the "second use," not just
the entry point:

```php
$stmt = $db->prepare("UPDATE users SET password = :p WHERE username = :u");
$stmt->execute([':p' => $hash, ':u' => $stored_username]);
```

Even better, identify the row by an **immutable primary key** (the numeric user id from the session),
never by a mutable string the user chose. Then the username's contents can never alter query
structure, no matter how many hops the data takes.

## Key lesson

"Safe on input" is not "safe forever." Data that was parameterized when it was stored can still be
injected the moment some later code concatenates it into SQL. Treat stored data as untrusted at every
sink, and bind by immutable id.
