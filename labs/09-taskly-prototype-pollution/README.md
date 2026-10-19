# 🧪 LAB 16 — "Taskly": Prototype Pollution (NEW concept — learning lab)

**Type:** Web App Pentest + Secure Code Review · **Class:** Prototype Pollution (server-side, Node.js)
**Difficulty:** ⭐⭐⭐ (gentle — your first ever) · **Target:** http://localhost:9007 · **Par:** no clock, learn it

> This is a **teaching lab**, not a pressure test. Read the primer, understand the idea, then apply it.

```bash
cd "CTF-Labs/lab16-proto-pollution"
docker compose up -d        # first run: npm installs express (~15s)
```
Reset anytime: `POST /api/reset` · Tear down: `docker compose down`

---

## 📖 Primer — what is prototype pollution?

You're a Python/PHP person, so here's the JavaScript idea from scratch.

**1. Every JS object has a hidden parent — its *prototype*.**
When you read `obj.x`, JavaScript first looks on `obj` itself; if it's not there, it walks *up* to
`obj`'s prototype, and so on. Almost every object's chain ends at one shared parent:
**`Object.prototype`**. So anything on `Object.prototype` is visible, by default, on *every* object.

**2. The magic key `__proto__`.**
In JS, `obj.__proto__` is a reference to that parent object. So:
```js
({}).__proto__ === Object.prototype    // true — the SHARED parent of all objects
```

**3. The bug.**
If attacker-controlled input is used to *set* keys on an object — especially a **recursive merge**
that copies a JSON body into a server object — then a key named `__proto__` doesn't set a normal
property. It walks into the shared parent and writes there. That one write **changes every object in
the program at once.** That's prototype pollution.

```js
// a vulnerable merge, walking attacker keys including __proto__:
merge(target, { "__proto__": { "isAdmin": true } });
// now, for ANY object created afterwards:
({}).isAdmin   // → true  (it inherited the polluted property!)
```

**4. Why it's dangerous (the "gadget").**
Pollution by itself is just a planted property. It becomes an *exploit* when some later code reads a
property off an object **without checking it's the object's own** — e.g. `if (perms.isAdmin)` on a
fresh `{}`. Your polluted value leaks in. Depending on the gadget, this leads to **privilege
escalation, auth bypass, DoS, or even RCE** (by polluting options later passed to a template engine
or `child_process`).

---

## Part 1 — Break it (exploit)

Taskly signs you in as **alice (user)**. There's an **admin panel** you can't open. Somewhere, a
feature takes your JSON and **merges it into a server-side object**. Your job: pollute the prototype
so that the admin check — which reads a property off a freshly-created object — passes, and the panel
hands you the flag.

In your writeup: what the sink is, the exact payload, *why* it works (in your own words — this is how
you prove you learned it), and the flag.

> Hint (concept, not the answer): find the endpoint that *merges* your input, send a key that isn't a
> normal property name but the one that reaches the shared parent, and set a property the admin check
> looks for.

## Part 2 — Secure it (blue team) 🛡️
Patch `app.js` so the exploit dies, and the preferences feature still works. Save `app_fixed.js` and
I'll verify. Think about the **root cause**, not a filter:

- Should you blacklist the string `__proto__`? Why is that a weak band-aid? (What about
  `constructor.prototype`?)
- What *structural* fixes make the merge unable to touch the prototype at all? (Consider:
  `Object.create(null)` objects with no prototype, `Map` instead of plain objects, rejecting
  dangerous keys, `Object.freeze(Object.prototype)`, or a vetted merge library / schema validation.)
- And the gadget side: why is `Object.hasOwn(obj, key)` / own-property checks part of the defense?

Deliverable: `app_fixed.js` + a short paragraph — root cause and why your fix kills the class.

---
*Deliberately vulnerable. Educational use only. Fictional brand. Only ever test systems you own or are authorized to test.*
