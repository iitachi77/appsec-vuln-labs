// Taskly — PATCHED.  Prototype pollution fixed at the ROOT (the sink) + defense-in-depth.
// Based on Ahmad's design: schema allow-list on the preferences endpoint, forbidden-key
// rejection, and an own-property check on the admin gadget.
const express = require("express");
const app = express();
app.use(express.json());

const FLAG = process.env.FLAG || "FLAG{placeholder}";

const user = { name: "alice", role: "user", prefs: { theme: "light", density: "cozy" } };

// --- FIX (sink / root cause): only accept known keys with known values. Arbitrary keys
//     (including __proto__) are never copied, so the prototype can't be touched at all. ---
const PREF_SCHEMA = {
  theme:   ["light", "dark", "sepia"],
  density: ["cozy", "compact"],
};

function validatePrefs(body) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return { error: "Invalid request body." };
  }
  const value = {};
  for (const key of Object.keys(PREF_SCHEMA)) {        // only iterate ALLOWED keys
    if (Object.hasOwn(body, key)) {
      if (!PREF_SCHEMA[key].includes(body[key])) {
        return { error: `Invalid value for '${key}'.` };
      }
      value[key] = body[key];
    }
  }
  return { value };
}

app.get("/api/me", (req, res) => res.json({ name: user.name, role: user.role, prefs: user.prefs }));

app.post("/api/preferences", (req, res) => {
  const { value, error } = validatePrefs(req.body);
  if (error) return res.status(400).json({ ok: false, error });
  Object.assign(user.prefs, value);                    // flat copy of validated, allow-listed keys
  res.json({ ok: true, prefs: user.prefs });
});

// --- FIX (gadget / defense-in-depth): trust only the object's OWN property, never an
//     inherited (possibly polluted) one. ---
app.get("/api/admin/flag", (req, res) => {
  const perms = {};
  if (Object.hasOwn(perms, "isAdmin") && perms.isAdmin === true) {
    return res.json({ ok: true, flag: FLAG });
  }
  return res.status(403).json({ ok: false, error: "Admins only." });
});

app.post("/api/reset", (req, res) => {
  delete Object.prototype.isAdmin;
  user.prefs = { theme: "light", density: "cozy" };
  res.json({ ok: true });
});

app.get("/", (req, res) => res.type("html").send("<h1>Taskly</h1><p>Patched build.</p>"));

app.listen(80, "0.0.0.0", () => console.log("Taskly (patched) on :80"));
