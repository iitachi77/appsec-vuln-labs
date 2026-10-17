"""
Notely — a small, real-feeling notes & to-do app.
Educational lab only (4 stars).

Architecture
------------
    app.py              this file  (routes + a tiny data layer + prefs handling)
    templates/          Jinja pages (base + landing/dashboard/notebook/note/settings)
    static/style.css    shared styling

The app remembers each visitor's preferences (display name, theme, density) in a
cookie so there's no login. Those prefs are serialized with pickle and base64'd into
the `np_session` cookie, and restored on every request.

SECURITY NOTE (the lab):
    Restoring the cookie calls pickle.loads() on fully client-controlled bytes.
    pickle can reconstruct arbitrary objects and invoke callables during loading,
    so an attacker who crafts the cookie gets remote code execution. See prefs.py
    section below ("load_prefs"). The fix is in Part 2 (don't deserialize untrusted
    input with pickle — use a signed/opaque token or plain JSON of a fixed shape).
"""
import base64
import pickle
import time
from flask import (Flask, g, request, redirect, url_for,
                   render_template, make_response, abort)

app = Flask(__name__)

# --------------------------------------------------------------------------
# Tiny in-memory data layer (a stand-in for a database)
# --------------------------------------------------------------------------
NOTEBOOKS = {
    "quick":    {"name": "Quick notes", "icon": "📌"},
    "work":     {"name": "Work",        "icon": "💼"},
    "personal": {"name": "Personal",    "icon": "🏠"},
}

# notebook_id -> list of note dicts
NOTES = {
    "quick": [
        {"id": 1, "title": "Call the bank", "body": "Ask about the new business account tiers.", "ts": "09:12"},
    ],
    "work": [
        {"id": 2, "title": "Standup talking points",
         "body": "Ship invoice export, review PR #214, follow up with design on the dashboard.", "ts": "Mon"},
        {"id": 3, "title": "Q4 roadmap draft",
         "body": "Billing revamp, SSO, audit logs. Lock scope by Friday.", "ts": "Tue"},
    ],
    "personal": [
        {"id": 4, "title": "Grocery run", "body": "Coffee, olive oil, bread, eggs, the good cheese.", "ts": "Sat"},
        {"id": 5, "title": "Reading list", "body": "Finish the threat-modeling book. Start the Kubernetes one.", "ts": "Sun"},
    ],
}
_next_id = 6


def all_notes():
    return [n for notes in NOTES.values() for n in notes]


def find_note(note_id):
    for notes in NOTES.values():
        for n in notes:
            if n["id"] == note_id:
                return n
    return None


def add_note(notebook, title, body):
    global _next_id
    note = {"id": _next_id, "title": title.strip() or "Untitled",
            "body": body.strip(), "ts": time.strftime("%H:%M")}
    NOTES.setdefault(notebook, []).insert(0, note)
    _next_id += 1
    return note


# --------------------------------------------------------------------------
# Preferences  (stored client-side in the `np_session` cookie)
# --------------------------------------------------------------------------
COOKIE = "np_session"
DEFAULT_PREFS = {"theme": "light", "display_name": "Guest", "density": "cozy"}


def encode_prefs(prefs: dict) -> str:
    return base64.b64encode(pickle.dumps(prefs)).decode()


def load_prefs():
    """Restore the visitor's prefs from their cookie.

    VULNERABLE: the cookie is attacker-controlled, and pickle.loads() on untrusted
    bytes allows arbitrary object construction / code execution during unpickling.
    """
    raw = request.cookies.get(COOKIE)
    if not raw:
        return DEFAULT_PREFS
    try:
        return pickle.loads(base64.b64decode(raw))     # <-- insecure deserialization sink
    except Exception:
        return DEFAULT_PREFS


@app.before_request
def restore_session():
    prefs = load_prefs()
    # Normalise for the templates. If prefs isn't the expected dict (e.g. an attacker
    # made it something else), we still surface it so the page renders.
    if isinstance(prefs, dict):
        g.display_name = str(prefs.get("display_name", "Guest"))
        g.theme = str(prefs.get("theme", "light"))
        g.density = str(prefs.get("density", "cozy"))
    else:
        g.display_name = repr(prefs)
        g.theme = "light"
        g.density = "custom"


def with_default_cookie(resp):
    if COOKIE not in request.cookies:
        resp.set_cookie(COOKIE, encode_prefs(DEFAULT_PREFS), path="/")
    return resp


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def landing():
    return with_default_cookie(make_response(render_template("landing.html")))


@app.route("/dashboard")
def dashboard():
    recent = sorted(all_notes(), key=lambda n: n["id"], reverse=True)[:4]
    return render_template("dashboard.html", notebooks=NOTEBOOKS, notes=NOTES, recent=recent)


@app.route("/notebook/<nb>")
def notebook(nb):
    if nb not in NOTEBOOKS:
        abort(404)
    return render_template("notebook.html", notebooks=NOTEBOOKS,
                           nb=nb, meta=NOTEBOOKS[nb], notes=NOTES.get(nb, []))


@app.route("/notebook/<nb>/add", methods=["POST"])
def add(nb):
    if nb not in NOTEBOOKS:
        abort(404)
    add_note(nb, request.form.get("title", ""), request.form.get("body", ""))
    return redirect(url_for("notebook", nb=nb))


@app.route("/note/<int:note_id>")
def note(note_id):
    n = find_note(note_id)
    if not n:
        abort(404)
    return render_template("note.html", notebooks=NOTEBOOKS, note=n)


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        prefs = {
            "theme": request.form.get("theme", "light"),
            "display_name": request.form.get("display_name", "Guest"),
            "density": request.form.get("density", "cozy"),
        }
        resp = make_response(redirect(url_for("settings")))
        resp.set_cookie(COOKIE, encode_prefs(prefs), path="/")   # save prefs back to the cookie
        return resp
    return render_template("settings.html", notebooks=NOTEBOOKS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, threaded=True)
