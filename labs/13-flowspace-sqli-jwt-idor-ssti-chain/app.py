"""
FLOWSPACE — a team workspace / project-tracker SaaS.  Educational EXAM lab (5 stars).

This is a deliberately realistic, multi-page app.  Somewhere inside the normal-looking
surface area there is a FULL exploitation chain.  Nothing is labelled.  The flag lives in
the server process environment (`$FLAG`) and the ONLY thing that can read it is code
execution on the box.  Several independent weaknesses stand between you and that — and
every one of them is load-bearing: skip a link and the next gate rejects you.

No payloads, no endpoint list, no hints.  Enumerate it like a real engagement.

Stack: Flask + SQLite + Jinja2 (server-rendered pages) + PyJWT (HS256 sessions).
Run:   pip install flask pyjwt   &&   FLAG='FLAG{...}' python3 app.py      # :9011
"""

import os
import json
import hmac
import time
import hashlib
import sqlite3
import secrets
import datetime

import jwt
from flask import (
    Flask, request, redirect, url_for, make_response,
    render_template, render_template_string, jsonify, abort, g,
)

# --------------------------------------------------------------------------------------
#  Boot-time configuration & secrets
# --------------------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "flowspace.db")
INTEGRATIONS_PATH = os.path.join(BASE_DIR, "integrations.json")

# The flag only ever exists in the process environment.  Reading it requires RCE.
FLAG = os.environ.get("FLAG", "FLAG{ch4in_1d0r_sql1_jwt_hm4c_ss7i_rce}")

# The JWT signing secret is generated fresh at boot and stored in the DB `settings`
# table.  An attacker must LEAK it (it is strong and un-guessable), not brute-force it.
JWT_SECRET = "fsk_" + secrets.token_hex(24)

# A separate HMAC signing secret used by the billing-webhook integration.  It lives in a
# FILE, never in the database, and the admin UI only ever shows it masked.
WEBHOOK_SECRET = "whk_" + secrets.token_hex(24)

APP_NAME = "Flowspace"
JWT_ALG = "HS256"


# --------------------------------------------------------------------------------------
#  Database helpers
# --------------------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Drop + recreate + seed on every boot so the lab is deterministic within a run."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);

        CREATE TABLE workspaces (
            id      INTEGER PRIMARY KEY,
            name    TEXT,
            slug    TEXT,
            plan    TEXT
        );

        CREATE TABLE users (
            id            INTEGER PRIMARY KEY,
            email         TEXT UNIQUE,
            password_hash TEXT,
            name          TEXT,
            role          TEXT,
            workspace_id  INTEGER,
            created_at    TEXT
        );

        CREATE TABLE projects (
            id           INTEGER PRIMARY KEY,
            workspace_id INTEGER,
            name         TEXT,
            description  TEXT,
            owner_id     INTEGER,
            archived     INTEGER DEFAULT 0
        );

        CREATE TABLE tasks (
            id          INTEGER PRIMARY KEY,
            project_id  INTEGER,
            title       TEXT,
            status      TEXT,
            priority    TEXT,
            assignee_id INTEGER,
            created_at  TEXT
        );

        CREATE TABLE invoices (
            id           INTEGER PRIMARY KEY,
            workspace_id INTEGER,
            number       TEXT,
            customer     TEXT,
            amount       REAL,
            status       TEXT,
            issued_at    TEXT
        );

        CREATE TABLE notifications (
            id      INTEGER PRIMARY KEY,
            user_id INTEGER,
            kind    TEXT,
            body    TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT
        );

        CREATE TABLE activity (
            id        INTEGER PRIMARY KEY,
            workspace_id INTEGER,
            actor     TEXT,
            verb      TEXT,
            target    TEXT,
            at        TEXT
        );

        CREATE TABLE comments (
            id         INTEGER PRIMARY KEY,
            task_id    INTEGER,
            author     TEXT,
            body       TEXT,
            created_at TEXT
        );

        CREATE TABLE webhook_deliveries (
            id         INTEGER PRIMARY KEY,
            workspace_id INTEGER,
            event      TEXT,
            status     INTEGER,
            at         TEXT
        );
        """
    )

    def pw(p):
        # salted sha256 — fine for a lab; the admin password is random & not the intended path
        salt = secrets.token_hex(8)
        return salt + "$" + hashlib.sha256((salt + p).encode()).hexdigest()

    db.execute("INSERT INTO settings(key,value) VALUES(?,?)", ("jwt_secret", JWT_SECRET))
    db.execute("INSERT INTO settings(key,value) VALUES(?,?)", ("app_version", "3.4.1"))
    db.execute("INSERT INTO settings(key,value) VALUES(?,?)", ("signups_open", "1"))

    db.executemany(
        "INSERT INTO workspaces(id,name,slug,plan) VALUES(?,?,?,?)",
        [
            (1, "Acme HQ", "acme", "enterprise"),
            (2, "Northwind", "northwind", "team"),
        ],
    )

    admin_pw = secrets.token_hex(18)  # un-crackable random; cracking users is NOT the path
    db.executemany(
        "INSERT INTO users(id,email,password_hash,name,role,workspace_id,created_at) VALUES(?,?,?,?,?,?,?)",
        [
            (1, "nadia.admin@flowspace.io", pw(admin_pw), "Nadia Haddad", "admin", 1, "2024-01-04"),
            (2, "marco.dev@flowspace.io", pw("marco123"), "Marco Ruiz", "member", 1, "2024-02-11"),
            (3, "lena.pm@flowspace.io", pw("lena2024"), "Lena Fischer", "member", 1, "2024-02-19"),
            (4, "sam.design@flowspace.io", pw("sammy!!"), "Sam Olsen", "member", 1, "2024-03-02"),
            (5, "demo@flowspace.io", pw("demo"), "Demo User", "member", 2, "2024-03-20"),
        ],
    )

    db.executemany(
        "INSERT INTO projects(id,workspace_id,name,description,owner_id,archived) VALUES(?,?,?,?,?,?)",
        [
            (1, 1, "Platform Rewrite", "Migrate the monolith to services.", 1, 0),
            (2, 1, "Mobile App v2", "Ship the new onboarding flow.", 3, 0),
            (3, 1, "Billing Revamp", "Usage-based invoicing + webhooks.", 1, 0),
            (4, 1, "Security Hardening", "Q3 remediation backlog.", 1, 0),
            (5, 2, "Website Refresh", "New marketing site.", 5, 0),
        ],
    )

    statuses = ["open", "in_progress", "review", "done", "blocked"]
    prios = ["low", "medium", "high", "critical"]
    seed_tasks = []
    tid = 1
    titles = [
        "Extract auth service", "Add rate limiting", "Write migration scripts",
        "Design onboarding screens", "Fix push notifications", "Audit JWT handling",
        "Instrument billing events", "Webhook signature verify", "Patch XSS in comments",
        "Rotate API keys", "Add 2FA", "Pen-test report triage", "Upgrade dependencies",
        "Cache invalidation bug", "Dark mode polish", "Invoice PDF export",
    ]
    for i, t in enumerate(titles):
        pid = (i % 5) + 1
        seed_tasks.append(
            (tid, pid, t, statuses[i % len(statuses)], prios[i % len(prios)],
             ((i % 5) + 1), "2024-04-%02d" % ((i % 27) + 1))
        )
        tid += 1
    db.executemany(
        "INSERT INTO tasks(id,project_id,title,status,priority,assignee_id,created_at) VALUES(?,?,?,?,?,?,?)",
        seed_tasks,
    )

    db.executemany(
        "INSERT INTO invoices(id,workspace_id,number,customer,amount,status,issued_at) VALUES(?,?,?,?,?,?,?)",
        [
            (1, 1, "INV-2041", "Globex Corp", 4200.00, "paid", "2024-03-01"),
            (2, 1, "INV-2042", "Initech", 1800.50, "due", "2024-03-15"),
            (3, 1, "INV-2043", "Soylent Inc", 9900.00, "overdue", "2024-02-20"),
            (4, 2, "INV-3001", "Stark Industries", 650.00, "paid", "2024-03-22"),
        ],
    )

    db.executemany(
        "INSERT INTO notifications(id,user_id,kind,body,is_read,created_at) VALUES(?,?,?,?,?,?)",
        [
            (1, 1, "mention", "Lena mentioned you in Billing Revamp", 0, "2024-04-10"),
            (2, 1, "system", "Weekly digest is ready", 1, "2024-04-09"),
            (3, 2, "assign", "You were assigned 'Add rate limiting'", 0, "2024-04-08"),
            (4, 3, "mention", "Nadia mentioned you in Mobile App v2", 0, "2024-04-07"),
        ],
    )

    db.executemany(
        "INSERT INTO activity(id,workspace_id,actor,verb,target,at) VALUES(?,?,?,?,?,?)",
        [
            (1, 1, "Nadia Haddad", "created", "Security Hardening", "2024-04-01"),
            (2, 1, "Marco Ruiz", "closed", "Upgrade dependencies", "2024-04-05"),
            (3, 1, "Lena Fischer", "commented on", "Mobile App v2", "2024-04-06"),
            (4, 1, "Nadia Haddad", "configured", "Billing Webhook integration", "2024-04-07"),
            (5, 1, "Sam Olsen", "uploaded", "mockups to Mobile App v2", "2024-04-08"),
            (6, 1, "Marco Ruiz", "opened", "Audit JWT handling", "2024-04-09"),
            (7, 1, "Lena Fischer", "moved", "Add 2FA to review", "2024-04-10"),
            (8, 1, "Nadia Haddad", "invited", "a new teammate", "2024-04-11"),
            (9, 1, "Marco Ruiz", "merged", "PR #412 into Platform Rewrite", "2024-04-12"),
            (10, 1, "Lena Fischer", "closed", "Cache invalidation bug", "2024-04-13"),
        ],
    )

    db.executemany(
        "INSERT INTO comments(id,task_id,author,body,created_at) VALUES(?,?,?,?,?)",
        [
            (1, 6, "Marco Ruiz", "The current code trusts the alg header — we must pin HS256.", "2024-04-09"),
            (2, 6, "Nadia Haddad", "Agreed. Also stop logging raw tokens.", "2024-04-09"),
            (3, 2, "Sam Olsen", "Onboarding copy is final, handing to eng.", "2024-04-08"),
            (4, 8, "Lena Fischer", "Webhook signatures need constant-time compare.", "2024-04-10"),
            (5, 1, "Marco Ruiz", "Auth service extraction is ~60% done.", "2024-04-12"),
            (6, 10, "Nadia Haddad", "Nice, that one was flaky for weeks.", "2024-04-13"),
        ],
    )

    db.executemany(
        "INSERT INTO webhook_deliveries(id,workspace_id,event,status,at) VALUES(?,?,?,?,?)",
        [
            (1, 1, "invoice.paid", 200, "2024-04-01 09:12"),
            (2, 1, "invoice.overdue", 200, "2024-04-02 10:30"),
            (3, 1, "invoice.paid", 500, "2024-04-03 14:05"),
            (4, 1, "invoice.paid", 200, "2024-04-04 08:44"),
            (5, 1, "invoice.overdue", 403, "2024-04-05 16:20"),
        ],
    )

    db.commit()
    db.close()


def init_integrations():
    """Integration records live in a FLAT FILE, never in the DB.  Each has a signing
    secret.  The billing webhook (id=1, workspace 1 / admin-owned) holds the secret the
    admin Vault uses to authenticate export requests."""
    data = {
        "1": {
            "id": 1,
            "workspace_id": 1,
            "name": "Billing Webhook",
            "provider": "stripe",
            "endpoint": "https://hooks.flowspace.io/billing/acme",
            "events": ["invoice.paid", "invoice.overdue"],
            "owner": "nadia.admin@flowspace.io",
            "signing_secret": WEBHOOK_SECRET,     # <-- authenticates Vault export requests
            "created_at": "2024-04-07",
        },
        "2": {
            "id": 2,
            "workspace_id": 1,
            "name": "Slack Notifications",
            "provider": "slack",
            "endpoint": "https://hooks.slack.com/services/T000/B000/xxx",
            "events": ["task.assigned"],
            "owner": "marco.dev@flowspace.io",
            "signing_secret": "whk_slack_" + secrets.token_hex(10),
            "created_at": "2024-03-30",
        },
        "3": {
            "id": 3,
            "workspace_id": 2,
            "name": "GitHub Sync",
            "provider": "github",
            "endpoint": "https://api.github.com/repos/northwind/site/hooks",
            "events": ["push"],
            "owner": "demo@flowspace.io",
            "signing_secret": "whk_gh_" + secrets.token_hex(10),
            "created_at": "2024-03-25",
        },
    }
    with open(INTEGRATIONS_PATH, "w") as f:
        json.dump(data, f, indent=2)


def load_integrations():
    with open(INTEGRATIONS_PATH) as f:
        return json.load(f)


# --------------------------------------------------------------------------------------
#  Auth helpers
# --------------------------------------------------------------------------------------
def make_token(user):
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "ws": user["workspace_id"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 60 * 60 * 8,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def current_user():
    tok = request.cookies.get("session")
    if not tok:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth[7:]
    if not tok:
        return None
    try:
        # Algorithm is pinned: forging requires the real secret, not alg:none.
        data = jwt.decode(tok, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        return None
    return data


def check_password(stored, given):
    try:
        salt, h = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(h, hashlib.sha256((salt + given).encode()).hexdigest())


def require_login():
    u = current_user()
    if not u:
        abort(401)
    return u


# --------------------------------------------------------------------------------------
#  App
# --------------------------------------------------------------------------------------
app = Flask(__name__)
app.teardown_appcontext(close_db)


@app.context_processor
def inject_globals():
    u = current_user()
    unread = 0
    if u:
        db = get_db()
        row = db.execute(
            "SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0", (int(u["sub"]),)
        ).fetchone()
        unread = row["c"] if row else 0
    return {"APP_NAME": APP_NAME, "current_user": u, "unread": unread, "now": datetime.datetime}


# ---------- public pages ----------
@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", error=None)
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    name = (request.form.get("name") or "").strip() or "New User"
    if not email or not password:
        return render_template("register.html", error="Email and password are required.")
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return render_template("register.html", error="That email is already registered.")
    salt = secrets.token_hex(8)
    ph = salt + "$" + hashlib.sha256((salt + password).encode()).hexdigest()
    # New sign-ups join the demo workspace (2) as a member.
    cur = db.execute(
        "INSERT INTO users(email,password_hash,name,role,workspace_id,created_at) VALUES(?,?,?,?,?,?)",
        (email, ph, name, "member", 2, datetime.date.today().isoformat()),
    )
    db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("session", make_token(user), httponly=True, samesite="Lax")
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not check_password(user["password_hash"], password):
        return render_template("login.html", error="Invalid email or password.")
    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("session", make_token(user), httponly=True, samesite="Lax")
    return resp


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("landing")))
    resp.delete_cookie("session")
    return resp


# ---------- authenticated pages ----------
@app.route("/dashboard")
def dashboard():
    u = require_login()
    db = get_db()
    projects = db.execute(
        "SELECT * FROM projects WHERE workspace_id=? AND archived=0 ORDER BY id", (u["ws"],)
    ).fetchall()
    my_tasks = db.execute(
        """SELECT t.*, p.name AS project FROM tasks t JOIN projects p ON p.id=t.project_id
           WHERE t.assignee_id=? ORDER BY t.id LIMIT 8""",
        (int(u["sub"]),),
    ).fetchall()
    activity = db.execute(
        "SELECT * FROM activity WHERE workspace_id=? ORDER BY id DESC LIMIT 6", (u["ws"],)
    ).fetchall()
    return render_template("dashboard.html", projects=projects, my_tasks=my_tasks, activity=activity)


@app.route("/projects")
def projects_list():
    u = require_login()
    db = get_db()
    projects = db.execute(
        "SELECT * FROM projects WHERE workspace_id=? ORDER BY id", (u["ws"],)
    ).fetchall()
    counts = {}
    for p in projects:
        c = db.execute("SELECT COUNT(*) c FROM tasks WHERE project_id=?", (p["id"],)).fetchone()
        counts[p["id"]] = c["c"]
    return render_template("projects.html", projects=projects, counts=counts)


@app.route("/projects/<int:pid>")
def project_detail(pid):
    u = require_login()
    db = get_db()
    project = db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    if not project or project["workspace_id"] != u["ws"]:
        abort(404)
    tasks = db.execute("SELECT * FROM tasks WHERE project_id=? ORDER BY id", (pid,)).fetchall()
    tids = [t["id"] for t in tasks] or [-1]
    qmarks = ",".join("?" for _ in tids)
    comments = db.execute(
        "SELECT * FROM comments WHERE task_id IN (%s) ORDER BY id" % qmarks, tids
    ).fetchall()
    return render_template("project_detail.html", project=project, tasks=tasks, comments=comments)


@app.route("/tasks")
def tasks_page():
    u = require_login()
    db = get_db()
    tasks = db.execute(
        """SELECT t.*, p.name AS project FROM tasks t JOIN projects p ON p.id=t.project_id
           WHERE p.workspace_id=? ORDER BY t.id""",
        (u["ws"],),
    ).fetchall()
    return render_template("tasks.html", tasks=tasks)


@app.route("/team")
def team_page():
    u = require_login()
    db = get_db()
    members = db.execute(
        "SELECT id,name,email,role,created_at FROM users WHERE workspace_id=? ORDER BY id", (u["ws"],)
    ).fetchall()
    return render_template("team.html", members=members)


@app.route("/notifications")
def notifications_page():
    u = require_login()
    db = get_db()
    notes = db.execute(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC", (int(u["sub"]),)
    ).fetchall()
    return render_template("notifications.html", notes=notes)


@app.route("/billing")
def billing_page():
    u = require_login()
    db = get_db()
    invoices = db.execute(
        "SELECT * FROM invoices WHERE workspace_id=? ORDER BY id DESC", (u["ws"],)
    ).fetchall()
    return render_template("billing.html", invoices=invoices)


@app.route("/settings")
def settings_page():
    u = require_login()
    db = get_db()
    me = db.execute("SELECT id,name,email,role,created_at FROM users WHERE id=?", (u["sub"],)).fetchone()
    return render_template("settings.html", me=me)


@app.route("/integrations")
def integrations_page():
    u = require_login()
    data = load_integrations()
    # The UI only lists integrations for the current workspace, and NEVER shows the secret.
    mine = [i for i in data.values() if i["workspace_id"] == u["ws"]]
    return render_template("integrations.html", integrations=mine)


@app.route("/reports")
def reports_page():
    require_login()
    return render_template("reports.html")


@app.route("/search")
def search_page():
    u = require_login()
    q = (request.args.get("q") or "").strip()
    projects = tasks = []
    if q:
        db = get_db()
        like = "%" + q + "%"
        # Parameterized LIKE — the search term is bound, never concatenated.
        projects = db.execute(
            "SELECT * FROM projects WHERE workspace_id=? AND (name LIKE ? OR description LIKE ?) ORDER BY id",
            (u["ws"], like, like),
        ).fetchall()
        tasks = db.execute(
            """SELECT t.*, p.name AS project FROM tasks t JOIN projects p ON p.id=t.project_id
               WHERE p.workspace_id=? AND t.title LIKE ? ORDER BY t.id""",
            (u["ws"], like),
        ).fetchall()
    return render_template("search.html", q=q, projects=projects, tasks=tasks)


@app.route("/activity")
def activity_page():
    u = require_login()
    db = get_db()
    rows = db.execute(
        "SELECT * FROM activity WHERE workspace_id=? ORDER BY id DESC", (u["ws"],)
    ).fetchall()
    deliveries = db.execute(
        "SELECT * FROM webhook_deliveries WHERE workspace_id=? ORDER BY id DESC", (u["ws"],)
    ).fetchall()
    return render_template("activity.html", rows=rows, deliveries=deliveries)


@app.route("/api/projects")
def api_projects():
    u = require_login()
    db = get_db()
    rows = db.execute(
        "SELECT id,name,description,owner_id,archived FROM projects WHERE workspace_id=? ORDER BY id",
        (u["ws"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/tasks")
def api_tasks():
    u = require_login()
    db = get_db()
    rows = db.execute(
        """SELECT t.id,t.title,t.status,t.priority FROM tasks t JOIN projects p ON p.id=t.project_id
           WHERE p.workspace_id=? ORDER BY t.id""",
        (u["ws"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------- admin pages ----------
@app.route("/admin")
def admin_home():
    u = require_login()
    if u.get("role") != "admin":
        abort(403)
    db = get_db()
    users = db.execute("SELECT id,name,email,role,workspace_id,created_at FROM users ORDER BY id").fetchall()
    stats = {
        "users": db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "projects": db.execute("SELECT COUNT(*) c FROM projects").fetchone()["c"],
        "tasks": db.execute("SELECT COUNT(*) c FROM tasks").fetchone()["c"],
        "version": db.execute("SELECT value FROM settings WHERE key='app_version'").fetchone()["value"],
    }
    return render_template("admin.html", users=users, stats=stats)


@app.route("/admin/vault")
def admin_vault_page():
    u = require_login()
    if u.get("role") != "admin":
        abort(403)
    return render_template("vault.html")


# --------------------------------------------------------------------------------------
#  JSON API
# --------------------------------------------------------------------------------------
@app.route("/api/me")
def api_me():
    u = require_login()
    return jsonify({"id": int(u["sub"]), "email": u["email"], "name": u["name"],
                    "role": u["role"], "workspace_id": u["ws"]})


@app.route("/api/notifications")
def api_notifications():
    u = require_login()
    db = get_db()
    rows = db.execute(
        "SELECT id,kind,body,is_read,created_at FROM notifications WHERE user_id=? ORDER BY id DESC",
        (int(u["sub"]),),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ----- the task report filter (member-accessible) -----
@app.route("/api/reports/tasks")
def api_reports_tasks():
    """Filter tasks by status for the report builder.  Returns id/title/status rows."""
    require_login()
    status = request.args.get("status", "open")
    db = get_db()
    # Legacy reporting query — the status filter is concatenated directly.
    q = ("SELECT id, title, status FROM tasks WHERE status = '%s' ORDER BY id" % status)
    try:
        cur = db.execute(q)  # single statement; sqlite3.execute() does not allow stacking
        rows = cur.fetchall()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "query": q}), 400
    return jsonify({"ok": True, "count": len(rows),
                    "rows": [{"id": r[0], "title": r[1], "status": r[2]} for r in rows]})


# ----- raw integration object (member-accessible) -----
@app.route("/api/integrations/<int:iid>")
def api_integration(iid):
    """Return a single integration record by id."""
    require_login()
    data = load_integrations()
    rec = data.get(str(iid))
    if not rec:
        return jsonify({"ok": False, "error": "not found"}), 404
    # NOTE: returns the stored record as-is.
    return jsonify({"ok": True, "integration": rec})


@app.route("/api/integrations")
def api_integrations_list():
    u = require_login()
    data = load_integrations()
    mine = [{"id": i["id"], "name": i["name"], "provider": i["provider"],
             "endpoint": i["endpoint"]} for i in data.values() if i["workspace_id"] == u["ws"]]
    return jsonify({"ok": True, "integrations": mine})


# ----- admin vault export (admin JWT + HMAC, then renders a report template) -----
_BLOCKED = [".", "[", "]", "_",
            "os", "popen", "system", "subprocess", "import", "eval", "exec",
            "globals", "getitem", "builtins", "class", "mro", "subclasses",
            "base", "getattr", "setattr", "config", "self", "cycler",
            "joiner", "namespace", "open", "read\x00"]


def _template_is_blocked(s):
    low = s.lower()
    for bad in _BLOCKED:
        if bad in low:
            return bad
    return None


@app.route("/api/admin/vault/export", methods=["POST"])
def api_vault_export():
    """Render a saved 'export template' to preview a billing report.

    Protected two ways:
      * caller must present an admin session (JWT, role=admin), AND
      * the request body must carry a valid HMAC signature in `X-Vault-Signature`,
        computed with the billing webhook's signing secret.
    """
    u = current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"ok": False, "error": "admin session required"}), 403

    raw = request.get_data()  # exact bytes signed
    sig = request.headers.get("X-Vault-Signature", "")
    expected = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return jsonify({"ok": False, "error": "invalid or missing X-Vault-Signature"}), 403

    try:
        body = json.loads(raw.decode() or "{}")
    except Exception:
        return jsonify({"ok": False, "error": "bad json"}), 400

    template = body.get("template", "")
    title = body.get("title", "Report")
    bad = _template_is_blocked(template)
    if bad:
        return jsonify({"ok": False, "error": "template contains a blocked token: %r" % bad}), 400

    # Render the operator-supplied template.  (Admins are trusted... right?)
    try:
        rendered = render_template_string(template, title=title, generated=datetime.datetime.utcnow())
    except Exception as e:
        return jsonify({"ok": False, "error": "render error: %s" % e}), 400
    return jsonify({"ok": True, "title": title, "rendered": rendered})


# --------------------------------------------------------------------------------------
#  Error handlers
# --------------------------------------------------------------------------------------
@app.errorhandler(401)
def e401(_):
    return render_template("error.html", code=401, msg="You need to sign in to view that."), 401


@app.errorhandler(403)
def e403(_):
    return render_template("error.html", code=403, msg="You don't have access to that."), 403


@app.errorhandler(404)
def e404(_):
    return render_template("error.html", code=404, msg="Nothing here."), 404


# --------------------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    init_integrations()
    print(" * Flowspace seeded. JWT secret + webhook secret generated for this run.")
    app.run(host="0.0.0.0", port=9011, debug=False)
