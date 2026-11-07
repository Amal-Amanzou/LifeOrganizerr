import os
import re
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "lifeorganizer.db")

app = Flask(__name__)
app.config.update(
    # En production: export SECRET_KEY="une-longue-chaine-aleatoire"
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)

USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,30}")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


# ---------------------------------------------------------------
# Database
# ---------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


init_db()


# ---------------------------------------------------------------
# Security helpers: current user, CSRF, login_required
# ---------------------------------------------------------------
@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if g.user is None:          # compte supprime
            session.clear()


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent.encode(), expected.encode()):
            abort(400)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def safe_next(target):
    """Accept only local paths like /tasks (no open redirect)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


def start_session(user_id, remember=False):
    session.clear()                 # evite la session fixation
    session["user_id"] = user_id
    session.permanent = remember


# ---------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))

    form = {"username": "", "email": ""}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        form = {"username": username, "email": email}

        error = None
        if not USERNAME_RE.fullmatch(username):
            error = "Username must be 3-30 characters: letters, numbers or _."
        elif not EMAIL_RE.fullmatch(email) or len(email) > 254:
            error = "Please enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif len(password) > 128:
            error = "Password is too long."
        elif password != confirm:
            error = "Passwords do not match."
        else:
            try:
                db = get_db()
                cur = db.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email,
                     generate_password_hash(password, method="pbkdf2:sha256")),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "This username or email is already used."
            else:
                start_session(cur.lastrowid)
                flash(f"Welcome, {username}! Your account is ready.", "success")
                return redirect(url_for("dashboard"))

        flash(error, "error")

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    identifier = ""

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = get_db().execute(
            "SELECT * FROM users WHERE email = ? OR username = ?",
            (identifier.lower(), identifier),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            start_session(user["id"], remember)
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(safe_next(request.args.get("next")) or url_for("dashboard"))

        # Message generique: ne dit pas si c'est l'email ou le mot de passe
        flash("Incorrect email/username or password.", "error")

    return render_template("login.html", identifier=identifier)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------
# App routes
# ---------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/tasks")
@login_required
def tasks():
    return render_template("tasks.html")


@app.route("/habits")
@login_required
def habits():
    return render_template("habits.html")


@app.route("/calendar")
@login_required
def calendar():
    return render_template("calendar.html")


if __name__ == "__main__":
    app.run(debug=True)
