import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-to-a-random-secret-key"

DB_NAME = "notes_v2.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            error = "Username and password are required."
        else:
            conn = get_db()
            cur = conn.cursor()
            existing = cur.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                error = "Username already taken. Please choose another."
            else:
                pw_hash = generate_password_hash(password)
                cur.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, pw_hash),
                )
                conn.commit()
                user_id = cur.lastrowid
                conn.close()
                session["user_id"] = user_id
                session["username"] = username
                return redirect(url_for("index"))
            conn.close()

    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user_id = session["user_id"]
    username = session.get("username", "")
    conn = get_db()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        if title and content:
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "INSERT INTO notes (user_id, title, content, created_at) VALUES (?, ?, ?, ?)",
                (user_id, title, content, created_at),
            )
            conn.commit()
        conn.close()
        return redirect(url_for("index"))

    rows = conn.execute(
        "SELECT id, title, content, created_at FROM notes WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()
    conn.close()

    notes = [(r["id"], r["title"], r["content"], r["created_at"]) for r in rows]
    return render_template("index.html", notes=notes, username=username)


@app.route("/delete/<int:note_id>")
@login_required
def delete_note(note_id):
    user_id = session["user_id"]
    conn = get_db()
    conn.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)