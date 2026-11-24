"""Leaky Notes — a deliberately INSECURE notes API for BE104.

This app works. It also has real security holes on purpose. You will find and
demonstrate them with your own eyes, then fix the same kinds of holes in your
own Recipe Box API.

DO NOT deploy this or reuse its patterns. It exists to be broken.

Two flaws are planted here:
  1. Passwords are stored in PLAINTEXT (Unit 2 finds this before you learn hashing).
  2. Note editing/deleting has NO ownership check — any logged-in user can change
     anyone's notes (Unit 3 finds this before you enforce ownership).
"""

import os
import sqlite3
import jwt
from datetime import datetime, timedelta, timezone


from flask import Flask, g, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = "leaky.db"


app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")

if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable must be set"
    )


def hash_password(password: str) -> str:
    return generate_password_hash(password, method="pbkdf2:sha256")

def verify_password(stored_hash: str, candidate: str) -> bool:
    return check_password_hash(stored_hash, candidate)

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()



@app.post("/register")
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not username.strip():
        return jsonify({"error": "valid username required"}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "valid password required"}), 400

    username = username.strip()

    if len(username) > 50:
        return jsonify({"error": "username too long"}), 400

    if len(password) < 12 or len(password) > 128:
        return jsonify({
            "error": "password must be between 12 and 128 characters"
        }), 400

    db = get_db()

    try:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password))
        )
        db.commit()

    except sqlite3.IntegrityError:
        return jsonify({"error": "username taken"}), 409

    return jsonify({"username": username}), 201






@app.post("/login")
def login():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    body = data.get("body")

    if not isinstance(body, str) or not body.strip():
        return jsonify({"error": "body must be non-empty text"}), 400

    if len(body) > 10000:
        return jsonify({"error": "body exceeds maximum length"}), 400


    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not username.strip():
        return jsonify({"error": "valid username required"}), 400

    if not isinstance(password, str) or not password:
        return jsonify({"error": "valid password required"}), 400

    username = username.strip()

    if len(username) > 50 or len(password) > 128:
        return jsonify({"error": "invalid credentials format"}), 400

    # Find the user in the database
    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    # Verify the stored password hash
    if row is None or not verify_password(row["password_hash"], password):
        return jsonify({"error": "bad credentials"}), 401

    # Generate a signed JWT
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(row["id"]),
        "username": row["username"],
        "iat": now,
        "exp": now + timedelta(minutes=30),
    }

    secret = app.config["JWT_SECRET_KEY"]

    if not secret:
        return jsonify({"error": "JWT signing key not configured"}), 500

    token = jwt.encode(payload, secret, algorithm="HS256")

    return jsonify({
        "username": row["username"],
        "token": token
    }), 200







def current_user_id():
    authorization = request.headers.get("Authorization", "")

    if not authorization.startswith("Bearer "):
        return None

    token = authorization[len("Bearer "):].strip()

    if not token:
        return None

    secret = app.config["JWT_SECRET_KEY"]

    if not secret:
        return None

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["sub", "iat", "exp"]}
        )

        subject = payload["sub"]

        if not isinstance(subject, str) or not subject.isdecimal():
            return None

        user_id = int(subject)

        if user_id <= 0:
            return None

        # SECURITY FIX: Verify the account still exists.
        user = get_db().execute(
            "SELECT id FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if user is None:
            return None

        return user_id

    except (jwt.InvalidTokenError, ValueError, TypeError):
        return None




@app.post("/notes")
def create_note():
    user_id = current_user_id()

    if user_id is None:
        return jsonify({"error": "log in first"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    body = data.get("body")

    if not isinstance(body, str) or not body.strip():
        return jsonify({"error": "body must be non-empty text"}), 400

    if len(body) > 10000:
        return jsonify({"error": "body exceeds maximum length"}), 400

    db = get_db()

    cur = db.execute(
        "INSERT INTO notes (owner_id, body) VALUES (?, ?)",
        (user_id, body)
    )

    db.commit()

    return jsonify({
        "id": cur.lastrowid,
        "owner_id": user_id,
        "body": body
    }), 201




@app.get("/notes")
def list_notes():
    user_id = current_user_id()

    if user_id is None:
        return jsonify({"error": "log in first"}), 401

    rows = get_db().execute(
        "SELECT * FROM notes WHERE owner_id = ? ORDER BY id",
        (user_id,)
    ).fetchall()

    return jsonify([dict(r) for r in rows]), 200



@app.patch("/notes/<int:note_id>")
def edit_note(note_id):
    user_id = current_user_id()

    if user_id is None:
        return jsonify({"error": "log in first"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    body = data.get("body")

    if not isinstance(body, str) or not body.strip():
        return jsonify({"error": "body must be non-empty text"}), 400

    if len(body) > 10000:
        return jsonify({"error": "body exceeds maximum length"}), 400

    db = get_db()

    # Only the note owner can edit this note.
    cur = db.execute(
        "UPDATE notes SET body = ? WHERE id = ? AND owner_id = ?",
        (body, note_id, user_id)
    )

    db.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "note not found"}), 404

    return jsonify({
        "id": note_id,
        "body": body
    }), 200




@app.delete("/notes/<int:note_id>")
def delete_note(note_id):
    user_id = current_user_id()

    if user_id is None:
        return jsonify({"error": "log in first"}), 401

    db = get_db()

    # SECURITY FIX: Only the note owner can delete this note.
    cur = db.execute(
        "DELETE FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, user_id)
    )

    db.commit()

    if cur.rowcount == 0:
        return jsonify({"error": "note not found"}), 404

    return "", 204




if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug_mode, port=5002)
