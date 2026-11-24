
"""Create and seed leaky.db. Run once after cloning: python init_db.py"""

import sqlite3
from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    body TEXT NOT NULL
);
"""

connection = sqlite3.connect("leaky.db")

connection.executescript(SCHEMA)

if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
    connection.executemany(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        [
            ("alice", generate_password_hash(
                "correcthorse", method="pbkdf2:sha256"
            )),
            ("bob", generate_password_hash(
                "hunter2", method="pbkdf2:sha256"
            )),
        ],
    )

    connection.executemany(
        "INSERT INTO notes (owner_id, body) VALUES (?, ?)",
        [
            (1, "Alice's private grocery list"),
            (2, "Bob's diary entry"),
        ],
    )

    connection.commit()
    print("Created leaky.db with 2 users and 2 notes.")
else:
    print("leaky.db already seeded - nothing to do.")

connection.close()
