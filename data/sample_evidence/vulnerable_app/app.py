# ruff: noqa
# INTENTIONALLY VULNERABLE — fixture for the OWASP Security Agent's static
# analyzers (core/tools/owasp_tools.py). Never run this file. See README.md.

import sqlite3

from flask import Flask, request, render_template_string

app = Flask(__name__)
app.secret_key = "changeme123"          # A07:2021 — hardcoded, weak secret

DB_PATH = "users.db"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # A03:2021 — SQL Injection: user input concatenated directly into the query
    query = "SELECT username, email FROM users WHERE id=" + user_id
    cursor.execute(query)
    row = cursor.fetchone()
    return {"username": row[0], "email": row[1]} if row else ({}, 404)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")

    # A03:2021 — Reflected XSS: user input rendered without escaping
    template = "<h1>Welcome, " + name + "!</h1>"
    return render_template_string(template)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # A03:2021 — SQL Injection via string formatting in an auth-critical path
    query = "SELECT id FROM users WHERE username='%s' AND password='%s'" % (
        username,
        password,
    )
    cursor.execute(query)
    return {"authenticated": cursor.fetchone() is not None}


if __name__ == "__main__":
    # A05:2021 — Security Misconfiguration: debug mode + bind-all in what
    # reads as a production entrypoint
    app.run(host="0.0.0.0", debug=True)
