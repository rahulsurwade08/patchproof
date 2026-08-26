"""DVPWA-style SQL injection scenario.

Replicates the SQL injection vulnerability from anxolerd/dvpwa:
student.py uses Python string formatting to build INSERT queries,
allowing an attacker to inject arbitrary SQL.

Vulnerable pattern (from dvpwa sqli/dao/student.py:42-43):
    q = "INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name}

CVE: demonstrates insecure query construction (no specific CVE, code-level vuln).
"""

import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

DATABASE = ":memory:"

conn = sqlite3.connect(DATABASE, check_same_thread=False)
conn.execute(
    "CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT)"
)
conn.execute(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)"
)
conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', '5f4dcc3b5aa765d61d8327deb882cf99')")
conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="dvpwa-sqli-scenario", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/students")
def list_students():
    cur = conn.execute("SELECT id, name FROM students")
    return {"students": [{"id": r[0], "name": r[1]} for r in cur.fetchall()]}


@app.post("/students")
def create_student(request: dict):
    name = request.get("name", "")
    # VULNERABLE: string formatting builds SQL — replicates dvpwa pattern
    q = "INSERT INTO students (name) VALUES ('%s')" % name
    try:
        conn.execute(q)
        conn.commit()
        return {"ok": True, "name": name}
    except Exception as e:
        return {"error": str(e)}


@app.get("/search")
def search_students(q: str = ""):
    # VULNERABLE: same pattern for SELECT
    query = "SELECT id, name FROM students WHERE name LIKE '%%%s%%'" % q
    try:
        cur = conn.execute(query)
        return {"results": [{"id": r[0], "name": r[1]} for r in cur.fetchall()]}
    except Exception as e:
        return {"error": str(e)}


@app.post("/login")
def login(request: dict):
    username = request.get("username", "")
    password = request.get("password", "")
    # VULNERABLE: string formatting in auth query
    query = "SELECT id, username FROM users WHERE username='%s' AND password_hash='%s'" % (
        username,
        password,
    )
    try:
        cur = conn.execute(query)
        user = cur.fetchone()
        if user:
            return {"authenticated": True, "user_id": user[0], "username": user[1]}
        return {"authenticated": False}
    except Exception as e:
        return {"error": str(e)}
