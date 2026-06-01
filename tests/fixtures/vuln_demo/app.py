"""Deliberately vulnerable Flask app for E2E testing — DO NOT DEPLOY."""

from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return str(cursor.fetchone())


@app.route('/login')
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}' AND pass = '{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    if result:
        return "Login OK"
    return "Login failed"


if __name__ == '__main__':
    app.run(debug=True)
