from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from passlib.hash import argon2
from Crypto.Cipher import AES
from dotenv import load_dotenv
import base64
import sqlite3
import os
from uuid import uuid4

# Load environment variables
load_dotenv()

# Flask App Initialization
app = Flask(__name__)

# Rate Limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per second"])

# Database Path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")

# AES Encryption Helper Functions
def encrypt_key(key, secret):
    cipher = AES.new(secret.encode('utf-8'), AES.MODE_CFB)
    return base64.b64encode(cipher.iv + cipher.encrypt(key.encode('utf-8'))).decode('utf-8')

def decrypt_key(encrypted_key, secret):
    data = base64.b64decode(encrypted_key)
    cipher = AES.new(secret.encode('utf-8'), AES.MODE_CFB, iv=data[:16])
    return cipher.decrypt(data[16:]).decode('utf-8')

# Setup Database Tables
def setup_database():
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL
            )
        """)
        conn.commit()


# User Registration Endpoint
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = str(uuid4())
        hashed_password = argon2.hash(password)

        secret_key = os.getenv("NOT_MY_KEY")
        private_key = "sample-private-key"
        encrypted_key = encrypt_key(private_key, secret_key)

        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            cursor.execute("INSERT INTO keys (key) VALUES (?)", (encrypted_key,))
            conn.commit()

        return jsonify({"password": password}), 201
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

# Authentication Endpoint
@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def authenticate():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

        if not user or not argon2.verify(password, user[1]):
            return jsonify({"message": "Unauthorized"}), 401

        user_id = user[0]
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO auth_logs (request_ip, user_id)
                VALUES (?, ?)
            """, (request.remote_addr, user_id))
            conn.commit()

        return jsonify({"message": "Authenticated"}), 200
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print(f"Database Path: {DATABASE_PATH}")
    setup_database()  # Call the setup function here
    app.run(host='127.0.0.1', port=8080, debug=True)
