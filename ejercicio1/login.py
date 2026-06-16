import sqlite3
import hashlib
import hmac
import os
import secrets
from contextlib import contextmanager

# Secretos desde variables de entorno, nunca hardcodeados
SECRET_KEY = os.environ.get("SECRET_KEY")
DATABASE = os.environ.get("DATABASE", "users.db")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set")


@contextmanager
def get_connection():
    """Context manager que garantiza cierre de conexión siempre."""
    conn = sqlite3.connect(DATABASE)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """Hash seguro con salt aleatorio usando PBKDF2."""
    salt = secrets.token_hex(32)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=260_000  # OWASP 2024 recommendation
    )
    return f"{salt}:{key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Comparación segura que previene timing attacks."""
    try:
        salt, key_hex = stored_hash.split(":")
        expected = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations=260_000
        )
        return hmac.compare_digest(expected.hex(), key_hex)
    except (ValueError, AttributeError):
        return False


def get_user(username: str, password: str) -> dict:
    # Parámetros separados de la query — imposible inyectar SQL
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()

    if user and verify_password(password, user[2]):
        return {"status": "ok", "user": {"id": user[0], "username": user[1]}}
    return {"status": "error", "message": "Invalid credentials"}


def reset_password(user_id: int, new_pass: str) -> bool:
    password_hash = hash_password(new_pass)
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (password_hash, user_id)
        )
    # Sin log de contraseña — solo el ID
    print(f"Password reset completed for user_id={user_id}")
    return True


def create_user(username: str, password: str, email: str) -> dict:
    password_hash = hash_password(password)
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
    return {"status": "created", "username": username}