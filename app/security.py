import base64
import hashlib
import hmac
import os
import re
from datetime import datetime, timezone
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from .db import connection


def hash_password(password):
    salt = os.urandom(16)
    value = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)
    return base64.b64encode(salt + value).decode()


def verify_password(password, encoded):
    raw = base64.b64decode(encoded)
    return hmac.compare_digest(
        raw[16:], hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], 600000)
    )


def validate_password(password):
    if (
        len(password) < 8
        or not re.search("[A-Za-zА-Яа-я]", password)
        or not re.search("[0-9]", password)
    ):
        raise HTTPException(400, "Пароль: минимум 8 символов, буквы и цифры")


bearer = HTTPBearer(auto_error=False)


def current_user(auth: HTTPAuthorizationCredentials = Depends(bearer), conn=Depends(connection)):
    try:
        if not auth:
            raise ValueError()
        data = jwt.decode(
            auth.credentials,
            os.environ["JWT_SECRET"],
            algorithms=["HS256"],
            options={"require": ["exp", "sub", "jti", "ver"]},
        )
        user = conn.execute(
            "SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE u.id=%s AND s.id=%s AND s.expires_at>now()",
            (int(data["sub"]), data["jti"]),
        ).fetchone()
        if not user or user["blocked"] or user["deleted"] or data["ver"] != user["token_version"]:
            raise ValueError()
    except (jwt.PyJWTError, ValueError, KeyError):
        raise HTTPException(401, "Сеанс завершён. Войдите снова.")
    if (
        not user["last_seen"]
        or (datetime.now(timezone.utc) - user["last_seen"]).total_seconds() > 10
    ):
        conn.execute("UPDATE users SET last_seen=now() WHERE id=%s", (user["id"],))
    user["session_id"] = data["jti"]
    return user


def administrator(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Доступ только администратору")
    return user
