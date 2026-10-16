"""Учебный API: права, учётные записи, чаты и хранение шифротекста."""

import base64
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict
from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb
from .db import audit, connection, initialize, pool
from .security import administrator, current_user, hash_password, validate_password, verify_password


@asynccontextmanager
async def lifespan(app):
    initialize()
    with pool.connection() as conn:
        if not conn.execute("SELECT id FROM users LIMIT 1").fetchone():
            password = os.environ["ADMIN_PASSWORD"]
            validate_password(password)
            conn.execute(
                "INSERT INTO users(login,first_name,last_name,password_hash,role) VALUES ('admin','Администратор','Системы',%s,'admin')",
                (hash_password(password),),
            )
    yield
    pool.close()


app = FastAPI(
    title="Мессенджер с шифрованием",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def headers(request: Request, call_next):
    if int(request.headers.get("content-length", "0")) > 16_000_000:
        return JSONResponse({"detail": "Файл слишком большой"}, status_code=413)
    response = await call_next(request)
    response.headers.update(
        {
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        }
    )
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Не возвращаем введённые пароли и содержимое запроса в ошибке.
    return JSONResponse({"detail": "Проверьте формат и длину заполненных полей"}, status_code=422)


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Input):
    login: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=200)


class Account(Input):
    login: str = Field(min_length=3, max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)
    role: str = Field(pattern="^(user|admin)$", default="user")
    password: str = Field(max_length=200, default="")


class Action(Input):
    action: str
    password: str = Field(max_length=200, default="")


class Vault(Input):
    public_key: dict
    vault: dict


class Chat(Input):
    title: str = Field(min_length=1, max_length=100)
    is_group: bool = False
    user_ids: list[int] = Field(min_length=1, max_length=9)


class Member(Input):
    user_id: int
    action: str = Field(pattern="^(add|remove|promote|demote)$")


class Packet(Input):
    id: UUID
    revision: int
    payload: dict
    reply_to: UUID | None = None


class Receipt(Input):
    ids: list[UUID] = Field(max_length=100)
    read: bool = False


def public(user):
    return {
        k: user[k]
        for k in (
            "id",
            "login",
            "first_name",
            "last_name",
            "role",
            "blocked",
            "deleted",
            "public_key",
            "last_seen",
        )
    }


def member_of(conn, chat_id, user, admin=False, lock=False):
    chat = conn.execute(
        "SELECT * FROM chats WHERE id=%s" + (" FOR UPDATE" if lock else ""), (chat_id,)
    ).fetchone()
    member = conn.execute(
        "SELECT * FROM members WHERE chat_id=%s AND user_id=%s", (chat_id, user["id"])
    ).fetchone()
    if not chat or not member:
        raise HTTPException(403, "Нет доступа к чату")
    if admin and (not chat["is_group"] or not member["is_admin"]):
        raise HTTPException(403, "Требуются права администратора группы")
    return chat


def b64(value, minimum, maximum):
    try:
        data = base64.b64decode(value, validate=True)
        if not minimum <= len(data) <= maximum:
            raise ValueError()
        return data
    except (ValueError, TypeError):
        raise HTTPException(400, "Некорректный зашифрованный пакет")


@app.get("/api/health")
def health(conn=Depends(connection)):
    conn.execute("SELECT 1")
    return {"status": "ok"}


@app.post("/api/login")
def login(body: Login, conn=Depends(connection)):
    user = conn.execute(
        "SELECT * FROM users WHERE login=%s FOR UPDATE", (body.login.lower(),)
    ).fetchone()
    now = datetime.now(timezone.utc)
    if user and user["locked_until"] and user["locked_until"] > now:
        raise HTTPException(429, "Вход заблокирован на 5 минут после трёх ошибок")
    valid = (
        verify_password(body.password, user["password_hash"])
        if user
        else verify_password(body.password, DUMMY_HASH)
    )
    if not user or not valid or user["blocked"] or user["deleted"]:
        if user:
            failures = (
                0 if user["locked_until"] and user["locked_until"] <= now else user["failures"]
            ) + 1
            conn.execute(
                "UPDATE users SET failures=%s, locked_until=%s WHERE id=%s",
                (failures, now + timedelta(minutes=5) if failures >= 3 else None, user["id"]),
            )
        audit(conn, user["id"] if user else None, "login_failed")
        conn.commit()  # Не откатываем счётчик из-за HTTPException.
        raise HTTPException(401, "Неверный логин или пароль, либо учётная запись заблокирована")
    conn.execute(
        "UPDATE users SET failures=0,locked_until=NULL,last_seen=now() WHERE id=%s", (user["id"],)
    )
    sid = str(uuid4())
    expires = now + timedelta(hours=8)
    conn.execute("DELETE FROM sessions WHERE expires_at<now()")
    conn.execute("INSERT INTO sessions VALUES (%s,%s,%s)", (sid, user["id"], expires))
    audit(conn, user["id"], "login")
    token = jwt.encode(
        {"sub": str(user["id"]), "jti": sid, "ver": user["token_version"], "exp": expires},
        os.environ["JWT_SECRET"],
        algorithm="HS256",
    )
    return {"token": token, "user": public(user), "vault": user["vault"]}


DUMMY_HASH = hash_password("dummy-password-123")


@app.post("/api/logout")
def logout(user=Depends(current_user), conn=Depends(connection)):
    conn.execute("DELETE FROM sessions WHERE id=%s", (user["session_id"],))
    conn.execute("UPDATE users SET last_seen=NULL WHERE id=%s", (user["id"],))
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return public(user)


@app.put("/api/keys")
def keys(body: Vault, user=Depends(current_user), conn=Depends(connection)):
    key, vault = body.public_key, body.vault
    if (
        set(key) - {"kty", "n", "e", "alg", "ext", "key_ops"}
        or key.get("kty") != "RSA"
        or len(key.get("n", "")) != 342
        or key.get("e") != "AQAB"
    ):
        raise HTTPException(400, "Нужен открытый RSA-ключ 2048 бит")
    if set(vault) != {"salt", "iv", "data"}:
        raise HTTPException(400, "Некорректное хранилище ключа")
    b64(vault["salt"], 16, 16)
    b64(vault["iv"], 12, 12)
    b64(vault["data"], 500, 8000)
    existing = conn.execute(
        "SELECT public_key FROM users WHERE id=%s FOR UPDATE", (user["id"],)
    ).fetchone()
    if existing["public_key"]:
        raise HTTPException(409, "Ключ уже создан. Сначала разблокируйте существующий ключ.")
    conn.execute(
        "UPDATE users SET public_key=%s,vault=%s WHERE id=%s",
        (Jsonb(key), Jsonb(vault), user["id"]),
    )
    audit(conn, user["id"], "keys_created")
    return {"ok": True}


@app.get("/api/users")
def users(q: str = "", user=Depends(current_user), conn=Depends(connection)):
    rows = conn.execute(
        "SELECT * FROM users WHERE NOT deleted AND (login ILIKE %s OR (first_name || ' ' || last_name) ILIKE %s) ORDER BY last_name,first_name",
        ("%" + q[:80] + "%",) * 2,
    ).fetchall()
    return [public(row) for row in rows]


@app.get("/api/chats")
def chats(user=Depends(current_user), conn=Depends(connection)):
    rows = conn.execute(
        "SELECT c.*,m.is_admin FROM chats c JOIN members m ON m.chat_id=c.id WHERE m.user_id=%s ORDER BY c.id DESC",
        (user["id"],),
    ).fetchall()
    for row in rows:
        row["members"] = conn.execute(
            "SELECT u.id,u.login,u.first_name,u.last_name,u.public_key,u.last_seen,u.blocked,u.deleted,m.is_admin FROM users u JOIN members m ON u.id=m.user_id WHERE m.chat_id=%s ORDER BY u.id",
            (row["id"],),
        ).fetchall()
    return rows


@app.post("/api/chats")
def create_chat(body: Chat, user=Depends(current_user), conn=Depends(connection)):
    ids = sorted(set(body.user_ids + [user["id"]]))
    if not 2 <= len(ids) <= 10 or (not body.is_group and len(ids) != 2):
        raise HTTPException(400, "Личный чат: 2 участника; группа: от 2 до 10")
    if conn.execute(
        "SELECT count(*) AS n FROM users WHERE id=ANY(%s) AND NOT blocked AND NOT deleted AND public_key IS NOT NULL",
        (ids,),
    ).fetchone()["n"] != len(ids):
        raise HTTPException(400, "Участники должны войти и создать ключи шифрования")
    if not body.is_group:
        # Сериализация создания личного чата для пары пользователей.
        conn.execute("SELECT pg_advisory_xact_lock(%s,%s)", (ids[0], ids[1]))
        old = conn.execute(
            "SELECT c.id FROM chats c JOIN members m ON m.chat_id=c.id WHERE NOT c.is_group GROUP BY c.id HAVING array_agg(m.user_id ORDER BY m.user_id)=%s::integer[]",
            (ids,),
        ).fetchone()
        if old:
            return old
    row = conn.execute(
        "INSERT INTO chats(title,is_group) VALUES (%s,%s) RETURNING id", (body.title, body.is_group)
    ).fetchone()
    for uid in ids:
        conn.execute("INSERT INTO members VALUES (%s,%s,%s)", (row["id"], uid, uid == user["id"]))
    return row


@app.post("/api/chats/{chat_id}/members")
def change_members(
    chat_id: int, body: Member, user=Depends(current_user), conn=Depends(connection)
):
    member_of(conn, chat_id, user, admin=True, lock=True)
    members = conn.execute("SELECT * FROM members WHERE chat_id=%s", (chat_id,)).fetchall()
    target = next((m for m in members if m["user_id"] == body.user_id), None)
    if body.action == "add":
        if target:
            raise HTTPException(409, "Пользователь уже в группе")
        if len(members) >= 10:
            raise HTTPException(400, "В группе не более 10 участников")
        if not conn.execute(
            "SELECT id FROM users WHERE id=%s AND NOT blocked AND NOT deleted AND public_key IS NOT NULL",
            (body.user_id,),
        ).fetchone():
            raise HTTPException(400, "Пользователь недоступен или ещё не создал ключи")
        conn.execute("INSERT INTO members VALUES (%s,%s,FALSE)", (chat_id, body.user_id))
    else:
        if not target:
            raise HTTPException(404, "Участник не найден")
        if (
            body.action in ("remove", "demote")
            and target["is_admin"]
            and sum(m["is_admin"] for m in members) == 1
        ):
            raise HTTPException(400, "Сначала назначьте другого администратора группы")
        if body.action == "remove":
            conn.execute(
                "DELETE FROM members WHERE chat_id=%s AND user_id=%s", (chat_id, body.user_id)
            )
        else:
            conn.execute(
                "UPDATE members SET is_admin=%s WHERE chat_id=%s AND user_id=%s",
                (body.action == "promote", chat_id, body.user_id),
            )
    conn.execute("UPDATE chats SET revision=revision+1 WHERE id=%s", (chat_id,))
    audit(conn, user["id"], "group_" + body.action, body.user_id)
    return {"ok": True}


@app.get("/api/chats/{chat_id}/messages")
def messages(
    chat_id: int,
    before: datetime | None = None,
    user=Depends(current_user),
    conn=Depends(connection),
):
    member_of(conn, chat_id, user)
    rows = conn.execute(
        "SELECT * FROM messages WHERE chat_id=%s AND (%s::timestamptz IS NULL OR created_at<%s) ORDER BY created_at DESC LIMIT 100",
        (chat_id, before, before),
    ).fetchall()
    for row in rows:
        row["receipts"] = conn.execute(
            "SELECT user_id,delivered_at,read_at FROM receipts WHERE message_id=%s", (row["id"],)
        ).fetchall()
    return list(reversed(rows))


@app.post("/api/chats/{chat_id}/messages")
def send(chat_id: int, body: Packet, user=Depends(current_user), conn=Depends(connection)):
    chat = member_of(conn, chat_id, user, lock=True)
    old = conn.execute(
        "SELECT id,chat_id,sender_id FROM messages WHERE id=%s", (body.id,)
    ).fetchone()
    if old:
        if old["sender_id"] != user["id"] or old["chat_id"] != chat_id:
            raise HTTPException(409, "Идентификатор сообщения уже используется")
        return {"id": str(old["id"])}
    if chat["revision"] != body.revision:
        raise HTTPException(409, "Состав группы изменился. Обновите чат и отправьте снова.")
    p = body.payload
    if set(p) != {"iv", "data", "keys"} or not isinstance(p["keys"], dict):
        raise HTTPException(400, "Некорректный зашифрованный пакет")
    b64(p["iv"], 12, 12)
    b64(p["data"], 16, 11_300_000)
    ids = {
        str(m["user_id"])
        for m in conn.execute("SELECT user_id FROM members WHERE chat_id=%s", (chat_id,)).fetchall()
    }
    if set(p["keys"]) != ids:
        raise HTTPException(400, "Пакет должен содержать ключ для каждого участника")
    for value in p["keys"].values():
        b64(value, 256, 256)
    if (
        body.reply_to
        and not conn.execute(
            "SELECT id FROM messages WHERE id=%s AND chat_id=%s", (body.reply_to, chat_id)
        ).fetchone()
    ):
        raise HTTPException(400, "Ответ должен относиться к сообщению этого чата")
    conn.execute(
        "INSERT INTO messages(id,chat_id,sender_id,payload,reply_to) VALUES (%s,%s,%s,%s,%s)",
        (body.id, chat_id, user["id"], Jsonb(p), body.reply_to),
    )
    return {"id": str(body.id)}


@app.post("/api/chats/{chat_id}/receipts")
def receipts(chat_id: int, body: Receipt, user=Depends(current_user), conn=Depends(connection)):
    member_of(conn, chat_id, user)
    for mid in body.ids:
        row = conn.execute(
            "SELECT * FROM messages WHERE id=%s AND chat_id=%s", (mid, chat_id)
        ).fetchone()
        if (
            row
            and not row["deleted"]
            and row["sender_id"] != user["id"]
            and str(user["id"]) in row["payload"]["keys"]
        ):
            conn.execute(
                "INSERT INTO receipts(message_id,user_id,read_at) VALUES (%s,%s,%s) ON CONFLICT(message_id,user_id) DO UPDATE SET read_at=COALESCE(receipts.read_at,EXCLUDED.read_at)",
                (mid, user["id"], datetime.now(timezone.utc) if body.read else None),
            )
    return {"ok": True}


@app.delete("/api/messages/{message_id}")
def delete_message(message_id: UUID, user=Depends(current_user), conn=Depends(connection)):
    row = conn.execute("SELECT * FROM messages WHERE id=%s", (message_id,)).fetchone()
    if not row or row["sender_id"] != user["id"]:
        raise HTTPException(403, "Можно удалить только своё сообщение")
    member_of(conn, row["chat_id"], user)
    conn.execute("UPDATE messages SET deleted=TRUE,payload=NULL WHERE id=%s", (message_id,))
    return {"ok": True}


@app.get("/api/admin/users")
def admin_users(user=Depends(administrator), conn=Depends(connection)):
    return [public(row) for row in conn.execute("SELECT * FROM users ORDER BY id").fetchall()]


@app.post("/api/admin/users")
def create_user(body: Account, user=Depends(administrator), conn=Depends(connection)):
    validate_password(body.password)
    try:
        row = conn.execute(
            "INSERT INTO users(login,first_name,last_name,password_hash,role) VALUES (%s,%s,%s,%s,%s) RETURNING id",
            (
                body.login.lower(),
                body.first_name.strip(),
                body.last_name.strip(),
                hash_password(body.password),
                body.role,
            ),
        ).fetchone()
    except UniqueViolation:
        raise HTTPException(409, "Этот логин уже занят")
    audit(conn, user["id"], "account_created", row["id"])
    return row


@app.put("/api/admin/users/{uid}")
def edit_user(uid: int, body: Account, user=Depends(administrator), conn=Depends(connection)):
    # Одна блокировка на административные изменения предотвращает потерю последнего администратора.
    conn.execute("SELECT pg_advisory_xact_lock(987654)")
    target = conn.execute(
        "SELECT * FROM users WHERE id=%s AND NOT deleted FOR UPDATE", (uid,)
    ).fetchone()
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if uid == user["id"] and body.role != "admin":
        raise HTTPException(400, "Нельзя снять собственные права администратора")
    try:
        conn.execute(
            "UPDATE users SET login=%s,first_name=%s,last_name=%s,role=%s,token_version=token_version+1 WHERE id=%s",
            (body.login.lower(), body.first_name.strip(), body.last_name.strip(), body.role, uid),
        )
    except UniqueViolation:
        raise HTTPException(409, "Этот логин уже занят")
    audit(conn, user["id"], "account_edited", uid)
    return {"ok": True}


@app.post("/api/admin/users/{uid}/action")
def user_action(uid: int, body: Action, user=Depends(administrator), conn=Depends(connection)):
    if body.action not in ("block", "unblock", "delete", "revoke", "reset_password"):
        raise HTTPException(400, "Неизвестное действие")
    conn.execute("SELECT pg_advisory_xact_lock(987654)")
    target = conn.execute(
        "SELECT * FROM users WHERE id=%s AND NOT deleted FOR UPDATE", (uid,)
    ).fetchone()
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if uid == user["id"] and body.action in ("block", "delete"):
        raise HTTPException(400, "Нельзя заблокировать или удалить себя")
    if (
        body.action in ("block", "delete")
        and conn.execute(
            "SELECT 1 FROM members m JOIN chats c ON c.id=m.chat_id WHERE m.user_id=%s AND m.is_admin AND c.is_group AND NOT EXISTS (SELECT 1 FROM members x JOIN users u ON u.id=x.user_id WHERE x.chat_id=m.chat_id AND x.is_admin AND x.user_id<>%s AND NOT u.blocked AND NOT u.deleted)",
            (uid, uid),
        ).fetchone()
    ):
        raise HTTPException(
            400, "Пользователь — единственный активный администратор группы. Назначьте другого."
        )
    if body.action == "reset_password":
        validate_password(body.password)
        conn.execute(
            "UPDATE users SET password_hash=%s,failures=0,locked_until=NULL WHERE id=%s",
            (hash_password(body.password), uid),
        )
    if body.action == "unblock":
        conn.execute(
            "UPDATE users SET blocked=FALSE,failures=0,locked_until=NULL WHERE id=%s", (uid,)
        )
    if body.action == "block":
        conn.execute("UPDATE users SET blocked=TRUE WHERE id=%s", (uid,))
    if body.action == "delete":
        conn.execute("UPDATE users SET deleted=TRUE,blocked=TRUE WHERE id=%s", (uid,))
        group_ids = [
            r["chat_id"]
            for r in conn.execute("SELECT chat_id FROM members WHERE user_id=%s", (uid,)).fetchall()
        ]
        conn.execute("DELETE FROM members WHERE user_id=%s", (uid,))
        conn.execute("UPDATE chats SET revision=revision+1 WHERE id=ANY(%s)", (group_ids,))
    conn.execute(
        "UPDATE users SET token_version=token_version+1,last_seen=NULL WHERE id=%s", (uid,)
    )
    conn.execute("DELETE FROM sessions WHERE user_id=%s", (uid,))
    audit(conn, user["id"], "account_" + body.action, uid)
    return {"ok": True}


@app.get("/api/admin/audit")
def audit_log(user=Depends(administrator), conn=Depends(connection)):
    return conn.execute(
        "SELECT a.*,u.login FROM audit a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 300"
    ).fetchall()


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
