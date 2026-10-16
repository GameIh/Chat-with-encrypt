"""Интеграционные проверки на отдельной PostgreSQL БД messenger_test."""

import base64
import os
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from app.main import app
from app.db import pool


def encoded(n):
    return base64.b64encode(os.urandom(n)).decode()


@pytest.fixture(scope="module")
def client():
    assert os.environ["DATABASE_URL"].endswith(
        "/messenger_test"
    ), "Tests require a separate database"
    with TestClient(app) as client:
        yield client


def login(client, login="admin", password=None):
    response = client.post(
        "/api/login", json={"login": login, "password": password or os.environ["ADMIN_PASSWORD"]}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["token"]}, response.json()


def account(client, admin, label):
    name = label + uuid4().hex[:8]
    result = client.post(
        "/api/admin/users",
        headers=admin,
        json={"login": name, "first_name": label, "last_name": "Тест", "password": "Password123"},
    )
    assert result.status_code == 200, result.text
    headers, data = login(client, name, "Password123")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    pub = {
        "kty": "RSA",
        "e": "AQAB",
        "n": base64.urlsafe_b64encode(numbers.n.to_bytes(256, "big")).decode().rstrip("="),
    }
    vault = {"salt": encoded(16), "iv": encoded(12), "data": encoded(1300)}
    response = client.put("/api/keys", headers=headers, json={"public_key": pub, "vault": vault})
    assert response.status_code == 200, response.text
    return result.json()["id"], headers, name, key


def group(client, admin):
    a = account(client, admin, "alice")
    b = account(client, admin, "bob")
    response = client.post(
        "/api/chats",
        headers=a[1],
        json={"title": "Тестовая группа", "is_group": True, "user_ids": [b[0]]},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"], a, b


def packet(a, b):
    return {
        "id": str(uuid4()),
        "revision": 1,
        "payload": {
            "iv": encoded(12),
            "data": encoded(50),
            "keys": {str(a[0]): encoded(256), str(b[0]): encoded(256)},
        },
    }


def test_unauthorized_and_role(client):
    assert client.get("/api/users").status_code == 401
    admin, _ = login(client)
    user = account(client, admin, "role")
    assert client.get("/api/admin/users", headers=user[1]).status_code == 403
    assert client.get("/api/admin/audit", headers=user[1]).status_code == 403


def test_password_policy_unique_and_hash(client):
    admin, _ = login(client)
    body = {"login": "invalid", "first_name": "Тест", "last_name": "Тест", "password": "12345678"}
    assert client.post("/api/admin/users", headers=admin, json=body).status_code == 400
    u = account(client, admin, "unique")
    body.update(login=u[2], password="Password123")
    assert client.post("/api/admin/users", headers=admin, json=body).status_code == 409
    with pool.connection() as conn:
        record = conn.execute("SELECT * FROM users WHERE id=%s", (u[0],)).fetchone()
        assert "Password123" not in record["password_hash"]
        assert record["vault"]["data"]


def test_three_failures_lock_five_minutes(client):
    admin, _ = login(client)
    u = account(client, admin, "locked")
    for _ in range(3):
        assert (
            client.post("/api/login", json={"login": u[2], "password": "wrong"}).status_code == 401
        )
    assert (
        client.post("/api/login", json={"login": u[2], "password": "Password123"}).status_code
        == 429
    )
    with pool.connection() as conn:
        seconds = conn.execute(
            "SELECT EXTRACT(EPOCH FROM locked_until-now()) AS seconds FROM users WHERE id=%s",
            (u[0],),
        ).fetchone()["seconds"]
        assert 290 < float(seconds) <= 300
        conn.execute("UPDATE users SET locked_until=now()-interval '1 second' WHERE id=%s", (u[0],))
    login(client, u[2], "Password123")


def test_message_isolation_dedup_delete_receipts(client):
    admin, _ = login(client)
    cid, a, b = group(client, admin)
    outsider = account(client, admin, "outside")
    data = packet(a, b)
    assert client.post(f"/api/chats/{cid}/messages", headers=a[1], json=data).status_code == 200
    assert client.post(f"/api/chats/{cid}/messages", headers=a[1], json=data).status_code == 200
    assert client.get(f"/api/chats/{cid}/messages", headers=outsider[1]).status_code == 403
    rows = client.get(f"/api/chats/{cid}/messages", headers=b[1]).json()
    assert len(rows) == 1
    assert (
        client.post(
            f"/api/chats/{cid}/receipts", headers=b[1], json={"ids": [data["id"]], "read": True}
        ).status_code
        == 200
    )
    assert client.get(f"/api/chats/{cid}/messages", headers=a[1]).json()[0]["receipts"][0][
        "read_at"
    ]
    assert client.delete("/api/messages/" + data["id"], headers=b[1]).status_code == 403
    assert client.delete("/api/messages/" + data["id"], headers=a[1]).status_code == 200
    row = client.get(f"/api/chats/{cid}/messages", headers=b[1]).json()[0]
    assert row["deleted"] and row["payload"] is None


def test_group_permissions_membership_and_stale_packet(client):
    admin, _ = login(client)
    cid, a, b = group(client, admin)
    c = account(client, admin, "carol")
    action = {"user_id": c[0], "action": "add"}
    assert client.post(f"/api/chats/{cid}/members", headers=b[1], json=action).status_code == 403
    assert client.post(f"/api/chats/{cid}/members", headers=a[1], json=action).status_code == 200
    assert (
        client.post(f"/api/chats/{cid}/messages", headers=a[1], json=packet(a, b)).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/chats/{cid}/members", headers=a[1], json={"user_id": a[0], "action": "remove"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/chats/{cid}/members", headers=a[1], json={"user_id": b[0], "action": "promote"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/chats/{cid}/members", headers=b[1], json={"user_id": a[0], "action": "remove"}
        ).status_code
        == 200
    )
    assert client.get(f"/api/chats/{cid}/messages", headers=a[1]).status_code == 403


def test_revoke_block_reset_do_not_change_keys(client):
    admin, _ = login(client)
    u = account(client, admin, "reset")
    with pool.connection() as conn:
        before = conn.execute("SELECT public_key,vault FROM users WHERE id=%s", (u[0],)).fetchone()
    for action in ["revoke", "block"]:
        assert (
            client.post(
                f"/api/admin/users/{u[0]}/action", headers=admin, json={"action": action}
            ).status_code
            == 200
        )
        assert client.get("/api/me", headers=u[1]).status_code == 401
    assert (
        client.post(
            f"/api/admin/users/{u[0]}/action", headers=admin, json={"action": "unblock"}
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/api/admin/users/{u[0]}/action",
            headers=admin,
            json={"action": "reset_password", "password": "NewPassword123"},
        ).status_code
        == 200
    )
    login(client, u[2], "NewPassword123")
    with pool.connection() as conn:
        after = conn.execute("SELECT public_key,vault FROM users WHERE id=%s", (u[0],)).fetchone()
    assert before == after


def test_reply_must_be_same_chat(client):
    admin, _ = login(client)
    cid, a, b = group(client, admin)
    other, _, _ = group(client, admin)
    data = packet(a, b)
    data["reply_to"] = str(uuid4())
    assert client.post(f"/api/chats/{cid}/messages", headers=a[1], json=data).status_code == 400


def test_deleted_user_cannot_login(client):
    admin, _ = login(client)
    u = account(client, admin, "deleted")
    assert (
        client.post(
            f"/api/admin/users/{u[0]}/action", headers=admin, json={"action": "delete"}
        ).status_code
        == 200
    )
    assert (
        client.post("/api/login", json={"login": u[2], "password": "Password123"}).status_code
        == 401
    )


def test_direct_chat_reused_and_key_overwrite_forbidden(client):
    admin, _ = login(client)
    a = account(client, admin, "direct")
    b = account(client, admin, "directb")
    body = {"title": "Личный", "user_ids": [b[0]]}
    first = client.post("/api/chats", headers=a[1], json=body).json()
    assert first == client.post("/api/chats", headers=a[1], json=body).json()
    with pool.connection() as conn:
        data = conn.execute("SELECT public_key,vault FROM users WHERE id=%s", (a[0],)).fetchone()
    assert client.put("/api/keys", headers=a[1], json=data).status_code == 409


def test_crypto_round_trip_and_tamper_detection(client):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidTag

    admin, _ = login(client)
    cid, a, b = group(client, admin)
    secret = "Секретное сообщение — только участникам".encode()
    key = AESGCM.generate_key(256)
    iv = os.urandom(12)
    mid = str(uuid4())
    aad = f"{cid}|{mid}|{a[0]}|".encode()
    data = AESGCM(key).encrypt(iv, secret, aad)
    keys = {
        str(u[0]): base64.b64encode(
            u[3]
            .public_key()
            .encrypt(
                key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
                ),
            )
        ).decode()
        for u in [a, b]
    }
    body = {
        "id": mid,
        "revision": 1,
        "payload": {
            "iv": base64.b64encode(iv).decode(),
            "data": base64.b64encode(data).decode(),
            "keys": keys,
        },
    }
    assert client.post(f"/api/chats/{cid}/messages", headers=a[1], json=body).status_code == 200
    received = client.get(f"/api/chats/{cid}/messages", headers=b[1]).json()[0]["payload"]
    raw = b[3].decrypt(
        base64.b64decode(received["keys"][str(b[0])]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    assert AESGCM(raw).decrypt(iv, base64.b64decode(received["data"]), aad) == secret
    with pytest.raises(InvalidTag):
        AESGCM(raw).decrypt(iv, data[:-1] + bytes([data[-1] ^ 1]), aad)
    with pool.connection() as conn:
        assert secret.decode() not in str(
            conn.execute("SELECT * FROM messages WHERE id=%s", (mid,)).fetchone()
        )
        assert secret.decode() not in str(conn.execute("SELECT * FROM audit").fetchall())


def test_group_size_limit_and_no_missing_recipient(client):
    admin, _ = login(client)
    owner = account(client, admin, "owner")
    others = [account(client, admin, "member") for _ in range(10)]
    response = client.post(
        "/api/chats",
        headers=owner[1],
        json={"title": "10 участников", "is_group": True, "user_ids": [u[0] for u in others[:9]]},
    )
    assert response.status_code == 200
    cid = response.json()["id"]
    assert (
        client.post(
            f"/api/chats/{cid}/members",
            headers=owner[1],
            json={"user_id": others[9][0], "action": "add"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/chats/{cid}/messages", headers=owner[1], json=packet(owner, others[0])
        ).status_code
        == 400
    )


def test_logout_invalidates_token_and_private_jwk_rejected(client):
    admin, _ = login(client)
    u = account(client, admin, "logout")
    with pool.connection() as conn:
        data = conn.execute("SELECT public_key,vault FROM users WHERE id=%s", (u[0],)).fetchone()
    data["public_key"]["d"] = "private-key-not-allowed"
    assert client.put("/api/keys", headers=u[1], json=data).status_code == 400
    assert client.post("/api/logout", headers=u[1]).status_code == 200
    assert client.get("/api/chats", headers=u[1]).status_code == 401
