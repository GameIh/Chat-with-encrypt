"""500 отдельных авторизованных HTTP-клиентов на изолированной тестовой БД.

Запуск внутри app: DATABASE_URL=.../messenger_test python -m scripts.load_test
"""

import asyncio
import json
import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import httpx
import jwt
import psycopg
from app.security import hash_password

assert os.environ["DATABASE_URL"].endswith("/messenger_test")
COUNT = 500


async def run():
    password = hash_password("LoadTest123")
    tokens = []
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        for i in range(COUNT):
            uid = conn.execute(
                "INSERT INTO users(login,first_name,last_name,password_hash,role) VALUES (%s,'Нагрузочный','Пользователь',%s,'user') RETURNING id",
                ("load_" + uuid4().hex, password),
            ).fetchone()[0]
            sid = str(uuid4())
            expires = datetime.now(timezone.utc) + timedelta(minutes=15)
            conn.execute("INSERT INTO sessions VALUES (%s,%s,%s)", (sid, uid, expires))
            tokens.append(
                jwt.encode(
                    {"sub": str(uid), "jti": sid, "ver": 0, "exp": expires},
                    os.environ["JWT_SECRET"],
                    algorithm="HS256",
                )
            )
    clients = [
        httpx.AsyncClient(
            base_url="http://localhost:9080",
            headers={"Authorization": "Bearer " + token},
            timeout=30,
        )
        for token in tokens
    ]
    times = []
    errors = []

    async def user(client):
        # Три цикла запросов списка чатов с паузой, как при polling в браузере.
        for _ in range(3):
            started = time.perf_counter()
            try:
                response = await client.get("/api/chats")
                if response.status_code != 200:
                    errors.append(response.status_code)
                times.append((time.perf_counter() - started) * 1000)
            except Exception as error:
                errors.append(type(error).__name__)
            await asyncio.sleep(1)

    started = time.perf_counter()
    await asyncio.gather(*(user(c) for c in clients))
    await asyncio.gather(*(c.aclose() for c in clients))
    ordered = sorted(times)
    print(
        json.dumps(
            {
                "users": COUNT,
                "requests": len(times),
                "errors": errors,
                "duration_seconds": round(time.perf_counter() - started, 2),
                "p50_ms": round(ordered[len(ordered) // 2], 1),
                "p95_ms": round(ordered[int(len(ordered) * 0.95)], 1),
                "max_ms": round(max(times), 1),
                "scope": "authenticated chat polling; no browser cryptography or file load",
            },
            ensure_ascii=False,
        )
    )
    assert not errors


if __name__ == "__main__":
    server = subprocess.Popen(
        [
            "python",
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "9080",
            "--no-access-log",
        ]
    )
    try:
        for _ in range(40):
            try:
                if httpx.get("http://localhost:9080/api/health").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        asyncio.run(run())
    finally:
        server.terminate()
        server.wait(timeout=15)
