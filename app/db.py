import os
import asyncio
from pathlib import Path
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

pool = ConnectionPool(
    os.environ["DATABASE_URL"],
    min_size=2,
    max_size=20,
    open=False,
    kwargs={"row_factory": dict_row},
)
slots = asyncio.Semaphore(20)


async def connection():
    # Ожидаем свободное соединение асинхронно, не занимая потоки обработчиков API.
    async with slots:
        conn = await asyncio.to_thread(pool.getconn)
        try:
            yield conn
        except BaseException:
            await asyncio.to_thread(conn.rollback)
            raise
        else:
            await asyncio.to_thread(conn.commit)
        finally:
            pool.putconn(conn)


def initialize():
    pool.open(wait=True)
    with pool.connection() as conn:
        conn.execute(Path(__file__).with_name("schema.sql").read_text())


def audit(conn, actor, event, target=None):
    conn.execute(
        "INSERT INTO audit(actor_id,event,target_id) VALUES (%s,%s,%s)", (actor, event, target)
    )
