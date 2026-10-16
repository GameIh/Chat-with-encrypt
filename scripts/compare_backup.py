"""Сравнение всех строк рабочей БД и отдельной БД, восстановленной из копии."""

import hashlib
import json
import os
import psycopg

url = os.environ["DATABASE_URL"]
restored = url.rsplit("/", 1)[0] + "/messenger_restore_check"
report = {}
with psycopg.connect(url) as source, psycopg.connect(restored) as target:
    for table in ["users", "sessions", "chats", "members", "messages", "receipts", "audit"]:

        def digest(conn):
            rows = conn.execute(f"SELECT row_to_json(t) FROM {table} t").fetchall()
            text = "\n".join(
                sorted(json.dumps(row[0], sort_keys=True, ensure_ascii=False) for row in rows)
            )
            return len(rows), hashlib.sha256(text.encode()).hexdigest()

        original = digest(source)
        copy = digest(target)
        assert original == copy, f"Mismatch: {table}"
        report[table] = {"rows": original[0], "sha256": original[1]}
print(json.dumps({"passed": True, "tables": report}, ensure_ascii=False, indent=2))
