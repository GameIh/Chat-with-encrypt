"""Добавляет учебные данные через API, не очищая существующую базу.

Запуск: docker compose exec -T app python -m scripts.seed_demo
Шифрование выполняет этот клиентский скрипт, сервер получает только пакеты.
"""

import base64
import json
import os
from uuid import NAMESPACE_URL, uuid5

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PASSWORD = "DemoPass2026"
PHRASE = "Демонстрационная фраза 2026"
PEOPLE = {
    "anna": ("Анна", "Смирнова"),
    "mikhail": ("Михаил", "Орлов"),
    "elena": ("Елена", "Волкова"),
    "dmitry": ("Дмитрий", "Соколов"),
    "olga": ("Ольга", "Кузнецова"),
}


def b64(data):
    return base64.b64encode(data).decode()


def phrase_key(salt):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(
        PHRASE.encode()
    )


def public_jwk(key):
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "e": "AQAB",
        "n": base64.urlsafe_b64encode(numbers.n.to_bytes(256, "big")).decode().rstrip("="),
    }


def oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def encrypt(content, members, chat_id, mid, sender_id, reply):
    key, iv = AESGCM.generate_key(256), os.urandom(12)
    aad = f'{chat_id}|{mid}|{sender_id}|{reply or ""}'.encode()
    data = AESGCM(key).encrypt(iv, json.dumps(content, ensure_ascii=False).encode(), aad)
    keys = {}
    for member in members:
        jwk = member["public_key"]
        n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=="), "big")
        public = rsa.RSAPublicNumbers(65537, n).public_key()
        keys[str(member["id"])] = b64(public.encrypt(key, oaep()))
    return {"iv": b64(iv), "data": b64(data), "keys": keys}


def message(who, text, reply=None, file=None, state="read", delete=False):
    return {
        "who": who,
        "content": {"text": text, **({"file": file} if file else {})},
        "reply": reply,
        "state": state,
        "delete": delete,
    }


def attachment(name, text):
    return {"name": name, "data": b64(text.encode("utf-8"))}


PLAN = attachment(
    "План демонстрации.txt",
    "План демонстрации мессенджера\n\n1. Вход и открытие переписки.\n2. Личное сообщение и ответ.\n3. Передача файла.\n4. Групповой чат и управление участниками.\n5. Блокировка пользователя и журнал событий.\n6. Резервная копия базы данных.\n",
)
CHECKLIST = attachment(
    "Проверки.csv",
    "Сценарий;Результат\nВход;Пройден\nЛичное сообщение;Пройден\nФайл;Пройден\nГруппа;Пройден\nОтзыв сеанса;Пройден\n",
)
DIAGRAM = attachment(
    "Схема обмена.svg",
    '<svg xmlns="http://www.w3.org/2000/svg" width="720" height="220" viewBox="0 0 720 220"><rect width="720" height="220" fill="#f8f7f4"/><g fill="#ece9e1" stroke="#aaa598"><rect x="30" y="65" width="180" height="90" rx="8"/><rect x="270" y="65" width="180" height="90" rx="8"/><rect x="510" y="65" width="180" height="90" rx="8"/></g><g font-family="Arial" font-size="18" fill="#333" text-anchor="middle"><text x="120" y="102">Отправитель</text><text x="120" y="130" font-size="13">Шифрование</text><text x="360" y="102">Сервер</text><text x="360" y="130" font-size="13">Зашифрованный пакет</text><text x="600" y="102">Получатель</text><text x="600" y="130" font-size="13">Расшифрование</text></g><path d="M218 110h42m-9-6 9 6-9 6M458 110h42m-9-6 9 6-9 6" fill="none" stroke="#666" stroke-width="2"/></svg>',
)

SCENARIOS = [
    (
        "Личный: Анна и администратор",
        False,
        ["admin", "anna"],
        [
            message(
                "anna",
                "Добрый день! Готовим демонстрацию курсового проекта. Учётные записи для команды уже можно использовать?",
            ),
            message(
                "admin",
                "Да, все пять участников добавлены. При первом входе нужно открыть переписку секретной фразой.",
            ),
            message("anna", "Я вошла, контакты отображаются. Создам группу для подготовки."),
            message(
                "admin", "Хорошо. Если кому-то потребуется сброс пароля входа, обращайтесь ко мне."
            ),
            message("anna", "А секретная фраза после сброса пароля останется прежней?", reply=3),
            message(
                "admin",
                "Да. Сброс пароля не меняет ключи и не даёт администратору доступа к личной переписке.",
                reply=4,
            ),
            message("anna", "Спасибо, добавлю это в пояснение к демонстрации."),
            message("admin", "План проверки во вложении.", file=PLAN),
        ],
    ),
    (
        "Личный: Анна и Михаил",
        False,
        ["anna", "mikhail"],
        [
            message(
                "anna", "Миша, посмотри, пожалуйста, отправку сообщений между двумя браузерами."
            ),
            message("mikhail", "Открыл второй профиль. Сообщение пришло."),
            message("anna", "Проверим ответ на выбранное сообщение."),
            message("mikhail", "Отвечаю на него — ссылка на исходное сообщение видна.", reply=2),
            message("anna", "Отлично. Файл тоже скачивается?"),
            message(
                "mikhail", "Да, содержимое совпало. Сохранил результаты проверок.", file=CHECKLIST
            ),
            message("anna", "Спасибо! На защите покажем этот диалог."),
        ],
    ),
    (
        "Личный: Анна и Елена",
        False,
        ["anna", "elena"],
        [
            message("elena", "Анна, как лучше показать шифрование на схеме?"),
            message(
                "anna",
                "Отдельно браузер отправителя, сервер и браузер получателя. На сервере только зашифрованный пакет.",
            ),
            message("elena", "Подготовила простую схему. Проверь подписи.", file=DIAGRAM),
            message("anna", "Всё понятно. Добавь её в материалы к выступлению.", reply=2),
            message("elena", "Хорошо, займусь оформлением."),
            message("anna", "Когда будет готово, напиши в общую группу.", state="delivered"),
        ],
    ),
    (
        "Личный: Анна и Дмитрий",
        False,
        ["anna", "dmitry"],
        [
            message("anna", "Дима, база после перезапуска контейнеров сохранилась?"),
            message("dmitry", "Да. Пользователи и история остались на месте."),
            message("anna", "А резервную копию проверяли восстановлением?"),
            message(
                "dmitry", "Восстановили в отдельную базу и сравнили таблицы. Результат совпал."
            ),
            message("anna", "Принято. Для демонстрации нужен только небольшой набор данных."),
            message("dmitry", "Подготовлю список команд запуска и резервирования."),
            message("anna", "Не забудь указать, что обычная остановка Docker сохраняет базу."),
            message("dmitry", "Добавлю это в инструкцию.", state="sent"),
        ],
    ),
    (
        "Разработка мессенджера",
        True,
        ["anna", "mikhail", "elena", "dmitry", "olga", "admin"],
        [
            message("anna", "Коллеги, здесь обсуждаем подготовку проекта к показу."),
            message("mikhail", "Личные сообщения, ответы и передача файлов работают."),
            message(
                "elena",
                "Проверила интерфейс на телефоне. Из переписки можно вернуться к списку чатов.",
            ),
            message("dmitry", "Приложение и PostgreSQL запущены в Docker."),
            message("olga", "Возьму на себя проверку прав пользователей и журнала событий."),
            message("anna", "Михаил, назначу тебя вторым администратором этой группы."),
            message("mikhail", "Хорошо. Покажем добавление участника и смену прав."),
            message("elena", "Схему обмена добавила в личный чат с Анной."),
            message("anna", "Спасибо всем. Вопросы для защиты собираем в отдельной группе."),
            message(
                "admin",
                "Учётная запись demo_archive заблокирована специально для показа административной панели.",
                state="delivered",
            ),
        ],
    ),
    (
        "Подготовка к защите",
        True,
        ["anna", "mikhail", "elena", "dmitry", "olga", "admin"],
        [
            message(
                "anna",
                "Предлагаю такой порядок: вход, личный чат, файл, группа, административная панель.",
            ),
            message("olga", "После входа объясним, чем пароль отличается от секретной фразы."),
            message(
                "mikhail",
                "Затем отправлю сообщение из второго окна, чтобы показать доставку и прочтение.",
            ),
            message("elena", "На каком сообщении покажем удаление?"),
            message(
                "anna", "Это сообщение можно удалить — оно оставлено для демонстрации.", delete=True
            ),
            message(
                "anna", "Уже удалила пробное сообщение. Вместо текста осталась отметка об удалении."
            ),
            message("dmitry", "В конце покажу состояние контейнеров и резервную копию."),
            message("anna", "Итоговый план прикрепляю сюда.", file=PLAN),
        ],
    ),
    (
        "Объявления",
        True,
        ["admin", "anna", "mikhail", "elena", "dmitry", "olga"],
        [
            message("admin", "Этот чат предназначен для организационных сообщений команды."),
            message(
                "admin",
                "Для демонстрации созданы пять учебных аккаунтов. Настоящие персональные данные в них не используются.",
            ),
            message("olga", "Учётные записи проверила, вход работает."),
            message(
                "admin",
                "Если забыли пароль входа, обратитесь к администратору. Секретную фразу храните отдельно.",
            ),
            message("anna", "Инструкцию передала участникам."),
            message(
                "admin",
                "Перед демонстрацией откройте мессенджер в двух отдельных профилях браузера.",
                state="sent",
            ),
        ],
    ),
]


def main():
    # Self-signed TLS is accepted only for the local Docker demo endpoint.
    with httpx.Client(base_url="https://localhost:8443", verify=False, timeout=30) as client:
        sessions = {}
        private_keys = {}

        def api(path, who="admin", method="GET", data=None):
            response = client.request(
                method,
                "/api" + path,
                json=data,
                headers=(
                    {"Authorization": "Bearer " + sessions[who]["token"]} if who in sessions else {}
                ),
            )
            if response.is_error:
                raise RuntimeError(
                    f'{method} {path}: {response.status_code} {response.json().get("detail")}'
                )
            return response.json()

        def history(chat_id, who):
            rows = {}
            before = ""
            while True:
                page = api(f"/chats/{chat_id}/messages{before}", who)
                rows.update((row["id"], row) for row in page)
                if len(page) < 100:
                    return rows
                before = (
                    "?before="
                    + str(httpx.QueryParams({"before": page[0]["created_at"]})).split("=", 1)[1]
                )

        sessions["admin"] = api(
            "/login",
            method="POST",
            data={"login": "admin", "password": os.environ["ADMIN_PASSWORD"]},
        )
        try:
            if not sessions["admin"]["user"]["public_key"]:
                raise RuntimeError("Сначала войдите как admin и создайте ключи в браузере.")
            existing = {u["login"]: u for u in api("/admin/users")}
            for short, (first, last) in PEOPLE.items():
                login = "demo_" + short
                if login not in existing:
                    api(
                        "/admin/users",
                        method="POST",
                        data={
                            "login": login,
                            "first_name": first,
                            "last_name": last,
                            "password": PASSWORD,
                        },
                    )
                elif existing[login]["blocked"] or existing[login]["deleted"]:
                    raise RuntimeError(
                        f"{login} заблокирован или удалён. Его состояние не изменено."
                    )
                sessions[short] = api(
                    "/login", who=short, method="POST", data={"login": login, "password": PASSWORD}
                )
                vault = sessions[short]["vault"]
                if vault:
                    raw = AESGCM(phrase_key(base64.b64decode(vault["salt"]))).decrypt(
                        base64.b64decode(vault["iv"]), base64.b64decode(vault["data"]), None
                    )
                    private = serialization.load_der_private_key(raw, password=None)
                else:
                    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    salt, iv = os.urandom(16), os.urandom(12)
                    raw = private.private_bytes(
                        serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                    vault = {
                        "salt": b64(salt),
                        "iv": b64(iv),
                        "data": b64(AESGCM(phrase_key(salt)).encrypt(iv, raw, None)),
                    }
                    api("/keys", short, "PUT", {"public_key": public_jwk(private), "vault": vault})
                private_keys[short] = private

            report = []
            created = 0
            for title, is_group, people, messages in SCENARIOS:
                owner = people[0]
                member_ids = sorted(sessions[p]["user"]["id"] for p in people)
                current = api("/chats", owner)
                chat = next(
                    (
                        c
                        for c in current
                        if c["is_group"] == is_group
                        and sorted(m["id"] for m in c["members"]) == member_ids
                        and (not is_group or c["title"] == title)
                    ),
                    None,
                )
                if not chat:
                    cid = api(
                        "/chats",
                        owner,
                        "POST",
                        {
                            "title": title,
                            "is_group": is_group,
                            "user_ids": [sessions[p]["user"]["id"] for p in people[1:]],
                        },
                    )["id"]
                    chat = next(c for c in api("/chats", owner) if c["id"] == cid)
                ids = [
                    str(uuid5(NAMESPACE_URL, f'messenger-demo-v1/{chat["id"]}/{title}/{i}'))
                    for i in range(len(messages))
                ]
                present = history(chat["id"], owner)
                for index, item in enumerate(messages):
                    mid = ids[index]
                    if mid in present:
                        continue
                    sender = item["who"]
                    sender_id = sessions[sender]["user"]["id"]
                    reply = ids[item["reply"]] if item["reply"] is not None else None
                    payload = encrypt(
                        item["content"], chat["members"], chat["id"], mid, sender_id, reply
                    )
                    api(
                        f'/chats/{chat["id"]}/messages',
                        sender,
                        "POST",
                        {
                            "id": mid,
                            "revision": chat["revision"],
                            "payload": payload,
                            "reply_to": reply,
                        },
                    )
                    created += 1
                    if item["delete"]:
                        api("/messages/" + mid, sender, "DELETE")
                    elif item["state"] != "sent":
                        for recipient in people:
                            if recipient != sender:
                                api(
                                    f'/chats/{chat["id"]}/receipts',
                                    recipient,
                                    "POST",
                                    {"ids": [mid], "read": item["state"] == "read"},
                                )
                # Проверяем расшифрование каждого добавленного сообщения реальным ключом участника.
                reader = next(p for p in people if p in private_keys)
                rows = history(chat["id"], reader)
                for i, mid in enumerate(ids):
                    row = rows[mid]
                    if row["deleted"]:
                        continue
                    p = row["payload"]
                    raw = private_keys[reader].decrypt(
                        base64.b64decode(p["keys"][str(sessions[reader]["user"]["id"])]), oaep()
                    )
                    aad = f'{chat["id"]}|{mid}|{row["sender_id"]}|{row["reply_to"] or ""}'.encode()
                    content = json.loads(
                        AESGCM(raw).decrypt(
                            base64.b64decode(p["iv"]), base64.b64decode(p["data"]), aad
                        )
                    )
                    assert content == messages[i]["content"], "Демонстрационный пакет не совпал"
                report.append({"chat": title, "messages": len(messages)})
                if title == "Разработка мессенджера":
                    target = next(
                        m for m in chat["members"] if m["id"] == sessions["mikhail"]["user"]["id"]
                    )
                    if not target["is_admin"]:
                        api(
                            f'/chats/{chat["id"]}/members',
                            owner,
                            "POST",
                            {"user_id": target["id"], "action": "promote"},
                        )

            if "demo_archive" not in existing:
                uid = api(
                    "/admin/users",
                    method="POST",
                    data={
                        "login": "demo_archive",
                        "first_name": "Архивный",
                        "last_name": "Пользователь",
                        "password": PASSWORD,
                    },
                )["id"]
                api(f"/admin/users/{uid}/action", method="POST", data={"action": "block"})
            print(
                json.dumps(
                    {
                        "added_messages": created,
                        "total_demo_messages": sum(len(s[3]) for s in SCENARIOS),
                        "chats": report,
                        "verified_decryption": True,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        finally:
            for who in sessions:
                try:
                    api("/logout", who, "POST")
                except Exception:
                    pass


if __name__ == "__main__":
    main()
