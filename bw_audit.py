#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Аудит экспорта Bitwarden:
- повторяющиеся пароли;
- поиск записей по паролю;
- выборочный показ пароля по короткому SHA-256-идентификатору;
- простые признаки слабых паролей.

Поддерживает незашифрованный экспорт Bitwarden в JSON или CSV.
"""

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from getpass import getpass
from pathlib import Path


COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "12345678",
    "12345",
    "1234567",
    "password",
    "qwerty",
    "111111",
    "1234567890",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "abc123",
    "passw0rd",
    "qazwsx",
    "iloveyou",
    "sunshine",
    "princess",
}


def clean(value):
    if value is None:
        return ""
    return str(value).strip()


def sha12(value: str) -> str:
    """
    Короткий идентификатор пароля.
    Это не замена паролю, а удобный способ ссылаться на него в отчёте.
    """
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def load_json(path: Path):
    text = path.read_text(encoding="utf-8-sig")
    data = json.loads(text)

    if isinstance(data, dict) and data.get("encrypted"):
        sys.exit(
            "Похоже, это зашифрованный экспорт Bitwarden. "
            "Для такого анализа нужен незашифрованный JSON или CSV."
        )

    folders = {}
    if isinstance(data, dict):
        for folder in data.get("folders", []) or []:
            if isinstance(folder, dict) and folder.get("id") is not None:
                folders[str(folder.get("id"))] = clean(folder.get("name"))

    items = data.get("items", []) if isinstance(data, dict) else data
    entries = []

    for item in items or []:
        if not isinstance(item, dict):
            continue

        login = item.get("login") or {}
        if not isinstance(login, dict):
            continue

        password = clean(login.get("password"))
        if not password:
            continue

        uris = login.get("uris") or []
        uri_values = []

        if isinstance(uris, list):
            for uri in uris:
                if isinstance(uri, dict):
                    value = clean(uri.get("uri"))
                else:
                    value = clean(uri)
                if value:
                    uri_values.append(value)
        elif uris:
            uri_values.append(clean(uris))

        folder_id = item.get("folderId")
        folder_name = folders.get(str(folder_id), "") if folder_id is not None else ""

        entries.append({
            "name": clean(item.get("name")),
            "username": clean(login.get("username")),
            "uri": ", ".join(uri_values),
            "folder": folder_name,
            "password": password,
            "id": clean(item.get("id")),
        })

    return entries


def load_csv(path: Path):
    entries = []

    with path.open(encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)

        for row in reader:
            normalized = {}

            for key, value in row.items():
                if key is None:
                    continue
                normalized[key.strip().lower()] = value

            password = clean(normalized.get("login_password"))
            if not password:
                password = clean(normalized.get("password"))

            if not password:
                continue

            username = clean(normalized.get("login_username"))
            if not username:
                username = clean(normalized.get("username"))

            uri = clean(normalized.get("login_uri"))
            if not uri:
                uri = clean(normalized.get("uri"))

            entries.append({
                "name": clean(normalized.get("name")),
                "username": username,
                "uri": uri,
                "folder": clean(normalized.get("folder")),
                "password": password,
                "id": clean(normalized.get("id")),
            })

    return entries


def load_entries(path: Path, fmt: str):
    if fmt == "json":
        return load_json(path)

    if fmt == "csv":
        return load_csv(path)

    suffix = path.suffix.lower()

    if suffix == ".json":
        return load_json(path)

    if suffix == ".csv":
        return load_csv(path)

    # Если расширение непонятное, пробуем сначала JSON, потом CSV.
    try:
        return load_json(path)
    except Exception:
        return load_csv(path)


def group_by_password(entries):
    groups = defaultdict(list)

    for entry in entries:
        groups[entry["password"]].append(entry)

    return groups


def format_entry(entry, show_password=False):
    parts = [entry["name"] or "<без имени>"]

    if entry["username"]:
        parts.append(f"логин: {entry['username']}")

    if entry["uri"]:
        parts.append(f"uri: {entry['uri']}")

    if entry["folder"]:
        parts.append(f"папка: {entry['folder']}")

    line = " | ".join(parts)

    if show_password:
        line += f" | пароль: {entry['password']}"

    return line


def print_duplicates(groups, show_password=False, min_count=2):
    total_entries = sum(len(items) for items in groups.values())
    duplicates = [
        (password, items)
        for password, items in groups.items()
        if len(items) >= min_count
    ]

    duplicates.sort(key=lambda x: len(x[1]), reverse=True)

    total_duplicate_entries = sum(len(items) for _, items in duplicates)

    print("=== Повторяющиеся пароли ===")
    print(f"Записей с паролями: {total_entries}")
    print(f"Уникальных паролей: {len(groups)}")
    print(f"Паролей повторяется (порог >= {min_count}): {len(duplicates)}")
    print(f"Записей с повторяющимися паролями: {total_duplicate_entries}")

    if not duplicates:
        return

    for password, items in duplicates:
        print("\n" + "=" * 80)
        print(
            f"Пароль повторяется {len(items)} раз | "
            f"длина: {len(password)} | "
            f"sha256_12: {sha12(password)}"
        )

        if show_password:
            print(f"Пароль: {password}")

        for entry in items:
            print("  - " + format_entry(entry, show_password=False))

    if not show_password:
        print(
            "\nПароли скрыты. Чтобы показать их, добавьте --show-password "
            "(небезопасно в общем терминале/логах)."
        )


def search_by_password(entries, query, contains=False, show_password=False):
    if contains:
        matches = [entry for entry in entries if query in entry["password"]]
    else:
        matches = [entry for entry in entries if entry["password"] == query]

    print(f"Найдено записей: {len(matches)}")

    for entry in matches:
        print("  - " + format_entry(entry, show_password=show_password))

    if matches and not show_password:
        print("Пароль скрыт. Добавьте --show-password, если нужно увидеть сам пароль.")


def reveal_by_sha12(groups, target_sha12):
    target = target_sha12.strip().lower()
    found = False

    for password, items in groups.items():
        if sha12(password) == target:
            found = True
            print(f"Найден пароль для sha256_12={target}")
            print(f"Записей с этим паролем: {len(items)}")
            print(f"Пароль: {password}")

            for entry in items:
                print("  - " + format_entry(entry, show_password=False))

    if not found:
        print("Не найден пароль с таким sha256_12.")


def weak_reasons(password, entries):
    reasons = []

    if len(password) < 12:
        reasons.append("длина меньше 12")

    if password.lower() in COMMON_PASSWORDS:
        reasons.append("очень популярный пароль")

    if password.isdigit():
        reasons.append("только цифры")

    if password.isalpha():
        reasons.append("только буквы")

    if len(password) >= 6 and len(set(password)) <= 3:
        reasons.append("очень мало уникальных символов")

    lowered_password = password.lower()

    for entry in entries:
        username = entry.get("username", "").lower()
        if not username:
            continue

        if username == lowered_password:
            reasons.append("пароль совпадает с логином")
            break

        if len(username) >= 4 and username in lowered_password:
            reasons.append("пароль содержит логин")
            break

    return reasons


def print_weak(groups, show_password=False):
    weak = []

    for password, items in groups.items():
        reasons = weak_reasons(password, items)
        if reasons:
            weak.append((password, items, reasons))

    weak.sort(key=lambda x: len(x[1]), reverse=True)

    print("\n=== Возможные слабые пароли ===")
    print(f"Найдено паролей: {len(weak)}")
    print(f"Затронуто записей: {sum(len(items) for _, items, _ in weak)}")

    if not weak:
        return

    for password, items, reasons in weak:
        print("\n" + "=" * 80)
        print(
            f"Пароль: длина {len(password)} | "
            f"sha256_12: {sha12(password)} | "
            f"записей: {len(items)} | "
            f"причины: {', '.join(reasons)}"
        )

        if show_password:
            print(f"Пароль: {password}")

        for entry in items:
            print("  - " + format_entry(entry, show_password=False))


def main():
    parser = argparse.ArgumentParser(
        description="Проверка повторяющихся паролей в экспорте Bitwarden."
    )

    parser.add_argument(
        "export_file",
        help="Файл экспорта Bitwarden: .json или .csv"
    )

    parser.add_argument(
        "--format",
        choices=["auto", "json", "csv"],
        default="auto",
        help="Формат файла, по умолчанию определяется автоматически"
    )

    parser.add_argument(
        "--search-password",
        help="Пароль для поиска (точный, если не задан --contains)"
    )

    parser.add_argument(
        "--ask-password",
        action="store_true",
        help="Запросить пароль для поиска в терминале, чтобы не светить его в истории команд"
    )

    parser.add_argument(
        "--contains",
        action="store_true",
        help="Искать не точный пароль, а вхождение подстроки"
    )

    parser.add_argument(
        "--show-password",
        action="store_true",
        help="Показывать пароли в выводе (осторожно)"
    )

    parser.add_argument(
        "--reveal-sha12",
        help="Показать пароль для конкретного sha256_12 из отчёта"
    )

    parser.add_argument(
        "--min-count",
        type=int,
        default=2,
        help="Минимальное количество повторов, чтобы считать пароль повторяющимся"
    )

    parser.add_argument(
        "--weak",
        action="store_true",
        help="Дополнительно показать простые признаки слабых паролей"
    )

    args = parser.parse_args()
    path = Path(args.export_file).expanduser()

    if not path.exists():
        sys.exit(f"Файл не найден: {path}")

    entries = load_entries(path, args.format)

    if not entries:
        print("Не найдено записей с паролями. Проверьте файл экспорта и его формат.")
        return

    groups = group_by_password(entries)

    if args.reveal_sha12:
        reveal_by_sha12(groups, args.reveal_sha12)
        return

    query = args.search_password

    if args.ask_password:
        query = getpass("Введите пароль для поиска: ")

    if query is not None:
        search_by_password(
            entries,
            query,
            contains=args.contains,
            show_password=args.show_password
        )
    else:
        print_duplicates(
            groups,
            show_password=args.show_password,
            min_count=args.min_count
        )

        if args.weak:
            print_weak(groups, show_password=args.show_password)


if __name__ == "__main__":
    main()
