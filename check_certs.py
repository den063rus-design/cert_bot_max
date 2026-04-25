#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import warnings
from datetime import date, datetime, timezone
from pathlib import Path

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID

from config import (
    ALERT_THRESHOLDS,
    ALLOWED_EXTENSIONS,
    CACHE_FILE,
    CHAT_ID,
    CERT_ROOTS,
    MAX_ACCESS_TOKEN,
    MAX_MESSAGES_URL,
    MAX_REQUEST_TIMEOUT,
    WORK_HOUR_END,
    WORK_HOUR_START,
)
try:
    from config import FORCE_SEND_EVERY_RUN
except ImportError:
    FORCE_SEND_EVERY_RUN = False
try:
    from config import GROUP_BY_ORGANIZATION
except ImportError:
    GROUP_BY_ORGANIZATION = True

# OID поля "ИНН ЮЛ" в Subject сертификата
LEGAL_ENTITY_INN_OID = x509.ObjectIdentifier("1.2.643.100.4")


# ------------------------------------------------------------
#  Вспомогательные функции
# ------------------------------------------------------------
def find_cert_files(root_dirs):
    """Рекурсивно найти все файлы с разрешёнными расширениями."""
    cert_files = []
    allowed_exts = {str(ext).strip().lower() for ext in ALLOWED_EXTENSIONS}

    for root in root_dirs:
        root_path = Path(root)
        if not root_path.exists():
            print(f"Предупреждение: папка {root} не существует, пропускаем")
            continue
        if not root_path.is_dir():
            print(f"Предупреждение: {root} не является папкой, пропускаем")
            continue

        root_found = 0

        def on_walk_error(exc):
            print(f"Предупреждение: нет доступа к {exc.filename}: {exc}")

        for dirpath, _dirnames, filenames in os.walk(
            root_path,
            topdown=True,
            onerror=on_walk_error,
            followlinks=False,
        ):
            for filename in filenames:
                suffix = Path(filename).suffix.strip().lower()
                if suffix not in allowed_exts:
                    continue
                file_path = Path(dirpath) / filename
                cert_files.append(file_path)
                root_found += 1

        print(f"Просканировано {root_path}: найдено {root_found} файлов сертификатов")

    cert_files.sort(key=lambda p: p.as_posix())
    return cert_files


def load_certificate(path):
    """Загрузить сертификат (PEM или DER)."""
    data = path.read_bytes()

    pem_error = None
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        pem_error = exc

    try:
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise ValueError(f"Не удалось распознать сертификат {path}: {pem_error}; {exc}") from exc


def first_subject_value(cert, oid):
    """Вернуть первое значение поля Subject по OID или None."""
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="Attribute's length must be >= 1 and <= 64, but it was .*",
            category=UserWarning,
        )
        attrs = cert.subject.get_attributes_for_oid(oid)
    if not attrs:
        return None
    value = attrs[0].value
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def is_legal_entity_certificate(cert):
    """Определить, что сертификат принадлежит юрлицу (есть ИНН ЮЛ)."""
    return first_subject_value(cert, LEGAL_ENTITY_INN_OID) is not None


def extract_person_surname(cert):
    """Получить фамилию физлица из Subject (приоритет: surname, затем CN)."""
    surname = first_subject_value(cert, NameOID.SURNAME)
    if surname:
        return surname

    common_name = first_subject_value(cert, NameOID.COMMON_NAME)
    if common_name:
        # CN может быть в виде "Иванов Иван Иванович" — берём первую часть.
        first_token = common_name.replace(",", " ").split()
        if first_token:
            return first_token[0]

    return None


def build_certificate_identity(cert, path):
    """
    Вернуть человекочитаемое имя и стабильный ключ группировки.

    Приоритет:
    1. organizationName
    2. commonName
    3. имя файла/путь, чтобы не склеивать все неизвестные сертификаты в один.
    """
    org = first_subject_value(cert, NameOID.ORGANIZATION_NAME)
    common_name = first_subject_value(cert, NameOID.COMMON_NAME)
    is_legal_entity = is_legal_entity_certificate(cert)

    # Для физлица в уведомлении показываем только фамилию.
    if not is_legal_entity:
        surname = extract_person_surname(cert)
        if GROUP_BY_ORGANIZATION:
            if surname:
                return surname, f"person::{surname}"
            if common_name:
                return common_name, f"cn::{common_name}"
            return path.as_posix(), f"path::{path.resolve().as_posix()}"

        if surname:
            return surname, f"path::{path.resolve().as_posix()}"
        if common_name:
            return common_name, f"path::{path.resolve().as_posix()}"
        return path.as_posix(), f"path::{path.resolve().as_posix()}"

    # Юрлицо
    if GROUP_BY_ORGANIZATION:
        if org:
            return org, f"org::{org}"
        if common_name:
            return common_name, f"cn::{common_name}"
        return path.as_posix(), f"path::{path.resolve().as_posix()}"

    if org:
        return f"{org} ({path.name})", f"path::{path.resolve().as_posix()}"
    if common_name:
        return f"{common_name} ({path.name})", f"path::{path.resolve().as_posix()}"
    return path.as_posix(), f"path::{path.resolve().as_posix()}"


def get_not_valid_after(cert):
    """Получить дату окончания сертификата в UTC."""
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is not None:
        return expiry

    expiry = cert.not_valid_after
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry.astimezone(timezone.utc)


def days_until_expiry(cert):
    """Сколько дней осталось до окончания сертификата (может быть отрицательным)."""
    expiry = get_not_valid_after(cert)
    today_utc = datetime.now(timezone.utc).date()
    return (expiry.date() - today_utc).days


def is_work_hour():
    """?????????, ?????? ?? ??????? ????? ?? ?????????? ??????? ???????."""
    if FORCE_SEND_EVERY_RUN:
        return True
    now_local = datetime.now()
    return WORK_HOUR_START <= now_local.hour < WORK_HOUR_END


def day_word(days_left):
    """Примитивная склонялка слова 'день'."""
    n = abs(int(days_left))
    if 11 <= n % 100 <= 14:
        return "дней"
    if n % 10 == 1:
        return "день"
    if 2 <= n % 10 <= 4:
        return "дня"
    return "дней"


def escape_max_markdown(text):
    """Escape basic MAX markdown control characters."""
    value = str(text)
    for ch in ("\\", "*", "_", "[", "]", "(", ")", "`", "~", "+"):
        value = value.replace(ch, f"\\{ch}")
    return value


def build_alert_message(org, days_left, expiry_str):
    """Build visually emphasized alert text."""
    org_md = escape_max_markdown(org)
    expiry_md = escape_max_markdown(expiry_str)

    if days_left < 0:
        return (
            "❌ **СЕРТИФИКАТ ПРОСРОЧЕН**\n"
            f"Организация: **{org_md}**\n"
            f"Просрочка: **{abs(days_left)} {day_word(days_left)}**\n"
            f"Дата окончания: `{expiry_md}`\n"
            "Требуется срочная замена."
        )
    if days_left == 0:
        return (
            "⚠️ **СЕРТИФИКАТ ИСТЕКАЕТ СЕГОДНЯ**\n"
            f"Организация: **{org_md}**\n"
            f"Дата окончания: `{expiry_md}`"
        )

    return (
        "⚠️ **СРОК СЕРТИФИКАТА ПОДХОДИТ**\n"
        f"Организация: **{org_md}**\n"
        f"Осталось: **{days_left} {day_word(days_left)}**\n"
        f"Дата окончания: `{expiry_md}`"
    )


def send_max_message(chat_id, text):
    """Send a message to MAX API. Returns True on success."""
    chat_id_value = str(chat_id).strip()
    if not chat_id_value:
        print("MAX send error: CHAT_ID is empty")
        return False

    token_value = str(MAX_ACCESS_TOKEN).strip()
    if not token_value:
        print("MAX send error: MAX_ACCESS_TOKEN is empty")
        return False

    auth_candidates = [token_value]
    if token_value.lower().startswith("bearer "):
        plain_token = token_value[7:].strip()
        if plain_token:
            auth_candidates.append(plain_token)
    else:
        auth_candidates.append(f"Bearer {token_value}")
    auth_candidates = list(dict.fromkeys(candidate for candidate in auth_candidates if candidate))

    payload = {
        "text": text,
        "notify": True,
        "format": "markdown",
    }

    try:
        last_response = None
        for attempt_num, auth_value in enumerate(auth_candidates, start=1):
            headers = {
                "Authorization": auth_value,
                "Content-Type": "application/json",
            }
            resp = requests.post(
                MAX_MESSAGES_URL,
                params={"chat_id": chat_id_value},
                json=payload,
                headers=headers,
                timeout=MAX_REQUEST_TIMEOUT,
            )
            if 200 <= resp.status_code < 300:
                print(f"MAX notification sent: {text[:80]}...")
                return True

            last_response = resp
            if resp.status_code not in (401, 403):
                break
            if attempt_num < len(auth_candidates):
                print(
                    f"MAX auth retry: received {resp.status_code}, "
                    "trying alternative Authorization format",
                )

        if last_response is not None:
            print(f"MAX send error: {last_response.status_code} {last_response.text}")
        return False
    except Exception as exc:
        print(f"MAX API connection error: {exc}")
        return False


def load_cache():
    """Загрузить кэш отправленных уведомлений."""
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

    if not isinstance(cache, dict):
        return {}

    pending = cache.get("_pending")
    if isinstance(pending, list):
        migrated = {}
        for index, item in enumerate(pending):
            if isinstance(item, str) and item.strip():
                migrated[f"legacy::{index}"] = {
                    "org_cache_key": None,
                    "org": "Неизвестно",
                    "days_left": None,
                    "expiry_str": None,
                    "message": item,
                    "created_at": None,
                    "last_attempt_at": None,
                    "attempts": 0,
                }
        cache["_pending"] = migrated
    elif not isinstance(pending, dict):
        cache["_pending"] = {}

    return cache


def save_cache(cache):
    """Сохранить кэш атомарно."""
    cache_path = Path(CACHE_FILE)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_name(cache_path.name + ".tmp")

    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    tmp_path.replace(cache_path)


def get_org_cache_entry(cache, cache_key):
    """Вернуть словарь кэша для организации или None."""
    entry = cache.get(cache_key)
    if isinstance(entry, dict):
        return entry
    return None


def should_send_alert(org, days_left, cache_entry, expiry_str):
    """
    ??????????, ????? ?? ????????? ??????????? ??? ???????????.
    cache_entry - ??????? ?? ???? ??? ???? ??????????? (??? None).
    ?????????? (?????_??, ?????_?????????).
    """
    if FORCE_SEND_EVERY_RUN:
        return True, build_alert_message(org, days_left, expiry_str)

    if days_left < 0:
        if cache_entry is None or cache_entry.get("last_alert_days") != days_left:
            return True, build_alert_message(org, days_left, expiry_str)
        return False, None

    if days_left in ALERT_THRESHOLDS:
        if cache_entry is None or cache_entry.get("last_alert_days") != days_left:
            return True, build_alert_message(org, days_left, expiry_str)
        return False, None

    if 0 <= days_left < 7:
        if cache_entry is None or cache_entry.get("last_alert_days") != days_left:
            return True, build_alert_message(org, days_left, expiry_str)
        return False, None

    return False, None


def get_pending_map(cache):
    """Вернуть карту отложенных уведомлений."""
    pending = cache.get("_pending")
    if not isinstance(pending, dict):
        pending = {}
        cache["_pending"] = pending
    return pending


def queue_pending_alert(cache, alert_id, alert_payload):
    """Добавить/обновить отложенное уведомление."""
    pending = get_pending_map(cache)
    pending[alert_id] = alert_payload


def prune_stale_pending_alerts(cache, cert_groups):
    """
    Удалить отложенные уведомления, которые относятся к уже изменённым
    или исчезнувшим сертификатам.
    """
    pending = get_pending_map(cache)
    if not pending:
        return False

    removed_any = False
    stale_ids = []

    for alert_id, item in pending.items():
        org_cache_key = item.get("org_cache_key")
        if not org_cache_key:
            continue

        current = cert_groups.get(org_cache_key)
        if current is not None and item.get("expiry_str") != current["expiry_str"]:
            stale_ids.append(alert_id)

    for alert_id in stale_ids:
        pending.pop(alert_id, None)
        removed_any = True

    return removed_any


def process_pending_alerts(cache):
    """Отправить все отложенные уведомления, если сейчас рабочее время."""
    pending = get_pending_map(cache)
    if not pending:
        return False

    if not is_work_hour():
        now_local = datetime.now()
        print(
            "Pending alerts are not sent now: "
            f"outside work hours ({now_local.strftime('%H:%M')}, "
            f"allowed {WORK_HOUR_START:02d}:00-{WORK_HOUR_END:02d}:00). "
            f"Queue size: {len(pending)}",
        )
        return False

    now_iso = datetime.now(timezone.utc).isoformat()
    updated = False
    sent_ids = []

    for alert_id, item in sorted(pending.items(), key=lambda kv: kv[1].get("created_at") or ""):
        message = item.get("message")
        if not message:
            sent_ids.append(alert_id)
            updated = True
            continue

        if send_max_message(CHAT_ID, message):
            sent_ids.append(alert_id)
            updated = True

            org_cache_key = item.get("org_cache_key")
            if org_cache_key:
                org_entry = get_org_cache_entry(cache, org_cache_key)
                if org_entry is not None:
                    org_entry["last_sent_time"] = now_iso
                    org_entry["delivery_state"] = "sent"
        else:
            item["last_attempt_at"] = now_iso
            item["attempts"] = int(item.get("attempts", 0)) + 1
            updated = True

    for alert_id in sent_ids:
        pending.pop(alert_id, None)

    return updated


# ------------------------------------------------------------
#  Основная логика
# ------------------------------------------------------------
def main():
    print(f"=== Запуск проверки сертификатов {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    cache = load_cache()
    cert_paths = find_cert_files(CERT_ROOTS)
    print(f"Найдено {len(cert_paths)} файлов сертификатов")

    # Группируем по организации/имени и выбираем сертификат с самой поздней датой окончания
    cert_groups = {}  # cache_key -> {"label": ..., "expiry": ..., "expiry_str": ..., "path": ...}
    for path in cert_paths:
        try:
            cert = load_certificate(path)
            label, cache_key = build_certificate_identity(cert, path)
            expiry_dt = get_not_valid_after(cert)
            expiry_date = expiry_dt.date()
            expiry_str = expiry_date.isoformat()

            current = cert_groups.get(cache_key)
            if current is None or expiry_date > current["expiry"]:
                cert_groups[cache_key] = {
                    "label": label,
                    "expiry": expiry_date,
                    "expiry_str": expiry_str,
                    "path": path,
                }
        except Exception as exc:
            print(f"Ошибка при обработке {path}: {exc}")

    mode_name = "по организациям" if GROUP_BY_ORGANIZATION else "по каждому сертификату"
    print(f"Сформировано {len(cert_groups)} записей для уведомлений (режим: {mode_name})")

    updated = False

    if prune_stale_pending_alerts(cache, cert_groups):
        updated = True

    # Сначала отправляем накопленные отложенные уведомления, если уже рабочее время
    if process_pending_alerts(cache):
        updated = True

    for cache_key, info in sorted(cert_groups.items(), key=lambda item: item[0].lower()):
        org = info["label"]
        expiry_date = info["expiry"]
        expiry_str = info["expiry_str"]
        path = info["path"]
        days_left = (expiry_date - date.today()).days

        cache_entry = get_org_cache_entry(cache, cache_key)

        # Если сертификат заменили на новый - сбрасываем историю по этой записи
        if cache_entry and cache_entry.get("expiry_str") != expiry_str:
            print(f"  → {org}: замена сертификата (было {cache_entry.get('expiry_str')}, стало {expiry_str})")
            cache_entry = None
            cache.pop(cache_key, None)
            updated = True

        need_send, msg = should_send_alert(org, days_left, cache_entry, expiry_str)
        if need_send:
            now_iso = datetime.now(timezone.utc).isoformat()
            cache[cache_key] = {
                "last_alert_days": days_left,
                "expiry_str": expiry_str,
                "last_alert_time": now_iso,
            }
            updated = True

            alert_id = f"{cache_key}|{expiry_str}|{days_left}"
            if is_work_hour():
                if send_max_message(CHAT_ID, msg):
                    cache[cache_key]["last_sent_time"] = now_iso
                    cache[cache_key]["delivery_state"] = "sent"
                else:
                    queue_pending_alert(
                        cache,
                        alert_id,
                        {
                            "org_cache_key": cache_key,
                            "org": org,
                            "days_left": days_left,
                            "expiry_str": expiry_str,
                            "message": msg,
                            "created_at": now_iso,
                            "last_attempt_at": None,
                            "attempts": 0,
                        },
                    )
                updated = True
            else:
                queue_pending_alert(
                    cache,
                    alert_id,
                    {
                        "org_cache_key": cache_key,
                        "org": org,
                        "days_left": days_left,
                        "expiry_str": expiry_str,
                        "message": msg,
                        "created_at": now_iso,
                        "last_attempt_at": None,
                        "attempts": 0,
                    },
                )
                print(f"  → Уведомление для {org} отложено (нерабочее время)")
                updated = True

        print(f"  {org}: действует до {expiry_str}, осталось {days_left} дн. Актуальный серт: {path.name}")

    if updated:
        save_cache(cache)
        print("Кэш обновлён")
    else:
        print("Новых уведомлений нет")

    print("=== Проверка завершена ===")


if __name__ == "__main__":
    main()
