#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import time
import warnings
import argparse
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
try:
    from config import RUN_AS_DAEMON
except ImportError:
    RUN_AS_DAEMON = False
try:
    from config import DAEMON_LOOP_INTERVAL
except ImportError:
    DAEMON_LOOP_INTERVAL = 60
try:
    from config import COMMAND_LOOP_INTERVAL
except ImportError:
    COMMAND_LOOP_INTERVAL = 3
try:
    from config import COMMAND_POLL_COUNT
except ImportError:
    COMMAND_POLL_COUNT = 100


def to_int(value, default):
    """Convert value to int with fallback."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def to_bool(value, default=False):
    """Convert common string/bool values to bool."""
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


RUN_AS_DAEMON = to_bool(RUN_AS_DAEMON, False)
DAEMON_LOOP_INTERVAL = max(5, to_int(DAEMON_LOOP_INTERVAL, 60))
COMMAND_LOOP_INTERVAL = max(1, to_int(COMMAND_LOOP_INTERVAL, 3))
COMMAND_POLL_COUNT = max(1, min(to_int(COMMAND_POLL_COUNT, 100), 100))

# OID РїРѕР»СЏ "РРќРќ Р®Р›" РІ Subject СЃРµСЂС‚РёС„РёРєР°С‚Р°
LEGAL_ENTITY_INN_OID = x509.ObjectIdentifier("1.2.643.100.4")


# -----------------------------------------------------
#  Р’СЃРїРѕРјРѕРіР°С‚РµР»СЊРЅС‹Рµ С„СѓРЅРєС†РёРё
# -----------------------------------------------------
def find_cert_files(root_dirs):
    """Р РµРєСѓСЂСЃРёРІРЅРѕ РЅР°Р№С‚Рё РІСЃРµ С„Р°Р№Р»С‹ СЃ СЂР°Р·СЂРµС€С‘РЅРЅС‹РјРё СЂР°СЃС€РёСЂРµРЅРёСЏРјРё."""
    cert_files = []
    allowed_exts = {str(ext).strip().lower() for ext in ALLOWED_EXTENSIONS}

    for root in root_dirs:
        root_path = Path(root)
        if not root_path.exists():
            print(f"РџСЂРµРґСѓРїСЂРµР¶РґРµРЅРёРµ: РїР°РїРєР° {root} РЅРµ СЃСѓС‰РµСЃС‚РІСѓРµС‚, РїСЂРѕРїСѓСЃРєР°РµРј")
            continue
        if not root_path.is_dir():
            print(f"РџСЂРµРґСѓРїСЂРµР¶РґРµРЅРёРµ: {root} РЅРµ СЏРІР»СЏРµС‚СЃСЏ РїР°РїРєРѕР№, РїСЂРѕРїСѓСЃРєР°РµРј")
            continue

        root_found = 0

        def on_walk_error(exc):
            print(f"РџСЂРµРґСѓРїСЂРµР¶РґРµРЅРёРµ: РЅРµС‚ РґРѕСЃС‚СѓРїР° Рє {exc.filename}: {exc}")

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

        print(f"РџСЂРѕСЃРєР°РЅРёСЂРѕРІР°РЅРѕ {root_path}: РЅР°Р№РґРµРЅРѕ {root_found} С„Р°Р№Р»РѕРІ СЃРµСЂС‚РёС„РёРєР°С‚РѕРІ")

    cert_files.sort(key=lambda p: p.as_posix())
    return cert_files


def load_certificate(path):
    """Р—Р°РіСЂСѓР·РёС‚СЊ СЃРµСЂС‚РёС„РёРєР°С‚ (PEM РёР»Рё DER)."""
    data = path.read_bytes()

    pem_error = None
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        pem_error = exc

    try:
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise ValueError(f"РќРµ СѓРґР°Р»РѕСЃСЊ СЂР°СЃРїРѕР·РЅР°С‚СЊ СЃРµСЂС‚РёС„РёРєР°С‚ {path}: {pem_error}; {exc}") from exc


def first_subject_value(cert, oid):
    """Р’РµСЂРЅСѓС‚СЊ РїРµСЂРІРѕРµ Р·РЅР°С‡РµРЅРёРµ РїРѕР»СЏ Subject РїРѕ OID РёР»Рё None."""
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
    """РћРїСЂРµРґРµР»РёС‚СЊ, С‡С‚Рѕ СЃРµСЂС‚РёС„РёРєР°С‚ РїСЂРёРЅР°РґР»РµР¶РёС‚ СЋСЂР»РёС†Сѓ (РµСЃС‚СЊ РРќРќ Р®Р›)."""
    return first_subject_value(cert, LEGAL_ENTITY_INN_OID) is not None


def extract_person_surname(cert):
    """РџРѕР»СѓС‡РёС‚СЊ С„Р°РјРёР»РёСЋ С„РёР·Р»РёС†Р° РёР· Subject (РїСЂРёРѕСЂРёС‚РµС‚: surname, Р·Р°С‚РµРј CN)."""
    surname = first_subject_value(cert, NameOID.SURNAME)
    if surname:
        return surname

    common_name = first_subject_value(cert, NameOID.COMMON_NAME)
    if common_name:
        # CN РјРѕР¶РµС‚ Р±С‹С‚СЊ РІ РІРёРґРµ "РРІР°РЅРѕРІ РРІР°РЅ РРІР°РЅРѕРІРёС‡" вЂ” Р±РµСЂС‘Рј РїРµСЂРІСѓСЋ С‡Р°СЃС‚СЊ.
        first_token = common_name.replace(",", " ").split()
        if first_token:
            return first_token[0]

    return None


def build_certificate_identity(cert, path):
    """
    Р’РµСЂРЅСѓС‚СЊ С‡РµР»РѕРІРµРєРѕС‡РёС‚Р°РµРјРѕРµ РёРјСЏ Рё СЃС‚Р°Р±РёР»СЊРЅС‹Р№ РєР»СЋС‡ РіСЂСѓРїРїРёСЂРѕРІРєРё.

    РџСЂРёРѕСЂРёС‚РµС‚:
    1. organizationName
    2. commonName
    3. РёРјСЏ С„Р°Р№Р»Р°/РїСѓС‚СЊ, С‡С‚РѕР±С‹ РЅРµ СЃРєР»РµРёРІР°С‚СЊ РІСЃРµ РЅРµРёР·РІРµСЃС‚РЅС‹Рµ СЃРµСЂС‚РёС„РёРєР°С‚С‹ РІ РѕРґРёРЅ.
    """
    org = first_subject_value(cert, NameOID.ORGANIZATION_NAME)
    common_name = first_subject_value(cert, NameOID.COMMON_NAME)
    is_legal_entity = is_legal_entity_certificate(cert)

    # Р”Р»СЏ С„РёР·Р»РёС†Р° РІ СѓРІРµРґРѕРјР»РµРЅРёРё РїРѕРєР°Р·С‹РІР°РµРј С‚РѕР»СЊРєРѕ С„Р°РјРёР»РёСЋ.
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

    # Р®СЂР»РёС†Рѕ
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
    """РџРѕР»СѓС‡РёС‚СЊ РґР°С‚Сѓ РѕРєРѕРЅС‡Р°РЅРёСЏ СЃРµСЂС‚РёС„РёРєР°С‚Р° РІ UTC."""
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is not None:
        return expiry

    expiry = cert.not_valid_after
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry.astimezone(timezone.utc)


def days_until_expiry(cert):
    """РЎРєРѕР»СЊРєРѕ РґРЅРµР№ РѕСЃС‚Р°Р»РѕСЃСЊ РґРѕ РѕРєРѕРЅС‡Р°РЅРёСЏ СЃРµСЂС‚РёС„РёРєР°С‚Р° (РјРѕР¶РµС‚ Р±С‹С‚СЊ РѕС‚СЂРёС†Р°С‚РµР»СЊРЅС‹Рј)."""
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
    """Простая склонялка слова 'день'."""
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


def build_auth_candidates():
    """Build possible Authorization header variants for MAX API."""
    token_value = str(MAX_ACCESS_TOKEN).strip()
    if not token_value:
        return []

    auth_candidates = [token_value]
    if token_value.lower().startswith("bearer "):
        plain_token = token_value[7:].strip()
        if plain_token:
            auth_candidates.append(plain_token)
    else:
        auth_candidates.append(f"Bearer {token_value}")

    return list(dict.fromkeys(candidate for candidate in auth_candidates if candidate))


def fetch_recent_chat_messages(chat_id, count=100):
    """Get recent messages from chat using MAX API."""
    chat_id_value = str(chat_id).strip()
    if not chat_id_value:
        print("MAX get messages error: CHAT_ID is empty")
        return None

    auth_candidates = build_auth_candidates()
    if not auth_candidates:
        print("MAX get messages error: MAX_ACCESS_TOKEN is empty")
        return None

    query = {
        "chat_id": chat_id_value,
        "count": int(max(1, min(int(count), 100))),
    }

    try:
        last_response = None
        for attempt_num, auth_value in enumerate(auth_candidates, start=1):
            headers = {
                "Authorization": auth_value,
            }
            resp = requests.get(
                MAX_MESSAGES_URL,
                params=query,
                headers=headers,
                timeout=MAX_REQUEST_TIMEOUT,
            )
            if 200 <= resp.status_code < 300:
                try:
                    payload = resp.json()
                except ValueError:
                    print("MAX get messages error: response is not valid JSON")
                    return None

                if isinstance(payload, dict):
                    messages = payload.get("messages")
                    if isinstance(messages, list):
                        return messages

                if isinstance(payload, list):
                    return payload

                print("MAX get messages error: unexpected response format")
                return None

            last_response = resp
            if resp.status_code not in (401, 403):
                break
            if attempt_num < len(auth_candidates):
                print(
                    f"MAX auth retry (GET): received {resp.status_code}, "
                    "trying alternative Authorization format",
                )

        if last_response is not None:
            print(f"MAX get messages error: {last_response.status_code} {last_response.text}")
        return None
    except Exception as exc:
        print(f"MAX get messages connection error: {exc}")
        return None


def parse_cert_command_days(text):
    """Parse /cert or /cert N command and return optional days limit."""
    if not isinstance(text, str):
        return None

    normalized = text.replace("\u00A0", " ").strip()
    match = re.match(
        r"^\s*/?cert(?:@[A-Za-z0-9_]{1,64})?(?:\s+(\d{1,5}))?\s*$",
        normalized,
        flags=re.IGNORECASE,
    )
    if not match:
        return None

    raw_days = match.group(1)
    if raw_days is None:
        return None
    return max(0, int(raw_days))


def is_cert_command(text):
    """Check if text is /cert command with or without day argument."""
    if not isinstance(text, str):
        return False
    normalized = text.replace("\u00A0", " ").strip()
    return bool(
        re.match(
            r"^\s*/?cert(?:@[A-Za-z0-9_]{1,64})?(?:\s+\d{1,5})?\s*$",
            normalized,
            flags=re.IGNORECASE,
        )
    )


def format_days_left_status(days_left):
    """Return human-readable status for number of days left."""
    if days_left < 0:
        return f"просрочен на {abs(days_left)} {day_word(days_left)}"
    if days_left == 0:
        return "истекает сегодня"
    return f"осталось {days_left} {day_word(days_left)}"


def split_lines_to_messages(lines, max_length=3500):
    """Split lines into message chunks that fit MAX text limits."""
    chunks = []
    current = []
    current_length = 0

    for line in lines:
        line = str(line)
        addition = len(line) + (1 if current else 0)
        if current and current_length + addition > max_length:
            chunks.append("\n".join(current))
            current = [line]
            current_length = len(line)
        else:
            current.append(line)
            current_length += addition

    if current:
        chunks.append("\n".join(current))

    return chunks


def build_cert_command_response_messages(cert_groups, days_limit):
    """Build one or several reply messages for /cert command."""
    rows = []
    today = date.today()

    for info in cert_groups.values():
        expiry_date = info["expiry"]
        days_left = (expiry_date - today).days
        if days_limit is None or days_left <= days_limit:
            rows.append((days_left, info["label"], info["expiry_str"]))

    rows.sort(key=lambda item: (item[0], item[1].lower()))

    if not rows:
        if days_limit is None:
            return ["Сертификаты не найдены."]
        return [f"По команде `/cert {days_limit}` сертификатов с остатком <= {days_limit} не найдено."]

    if days_limit is None:
        title = f"Список сертификатов (по возрастанию срока): {len(rows)} шт."
    else:
        title = f"Список сертификатов <= {days_limit} дн.: {len(rows)} шт."

    lines = [title, ""]
    total_rows = len(rows)
    for index, (days_left, label, expiry_str) in enumerate(rows, start=1):
        safe_label = escape_max_markdown(label)
        safe_date = escape_max_markdown(expiry_str)
        safe_status = escape_max_markdown(format_days_left_status(days_left))
        lines.append(f"{index}. {safe_label} - {safe_date} - {safe_status}")
        if index < total_rows:
            lines.append("------------------------------")

    return split_lines_to_messages(lines, max_length=3500)


def parse_message_seq(value):
    """Convert message seq to int if possible."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.isdigit():
            try:
                return int(stripped)
            except ValueError:
                return None
    return None


def get_last_command_seq(cache, chat_id):
    """Return last processed command seq for current chat."""
    chat_key = str(chat_id).strip() or "_default"

    by_chat = cache.get("_last_command_seq_by_chat")
    if isinstance(by_chat, dict):
        try:
            return int(by_chat.get(chat_key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    try:
        return int(cache.get("_last_command_seq", 0) or 0)
    except (TypeError, ValueError):
        return 0


def set_last_command_seq(cache, chat_id, seq):
    """Persist last processed seq for current chat."""
    chat_key = str(chat_id).strip() or "_default"
    seq_value = max(0, int(seq))

    by_chat = cache.get("_last_command_seq_by_chat")
    if not isinstance(by_chat, dict):
        by_chat = {}
        cache["_last_command_seq_by_chat"] = by_chat
    by_chat[chat_key] = seq_value

    # Keep legacy key too for backward compatibility.
    cache["_last_command_seq"] = seq_value


def process_chat_commands(cache, cert_groups):
    """Read latest chat messages and process /cert commands."""
    messages = fetch_recent_chat_messages(CHAT_ID, count=COMMAND_POLL_COUNT)
    if messages is None or not messages:
        return False

    last_processed_seq = get_last_command_seq(cache, CHAT_ID)
    cache_adjusted = False
    seen_seqs = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        body = message.get("body")
        if not isinstance(body, dict):
            continue
        seq_value = parse_message_seq(body.get("seq"))
        if seq_value is not None:
            seen_seqs.append(seq_value)

    if seen_seqs and last_processed_seq > max(seen_seqs):
        set_last_command_seq(cache, CHAT_ID, 0)
        last_processed_seq = 0
        cache_adjusted = True

    commands = []

    for message in messages:
        if not isinstance(message, dict):
            continue

        body = message.get("body")
        if not isinstance(body, dict):
            continue

        seq = parse_message_seq(body.get("seq"))
        if seq is None or seq <= last_processed_seq:
            continue

        sender = message.get("sender")
        if isinstance(sender, dict) and sender.get("is_bot"):
            continue

        raw_text = body.get("text")
        if raw_text is None:
            raw_text = body.get("caption")
        if not isinstance(raw_text, str):
            continue

        normalized_text = raw_text.strip()
        days_limit = parse_cert_command_days(normalized_text)
        if days_limit is None and not is_cert_command(normalized_text):
            continue

        commands.append((seq, normalized_text, days_limit))

    if not commands:
        return cache_adjusted

    commands.sort(key=lambda item: item[0])
    updated = False

    for seq, raw_command, days_limit in commands:
        response_messages = build_cert_command_response_messages(cert_groups, days_limit)
        sent_ok = True

        for message_text in response_messages:
            if not send_max_message(CHAT_ID, message_text):
                sent_ok = False
                break

        if not sent_ok:
            print(f"РљРѕРјР°РЅРґР° РЅРµ РѕР±СЂР°Р±РѕС‚Р°РЅР° (РѕС€РёР±РєР° РѕС‚РїСЂР°РІРєРё): {raw_command} (seq={seq})")
            break

        set_last_command_seq(cache, CHAT_ID, seq)
        updated = True
        print(f"РљРѕРјР°РЅРґР° РѕР±СЂР°Р±РѕС‚Р°РЅР°: {raw_command} (seq={seq})")

    return updated


def send_max_message(chat_id, text):
    """Send a message to MAX API. Returns True on success."""
    chat_id_value = str(chat_id).strip()
    if not chat_id_value:
        print("MAX send error: CHAT_ID is empty")
        return False

    auth_candidates = build_auth_candidates()
    if not auth_candidates:
        print("MAX send error: MAX_ACCESS_TOKEN is empty")
        return False

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
    """Р—Р°РіСЂСѓР·РёС‚СЊ РєСЌС€ РѕС‚РїСЂР°РІР»РµРЅРЅС‹С… СѓРІРµРґРѕРјР»РµРЅРёР№."""
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
                    "org": "РќРµРёР·РІРµСЃС‚РЅРѕ",
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

    command_seq_map = cache.get("_last_command_seq_by_chat")
    if not isinstance(command_seq_map, dict):
        cache["_last_command_seq_by_chat"] = {}

    return cache


def save_cache(cache):
    """РЎРѕС…СЂР°РЅРёС‚СЊ РєСЌС€ Р°С‚РѕРјР°СЂРЅРѕ."""
    cache_path = Path(CACHE_FILE)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = cache_path.with_name(cache_path.name + ".tmp")

    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")

    tmp_path.replace(cache_path)


def get_org_cache_entry(cache, cache_key):
    """Р’РµСЂРЅСѓС‚СЊ СЃР»РѕРІР°СЂСЊ РєСЌС€Р° РґР»СЏ РѕСЂРіР°РЅРёР·Р°С†РёРё РёР»Рё None."""
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
    """Р’РµСЂРЅСѓС‚СЊ РєР°СЂС‚Сѓ РѕС‚Р»РѕР¶РµРЅРЅС‹С… СѓРІРµРґРѕРјР»РµРЅРёР№."""
    pending = cache.get("_pending")
    if not isinstance(pending, dict):
        pending = {}
        cache["_pending"] = pending
    return pending


def queue_pending_alert(cache, alert_id, alert_payload):
    """Р”РѕР±Р°РІРёС‚СЊ/РѕР±РЅРѕРІРёС‚СЊ РѕС‚Р»РѕР¶РµРЅРЅРѕРµ СѓРІРµРґРѕРјР»РµРЅРёРµ."""
    pending = get_pending_map(cache)
    pending[alert_id] = alert_payload


def prune_stale_pending_alerts(cache, cert_groups):
    """
    РЈРґР°Р»РёС‚СЊ РѕС‚Р»РѕР¶РµРЅРЅС‹Рµ СѓРІРµРґРѕРјР»РµРЅРёСЏ, РєРѕС‚РѕСЂС‹Рµ РѕС‚РЅРѕСЃСЏС‚СЃСЏ Рє СѓР¶Рµ РёР·РјРµРЅС‘РЅРЅС‹Рј
    РёР»Рё РёСЃС‡РµР·РЅСѓРІС€РёРј СЃРµСЂС‚РёС„РёРєР°С‚Р°Рј.
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
    """РћС‚РїСЂР°РІРёС‚СЊ РІСЃРµ РѕС‚Р»РѕР¶РµРЅРЅС‹Рµ СѓРІРµРґРѕРјР»РµРЅРёСЏ, РµСЃР»Рё СЃРµР№С‡Р°СЃ СЂР°Р±РѕС‡РµРµ РІСЂРµРјСЏ."""
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


# -----------------------------------------------------
#  РћСЃРЅРѕРІРЅР°СЏ Р»РѕРіРёРєР°
# -----------------------------------------------------
def main():
    print(f"=== Р—Р°РїСѓСЃРє РїСЂРѕРІРµСЂРєРё СЃРµСЂС‚РёС„РёРєР°С‚РѕРІ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    cache = load_cache()
    cert_paths = find_cert_files(CERT_ROOTS)
    print(f"РќР°Р№РґРµРЅРѕ {len(cert_paths)} С„Р°Р№Р»РѕРІ СЃРµСЂС‚РёС„РёРєР°С‚РѕРІ")

    # Р“СЂСѓРїРїРёСЂСѓРµРј РїРѕ РѕСЂРіР°РЅРёР·Р°С†РёРё/РёРјРµРЅРё Рё РІС‹Р±РёСЂР°РµРј СЃРµСЂС‚РёС„РёРєР°С‚ СЃ СЃР°РјРѕР№ РїРѕР·РґРЅРµР№ РґР°С‚РѕР№ РѕРєРѕРЅС‡Р°РЅРёСЏ
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
            print(f"РћС€РёР±РєР° РїСЂРё РѕР±СЂР°Р±РѕС‚РєРµ {path}: {exc}")

    mode_name = "РїРѕ РѕСЂРіР°РЅРёР·Р°С†РёСЏРј" if GROUP_BY_ORGANIZATION else "РїРѕ РєР°Р¶РґРѕРјСѓ СЃРµСЂС‚РёС„РёРєР°С‚Сѓ"
    print(f"РЎС„РѕСЂРјРёСЂРѕРІР°РЅРѕ {len(cert_groups)} Р·Р°РїРёСЃРµР№ РґР»СЏ СѓРІРµРґРѕРјР»РµРЅРёР№ (СЂРµР¶РёРј: {mode_name})")

    updated = False

    if prune_stale_pending_alerts(cache, cert_groups):
        updated = True

    # РЎРЅР°С‡Р°Р»Р° РѕС‚РїСЂР°РІР»СЏРµРј РЅР°РєРѕРїР»РµРЅРЅС‹Рµ РѕС‚Р»РѕР¶РµРЅРЅС‹Рµ СѓРІРµРґРѕРјР»РµРЅРёСЏ, РµСЃР»Рё СѓР¶Рµ СЂР°Р±РѕС‡РµРµ РІСЂРµРјСЏ
    if process_pending_alerts(cache):
        updated = True

    if process_chat_commands(cache, cert_groups):
        updated = True

    for cache_key, info in sorted(cert_groups.items(), key=lambda item: item[0].lower()):
        org = info["label"]
        expiry_date = info["expiry"]
        expiry_str = info["expiry_str"]
        path = info["path"]
        days_left = (expiry_date - date.today()).days

        cache_entry = get_org_cache_entry(cache, cache_key)

        # Р•СЃР»Рё СЃРµСЂС‚РёС„РёРєР°С‚ Р·Р°РјРµРЅРёР»Рё РЅР° РЅРѕРІС‹Р№ - СЃР±СЂР°СЃС‹РІР°РµРј РёСЃС‚РѕСЂРёСЋ РїРѕ СЌС‚РѕР№ Р·Р°РїРёСЃРё
        if cache_entry and cache_entry.get("expiry_str") != expiry_str:
            print(f"  в†’ {org}: Р·Р°РјРµРЅР° СЃРµСЂС‚РёС„РёРєР°С‚Р° (Р±С‹Р»Рѕ {cache_entry.get('expiry_str')}, СЃС‚Р°Р»Рѕ {expiry_str})")
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
                print(f"  в†’ РЈРІРµРґРѕРјР»РµРЅРёРµ РґР»СЏ {org} РѕС‚Р»РѕР¶РµРЅРѕ (РЅРµСЂР°Р±РѕС‡РµРµ РІСЂРµРјСЏ)")
                updated = True

        print(f"  {org}: РґРµР№СЃС‚РІСѓРµС‚ РґРѕ {expiry_str}, РѕСЃС‚Р°Р»РѕСЃСЊ {days_left} РґРЅ. РђРєС‚СѓР°Р»СЊРЅС‹Р№ СЃРµСЂС‚: {path.name}")

    if process_chat_commands(cache, cert_groups):
        updated = True

    if updated:
        save_cache(cache)
        print("РљСЌС€ РѕР±РЅРѕРІР»С‘РЅ")
    else:
        print("РќРѕРІС‹С… СѓРІРµРґРѕРјР»РµРЅРёР№ РЅРµС‚")

    print("=== РџСЂРѕРІРµСЂРєР° Р·Р°РІРµСЂС€РµРЅР° ===")

    return cert_groups


def process_chat_commands_fast(cert_groups):
    """Poll commands between full cycles in daemon mode."""
    if not cert_groups:
        return False

    cache = load_cache()
    updated = process_chat_commands(cache, cert_groups)
    if updated:
        save_cache(cache)
        print("Fast command poll: cache updated")
    return updated


def parse_args():
    """CLI options."""
    parser = argparse.ArgumentParser(description="Certificate monitor for MAX")
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously in loop mode",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one cycle and exit",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(DAEMON_LOOP_INTERVAL),
        help="Loop interval in seconds for daemon mode",
    )
    parser.add_argument(
        "--command-interval",
        type=int,
        default=int(COMMAND_LOOP_INTERVAL),
        help="Quick command polling interval in seconds while waiting for next cycle",
    )
    return parser.parse_args()


def run_daemon(interval_seconds, command_interval_seconds):
    """Run bot continuously with fixed interval and fast command polling."""
    interval = max(5, int(interval_seconds))
    command_interval = max(1, int(command_interval_seconds))
    print(
        "=== Daemon mode enabled, "
        f"scan interval {interval} sec, command interval {command_interval} sec ==="
    )
    cert_groups_snapshot = {}

    while True:
        cycle_started = datetime.now()
        try:
            cert_groups_snapshot = main() or {}
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            print(f"Daemon cycle error: {exc}")

        while True:
            elapsed = (datetime.now() - cycle_started).total_seconds()
            remaining = interval - elapsed
            if remaining <= 0:
                break

            try:
                process_chat_commands_fast(cert_groups_snapshot)
            except Exception as exc:
                print(f"Fast command poll error: {exc}")

            sleep_for = min(command_interval, max(1, int(remaining)))
            print(f"Next fast poll in {sleep_for} sec, full cycle in {max(1, int(remaining))} sec")
            time.sleep(sleep_for)


if __name__ == "__main__":
    args = parse_args()
    daemon_enabled = (args.daemon or bool(RUN_AS_DAEMON)) and not args.once
    if daemon_enabled:
        try:
            run_daemon(args.interval, args.command_interval)
        except KeyboardInterrupt:
            print("=== Daemon stopped by user ===")
    else:
        main()

