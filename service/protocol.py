"""Протокол канала службы: имена, сообщения, права операций.

Сообщение — JSON в UTF-8, одно сообщение канала (режим PIPE_TYPE_MESSAGE) — один запрос или
ответ:
    запрос  {"id": 1, "op": "status", "args": {...}}
    ответ   {"id": 1, "ok": true, "result": ...}
            {"id": 1, "ok": false, "error": "текст", "type": "PermissionError"}
"""
import json
import os
import sys

from diag import edition

MAX_REQUEST = 1 << 20          # запрос клиента
MAX_REPLY = 32 << 20           # ответ службы (журнал защиты со сводками бывает большим)
PROTOCOL = 2

# уровни прав (service/DESIGN.md)
READ, CONTROL, WEAKEN, ADMIN = "read", "control", "weaken", "admin"

OPS = {
    "hello": READ,
    "status": READ,
    "events": READ,
    "protection.set": CONTROL,      # выключение и удаление папок — WEAKEN (core.weakens)
    "bases.reload": CONTROL,
    "quarantine.list": READ,
    "quarantine.add": CONTROL,
    "quarantine.delete": CONTROL,
    "quarantine.restore": WEAKEN,
    "threats.list": READ,
    "threats.get": READ,
    "threats.add": CONTROL,
    "threats.set_status": CONTROL,
    "threats.mark_path": CONTROL,
    "threats.dismiss": CONTROL,
    "whitelist.list": READ,
    "whitelist.add": WEAKEN,
    "whitelist.remove": CONTROL,
    "config.set": ADMIN,
    # защиты с правами (service/guards.py); выключение — WEAKEN внутри операции
    "guards.state": READ,
    "guards.set": CONTROL,
    "stealer.decide": CONTROL,      # allow — WEAKEN
    "amsi.register": CONTROL,       # снять — WEAKEN
    "pslog.policy": CONTROL,        # выключить — WEAKEN
    "net.sensors": CONTROL,         # выключить — WEAKEN
    "story.get": READ,
    # брандмауэр
    "firewall.block_ip": CONTROL,
    "firewall.block_program": CONTROL,
    "firewall.unblock": WEAKEN,
    # журнал действий службы
    "journal.list": READ,
    "journal.undo": WEAKEN,
    "journal.cleanup": CONTROL,
    # VPN с правами (service/vpnhost.py)
    "vpn.connect": CONTROL,
    "vpn.disconnect": CONTROL,
    "vpn.status": READ,
    "vpn.counters": READ,
    "vpn.release_block": CONTROL,
}

# исключения, которые проходят через канал как есть (остальные — ServiceError)
ERROR_TYPES = ("FileExistsError", "FileNotFoundError", "ValueError", "PermissionError",
               "NeedAdmin", "Refused")


def service_name() -> str:
    return "StretchBITService" + ("-test" if edition.is_test() else "")


def display_name() -> str:
    return "StretchBIT — защита" + (" (тест)" if edition.is_test() else "")


def pipe_name() -> str:
    return r"\\.\pipe\sbit-service" + ("-test" if edition.is_test() else "")


DESCRIPTION = ("Движок антивируса StretchBIT: защита файлов, контроль запуска, защита от "
               "стилеров, AMSI, мониторинг сети, брандмауэр и VPN с правами системы. Окно "
               "программы работает без прав администратора и обращается к службе по каналу.")

DEV_ENV = "STRETCHBIT_SERVICE_DEV"   # из исходников: интерфейс ищет службу в консоли


def dev_mode() -> bool:
    """Запуск из исходников с ядром службы в консоли (python -m service --console)."""
    return not getattr(sys, "frozen", False) and os.environ.get(DEV_ENV) == "1"


def encode(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def decode(data: bytes):
    return json.loads(data.decode("utf-8"))


def request(rid: int, op: str, args: dict | None = None) -> bytes:
    return encode({"id": rid, "op": op, "args": args or {}})


def ok(rid, result) -> bytes:
    return encode({"id": rid, "ok": True, "result": result})


def fail(rid, error: str, kind: str = "ServiceError") -> bytes:
    return encode({"id": rid, "ok": False, "error": error, "type": kind})
