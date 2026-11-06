"""Ручная правка баз против ложных срабатываний: хэши, убранные из базы, и отключённые
правила YARA. Хранится в signatures/overrides.json (не в Git): обновление баз скачивает
файлы заново, а этот список продолжает действовать поверх них.
Каждое изменение пишется в журнал действий с возможностью отмены."""
import json
import os
import threading
from datetime import datetime
from pathlib import Path

from recovery import journal
from recovery.journal import undo_op

OVERRIDES_FILE = Path(__file__).resolve().parent.parent / "signatures" / "overrides.json"

_lock = threading.Lock()
_cache: tuple[float, dict] | None = None  # (mtime файла, данные)


def load() -> dict:
    """{"hashes": {хэш: {...}}, "rules": {имя: {...}}}. Перечитывается при изменении файла."""
    global _cache
    try:
        mtime = OVERRIDES_FILE.stat().st_mtime_ns
    except OSError:
        return {"hashes": {}, "rules": {}}
    with _lock:
        if _cache is None or _cache[0] != mtime:
            try:
                data = json.loads(OVERRIDES_FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
            data = {"hashes": dict(data.get("hashes") or {}), "rules": dict(data.get("rules") or {})}
            _cache = (mtime, data)
        return _cache[1]


def _save(data: dict) -> None:
    OVERRIDES_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = OVERRIDES_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, OVERRIDES_FILE)


def version() -> str:
    """Меняется при каждой правке: кэш вердиктов по нему понимает, что пора перепроверить."""
    try:
        return str(OVERRIDES_FILE.stat().st_mtime_ns)
    except OSError:
        return "0"


def hash_ignored(digest: str) -> bool:
    return digest.lower() in load()["hashes"]


def rule_disabled(name: str) -> bool:
    return name in load()["rules"]


def active_rules(names: list[str]) -> list[str]:
    """Сработавшие правила без отключённых вручную."""
    disabled = load()["rules"]
    return [n for n in names if n not in disabled]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def ignore_hash(digest: str, path: str = "", source: str = "", note: str = "") -> bool:
    """Убирает хэш из базы (поверх скачанных файлов). False, если он уже убран."""
    digest = digest.strip().lower()
    data = load()
    if digest in data["hashes"]:
        return False
    data = {"hashes": {**data["hashes"], digest: {"path": path, "source": source,
                                                  "note": note, "added_at": _now()}},
            "rules": data["rules"]}
    _save(data)
    name = os.path.basename(path) or digest[:16]
    journal.log_action(f"Хэш «{name}» убран из базы сигнатур (ложное срабатывание)",
                       "fp_hash_restore", {"hash": digest, "path": path})
    return True


def restore_hash(digest: str) -> bool:
    data = load()
    hashes = dict(data["hashes"])
    if hashes.pop(digest.strip().lower(), None) is None:
        return False
    _save({"hashes": hashes, "rules": data["rules"]})
    return True


def disable_rule(name: str, source: str = "", note: str = "") -> bool:
    """Отключает правило YARA по имени. False, если оно уже отключено."""
    data = load()
    if name in data["rules"]:
        return False
    _save({"hashes": data["hashes"],
           "rules": {**data["rules"], name: {"source": source, "note": note, "added_at": _now()}}})
    journal.log_action(f"Правило YARA {name} отключено (ложное срабатывание)",
                       "fp_rule_enable", {"rule": name})
    return True


def enable_rule(name: str) -> bool:
    data = load()
    rules = dict(data["rules"])
    if rules.pop(name, None) is None:
        return False
    _save({"hashes": data["hashes"], "rules": rules})
    return True


@undo_op("fp_hash_restore")
def _undo_hash(d: dict) -> str:
    restore_hash(d["hash"])
    return f"Хэш снова в базе: {os.path.basename(d.get('path') or '') or d['hash'][:16]}"


@undo_op("fp_rule_enable")
def _undo_rule(d: dict) -> str:
    enable_rule(d["rule"])
    return f"Правило {d['rule']} снова включено"
