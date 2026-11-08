"""Ручная правка баз против ложных срабатываний: хэши, убранные из базы, отключённые
правила YARA и исключённые программы (файл по SHA-256: не судить его по хэшу и/или по YARA —
остальные слои действуют, в отличие от белого списка). Обновление баз скачивает файлы
заново, а эти списки продолжают действовать поверх них.

Два файла, читаются вместе:
• signatures/release_overrides.json — в Git и в сборке. Сюда пишет тестовая версия (и запуск
  из исходников): всё, что разработчик исключил при тестировании, попадает в релиз.
  build_release.py перед сборкой вливает сюда исключения из установленной тестовой версии;
• signatures/overrides.json — только этот компьютер: сюда пишет релизная версия.
Каждое изменение пишется в журнал действий с возможностью отмены."""
import json
import os
import threading
from datetime import datetime
from pathlib import Path

from recovery import journal
from recovery.journal import active_check, undo_op

OVERRIDES_FILE = Path(__file__).resolve().parent.parent / "signatures" / "overrides.json"
RELEASE_FILE = OVERRIDES_FILE.with_name("release_overrides.json")
KINDS = ("hashes", "rules", "files")

_lock = threading.Lock()
_cache: tuple[tuple, dict] | None = None  # (время изменения обоих файлов, данные)


def _mtime(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def read_file(path: Path) -> dict:
    """Один файл: {"hashes": {...}, "rules": {...}, "files": {...}}."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {kind: dict(data.get(kind) or {}) for kind in KINDS}


def write_file(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({k: data.get(k, {}) for k in KINDS}, ensure_ascii=False,
                              indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def merge(*sources: dict) -> dict:
    """Объединение файлов: при совпадении ключа — запись из последнего."""
    result = {kind: {} for kind in KINDS}
    for data in sources:
        for kind in KINDS:
            result[kind].update(data.get(kind) or {})
    return result


def load() -> dict:
    """{"hashes": {хэш: {...}}, "rules": {имя: {...}}, "files": {sha256: {"layers": [...]}}}
    из обоих файлов. Перечитывается при изменении любого из них."""
    global _cache
    stamp = (_mtime(RELEASE_FILE), _mtime(OVERRIDES_FILE), str(RELEASE_FILE), str(OVERRIDES_FILE))
    with _lock:
        if _cache is None or _cache[0] != stamp:
            _cache = (stamp, merge(read_file(RELEASE_FILE), read_file(OVERRIDES_FILE)))
        return _cache[1]


def target_file() -> Path:
    """Куда пишутся новые исключения: тестовая версия — в релизный файл."""
    from diag import edition
    return RELEASE_FILE if edition.is_test() else OVERRIDES_FILE


def _add(kind: str, key: str, info: dict) -> None:
    path = target_file()
    if path == RELEASE_FILE and info.get("path"):
        # релизный файл — в Git: вместо папки профиля и имени учётной записи — %USERPROFILE%...
        from diag.anon import anonymize_user
        info = {**info, "path": anonymize_user(info["path"])}
    data = read_file(path)
    data[kind][key] = info
    write_file(path, data)


def _remove(kind: str, key: str) -> bool:
    """Убирает запись из обоих файлов (она могла быть сделана в другой версии)."""
    removed = False
    for path in (OVERRIDES_FILE, RELEASE_FILE):
        data = read_file(path)
        if data[kind].pop(key, None) is not None:
            write_file(path, data)
            removed = True
    return removed


def version() -> str:
    """Меняется при каждой правке: кэш вердиктов по нему понимает, что пора перепроверить."""
    return f"{_mtime(RELEASE_FILE)}.{_mtime(OVERRIDES_FILE)}"


def hash_ignored(digest: str) -> bool:
    return digest.lower() in load()["hashes"]


def rule_disabled(name: str) -> bool:
    return name in load()["rules"]


FILE_LAYERS = {"hash": "базы хэшей", "yara": "правила YARA"}


def file_excluded(digest: str, layer: str) -> bool:
    """Программа (по SHA-256) исключена из слоя hash или yara."""
    info = load()["files"].get((digest or "").lower())
    return bool(info) and layer in info.get("layers", [])


def filter_reason(digest: str, reason: str | None) -> str | None:
    """Вердикт движка с учётом исключённых программ: срабатывание исключённого слоя
    (хэш, YARA) не считается угрозой."""
    if not reason or not digest or not load()["files"]:
        return reason
    if reason.startswith("hash match") and file_excluded(digest, "hash"):
        return None
    if reason.startswith("YARA") and file_excluded(digest, "yara"):
        return None
    return reason


def exclude_file(digest: str, path: str, layers: list[str], note: str = "") -> bool:
    """Исключить программу из слоёв layers (hash, yara). Пишется в журнал с откатом."""
    digest = digest.lower()
    old = load()["files"].get(digest)
    merged = sorted(set(layers) | set(old.get("layers", []) if old else []))
    if old and merged == sorted(old.get("layers", [])):
        return False
    _add("files", digest, {"path": path, "layers": merged, "note": note, "added_at": _now()})
    what = " и ".join(FILE_LAYERS[x] for x in layers if x in FILE_LAYERS)
    journal.log_action(f"Программа «{os.path.basename(path) or digest[:16]}» исключена из "
                       f"проверки: {what}", "fp_file_include", {"hash": digest, "path": path})
    return True


def include_file(digest: str) -> bool:
    return _remove("files", digest.lower())


@active_check("fp_file_include")
def _file_active(d: dict) -> bool:
    return d["hash"] in load()["files"]


@undo_op("fp_file_include")
def _undo_file(d: dict) -> str:
    include_file(d["hash"])
    return f"Программа снова проверяется всеми слоями: {os.path.basename(d.get('path') or '')}"


def active_rules(names: list[str]) -> list[str]:
    """Сработавшие правила без отключённых вручную."""
    disabled = load()["rules"]
    return [n for n in names if n not in disabled]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def ignore_hash(digest: str, path: str = "", source: str = "", note: str = "") -> bool:
    """Убирает хэш из базы (поверх скачанных файлов). False, если он уже убран."""
    digest = digest.strip().lower()
    if digest in load()["hashes"]:
        return False
    _add("hashes", digest, {"path": path, "source": source, "note": note, "added_at": _now()})
    name = os.path.basename(path) or digest[:16]
    journal.log_action(f"Хэш «{name}» убран из базы сигнатур (ложное срабатывание)",
                       "fp_hash_restore", {"hash": digest, "path": path})
    return True


def restore_hash(digest: str) -> bool:
    return _remove("hashes", digest.strip().lower())


def disable_rule(name: str, source: str = "", note: str = "") -> bool:
    """Отключает правило YARA по имени. False, если оно уже отключено."""
    if name in load()["rules"]:
        return False
    _add("rules", name, {"source": source, "note": note, "added_at": _now()})
    journal.log_action(f"Правило YARA {name} отключено (ложное срабатывание)",
                       "fp_rule_enable", {"rule": name})
    return True


def enable_rule(name: str) -> bool:
    return _remove("rules", name)


@active_check("fp_hash_restore")
def _hash_active(d: dict) -> bool:
    return hash_ignored(d["hash"])


@active_check("fp_rule_enable")
def _rule_active(d: dict) -> bool:
    return rule_disabled(d["rule"])


@undo_op("fp_hash_restore")
def _undo_hash(d: dict) -> str:
    restore_hash(d["hash"])
    return f"Хэш снова в базе: {os.path.basename(d.get('path') or '') or d['hash'][:16]}"


@undo_op("fp_rule_enable")
def _undo_rule(d: dict) -> str:
    enable_rule(d["rule"])
    return f"Правило {d['rule']} снова включено"
