"""Исключения: то, чему пользователь доверяет.

Два файла:
• signatures/exclusions.json — локальные (автозапуск, находки проверки системы): зависят от
  конкретного компьютера, в Git и релиз не попадают;
• signatures/release_exclusions.json — RELEASE_CATEGORIES: заранее известные безвредные
  файлы, которые базы помечают вредоносными (winws.exe и WinDivert из zapret, MsIo64.sys от
  MSI): drivers — для окна уязвимых драйверов, programs — для всех проверок файлов
  (whitelist.trusted_hashes). Хранится в Git и попадает в релиз. Белый список пользователя
  (signatures/whitelist.json: файлы, возвращённые из карантина) — только на этом компьютере.
• TEST_TO_RELEASE (network — программы без оповещений мониторинга сети): в тестовой версии
  пишутся в релизный файл (разработчик исключает их для всех), в релизной — локально;
  читаются из обоих.
"""
import json
import os
import threading
from datetime import datetime
from pathlib import Path

import trustseal
import userdata

EXCLUSIONS_FILE = userdata.EXCLUSIONS_FILE  # папка конфигурации пользователя
RELEASE_FILE = Path(__file__).resolve().parent.parent / "signatures" / "release_exclusions.json"
RELEASE_CATEGORIES = {"drivers", "programs"}
TEST_TO_RELEASE = {"network"}
CATEGORY_TEXT = {"autoruns": "Автозапуск", "checks": "Проверка системы",
                 "drivers": "Драйверы (в релизе)", "programs": "Программы (в релизе)",
                 "network": "Мониторинг сети"}
_lock = threading.Lock()


def fingerprint(path) -> list | None:
    """[размер, время изменения] файла. Исключение действует, пока файл не менялся."""
    if not path:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return [st.st_size, st.st_mtime_ns]


def entry_key(e) -> str:
    return f"{e.kind}|{e.location}|{e.name}|{e.command}"


def finding_key(f) -> str:
    return f"{f.category}|{f.title}|{f.status}|{f.detail}"


def hit_key(h) -> str:
    return f"policy|{h.hive}|{h.path}|{h.name}|{h.value}"


def _file(category: str) -> Path:
    if category in RELEASE_CATEGORIES:
        return RELEASE_FILE
    if category in TEST_TO_RELEASE:
        from diag import edition
        return RELEASE_FILE if edition.is_test() else EXCLUSIONS_FILE
    return EXCLUSIONS_FILE


def _read_file(path: Path) -> dict:
    try:
        if path == EXCLUSIONS_FILE:  # файл пользователя — через защиту от подмены
            data = json.loads(trustseal.read(path).decode("utf-8"))
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _read() -> dict:
    """Оба файла вместе (TEST_TO_RELEASE — записи из обоих)."""
    data = _read_file(EXCLUSIONS_FILE)
    for category, entries in _read_file(RELEASE_FILE).items():
        if category in RELEASE_CATEGORIES:
            data[category] = entries
        elif category in TEST_TO_RELEASE and isinstance(entries, dict):
            data[category] = {**entries, **data.get(category, {})}
    return data


def _save(data: dict, path: Path = EXCLUSIONS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # запись через временный файл
    if path == EXCLUSIONS_FILE:
        trustseal.saved(path)
    from scanner import whitelist
    whitelist.forget_trusted()


def load() -> dict:
    """Все исключения. Читается один раз на проверку, дальше используется matches()."""
    with _lock:
        return _read()


def matches(data: dict, category: str, key: str, fp=None) -> bool:
    item = data.get(category, {}).get(key)
    return item is not None and item.get("fp") == fp


def add(category: str, key: str, title: str, detail: str = "", fp=None) -> None:
    with _lock:
        path = _file(category)
        data = _read_file(path)
        data.setdefault(category, {})[key] = {
            "title": title, "detail": detail, "fp": fp,
            "added": datetime.now().isoformat(timespec="seconds")}
        _save(data, path)


def remove(category: str, key: str) -> bool:
    with _lock:
        paths = [_file(category)]
        if category in TEST_TO_RELEASE:  # запись могла быть сделана в другой версии
            paths = [EXCLUSIONS_FILE, RELEASE_FILE]
        removed = False
        for path in paths:
            data = _read_file(path)
            if data.get(category, {}).pop(key, None) is not None:
                _save(data, path)
                removed = True
        return removed


def program_key(exe: str, publisher: str | None = None, sha256: str = "") -> str:
    """Ключ программы, одинаковый на любом компьютере: имя файла и издатель подписи, а у
    неподписанной — имя файла и SHA-256 (обновится файл — исключение перестанет действовать)."""
    name = os.path.basename(exe).lower()
    return f"{name}|pub:{publisher}" if publisher else f"{name}|sha256:{sha256.lower()}"


def items() -> list[dict]:
    """Плоский список для показа: категория, ключ, название, подробности, дата."""
    result = []
    for category, entries in load().items():
        for key, item in entries.items():
            result.append({"category": category, "key": key, "title": item.get("title", ""),
                           "detail": item.get("detail", ""), "added": item.get("added", "")})
    return sorted(result, key=lambda i: i["added"], reverse=True)
