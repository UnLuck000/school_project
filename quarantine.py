import json
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from scanner.hashing import sha256_of, load_signatures
from scanner.whitelist import add_to_whitelist
from scanner.signature import describe, inspect_signature

QUARANTINE_DIR = Path("quarantine_data").resolve()
SIGNATURES_FILE = Path("signatures/hashes.txt")

STATUS_QUARANTINED = "quarantined"
STATUS_RESTORED = "restored"
STATUS_DELETED = "deleted"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _meta_path(item_id: str) -> Path:
    return QUARANTINE_DIR / f"{item_id}.json"


def _stored_path(item_id: str) -> Path:
    return QUARANTINE_DIR / f"{item_id}.quar"


def _read_meta(item_id: str) -> dict:
    meta = json.loads(_meta_path(item_id).read_text(encoding="utf-8"))
    # записи, созданные до появления статусов, считаем находящимися в карантине
    meta.setdefault("status", STATUS_QUARANTINED)
    return meta


def _write_meta(meta: dict) -> None:
    """Записывает метаданные через временный файл, чтобы JSON не повредился при сбое."""
    path = _meta_path(meta["id"])
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def add_hash_to_signatures(sha256: str) -> bool:
    """Дописывает хэш в hashes.txt. Возвращает False, если он там уже есть."""
    sha256 = sha256.strip().lower()
    SIGNATURES_FILE.parent.mkdir(parents=True, exist_ok=True)

    needs_newline = False
    if SIGNATURES_FILE.exists():
        if sha256 in load_signatures(SIGNATURES_FILE):
            return False
        content = SIGNATURES_FILE.read_bytes()
        needs_newline = bool(content) and not content.endswith(b"\n")

    with SIGNATURES_FILE.open("a", encoding="utf-8") as f:
        if needs_newline:  # последняя строка без переноса: не склеиваем хэши
            f.write("\n")
        f.write(sha256 + "\n")
    return True


def quarantine_file(path: Path, reason: str) -> str:
    """Перемещает файл в карантин и возвращает его идентификатор."""
    QUARANTINE_DIR.mkdir(exist_ok=True)
    path = Path(path).resolve()

    # сначала подпись, потом словарь: переменная должна существовать до его создания
    try:
        signature_text = describe(inspect_signature(path))
    except Exception:  # подпись не должна мешать изоляции файла
        signature_text = ""

    item_id = uuid.uuid4().hex
    meta = {
        "id": item_id,
        "status": STATUS_QUARANTINED,
        "original_path": str(path),
        "sha256": sha256_of(path),
        "size": path.stat().st_size,
        "reason": reason,
        "signature": signature_text,
        "quarantined_at": _now(),
    }

    _write_meta(meta)
    try:
        shutil.move(str(path), _stored_path(item_id))
    except Exception:
        _meta_path(item_id).unlink(missing_ok=True)
        raise
    return item_id

def list_quarantine(include_history: bool = False) -> list[dict]:
    """По умолчанию возвращает только файлы, которые сейчас в карантине.
    С include_history=True добавляет восстановленные и удалённые записи."""
    if not QUARANTINE_DIR.exists():
        return []
    items = []
    for meta_file in QUARANTINE_DIR.glob("*.json"):
        meta = _read_meta(meta_file.stem)
        if include_history or meta["status"] == STATUS_QUARANTINED:
            items.append(meta)
    return sorted(items, key=lambda m: m["quarantined_at"])


def restore_file(item_id: str, overwrite: bool = False, whitelist: bool = True) -> Path:
    """Возвращает файл на исходное место. JSON остаётся со статусом «restored».
    По умолчанию хэш файла заносится в белый список."""
    meta = _read_meta(item_id)
    if meta["status"] != STATUS_QUARANTINED:
        raise ValueError("Этот элемент уже восстановлен или удалён")

    stored = _stored_path(item_id)
    if sha256_of(stored) != meta["sha256"]:
        raise ValueError("Хэш изменился: файл в карантине повреждён")

    dest = Path(meta["original_path"])
    if dest.exists() and not overwrite:
        raise FileExistsError(f"По пути {dest} уже есть файл")

    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), dest)

    meta["status"] = STATUS_RESTORED
    meta["restored_at"] = _now()
    _write_meta(meta)

    if whitelist:
        add_to_whitelist(meta["sha256"], str(dest))
    return dest


def delete_file(item_id: str) -> bool:
    """Удаляет файл, оставляет JSON со статусом «deleted» и заносит хэш в базу сигнатур.
    Возвращает True, если хэш был добавлен в hashes.txt (False, если уже был там)."""
    meta = _read_meta(item_id)
    if meta["status"] != STATUS_QUARANTINED:
        raise ValueError("Этот элемент уже восстановлен или удалён")

    added = add_hash_to_signatures(meta["sha256"])  # операция безопасна для повтора
    _stored_path(item_id).unlink(missing_ok=True)

    meta["status"] = STATUS_DELETED
    meta["deleted_at"] = _now()
    _write_meta(meta)
    return added