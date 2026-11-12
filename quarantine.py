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


# Файл в карантине не должен оставаться рабочей программой: его нельзя запустить из папки
# карантина, и на него не срабатывают другие антивирусы. Содержимое — XOR с ключом по кругу
# (это не шифрование от человека, а обезвреживание). В метаданных — "encoding": "xor1";
# записи прежних версий без этого поля лежат как есть и восстанавливаются по-старому.
XOR_KEY = bytes.fromhex("5342495451a7c33e9d18f06b2c74e5b1")
ENCODING = "xor1"
_CHUNK = 1 << 20


def _xor_copy(src: Path, dst: Path) -> None:
    """Копия src в dst через XOR (операция обратима: тем же вызовом обратно)."""
    table = [bytes(b ^ k for b in range(256)) for k in XOR_KEY]
    width = len(XOR_KEY)
    block = _CHUNK - _CHUNK % width  # кусок кратен ключу: его фаза не сбивается
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            chunk = fin.read(block)
            if not chunk:
                break
            out = bytearray(chunk)
            for i in range(width):
                out[i::width] = chunk[i::width].translate(table[i])
            fout.write(out)


def _stored_sha256(meta: dict) -> str:
    """SHA-256 исходного содержимого файла, лежащего в карантине."""
    import hashlib
    stored = _stored_path(meta["id"])
    if meta.get("encoding") != ENCODING:
        return sha256_of(stored)
    digest = hashlib.sha256()
    table = [bytes(b ^ k for b in range(256)) for k in XOR_KEY]
    width = len(XOR_KEY)
    block = _CHUNK - _CHUNK % width
    with open(stored, "rb") as f:
        while True:
            chunk = f.read(block)
            if not chunk:
                break
            out = bytearray(chunk)
            for i in range(width):
                out[i::width] = chunk[i::width].translate(table[i])
            digest.update(out)
    return digest.hexdigest()


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
        "encoding": ENCODING,
    }

    _write_meta(meta)
    stored = _stored_path(item_id)
    try:
        _xor_copy(path, stored)
        path.unlink()  # исходный файл убираем только после готовой копии
    except Exception:
        stored.unlink(missing_ok=True)
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
    if _stored_sha256(meta) != meta["sha256"]:
        raise ValueError("Хэш изменился: файл в карантине повреждён")

    dest = Path(meta["original_path"])
    if dest.exists() and not overwrite:
        raise FileExistsError(f"По пути {dest} уже есть файл")

    dest.parent.mkdir(parents=True, exist_ok=True)
    if meta.get("encoding") == ENCODING:
        tmp = dest.with_name(dest.name + ".sbit-restore")
        try:
            _xor_copy(stored, tmp)
            os.replace(tmp, dest)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        stored.unlink(missing_ok=True)
    else:
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
