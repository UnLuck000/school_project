"""Проверка секретной комбинации для скрытого режима отладки.
Эта папка исключена из Git. Добавить комбинацию: python debug_mode/gate.py add"""
import getpass
import hashlib
import secrets
import sys
from pathlib import Path

PASSWORDS_FILE = Path(__file__).resolve().parent / "passwords.txt"
MAX_LEN = 64
HEADER = ("# Хэши допустимых комбинаций (не сами пароли).\n"
          "# Добавить новую: python debug_mode/gate.py add\n")


def _load() -> tuple[str, set[str]]:
    if not PASSWORDS_FILE.exists():
        return "", set()
    salt, hashes = "", set()
    for line in PASSWORDS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("salt:"):
            salt = line[5:]
        else:
            hashes.add(line.lower())
    return salt, hashes


def _hash(salt: str, text: str) -> str:
    return hashlib.sha256((salt + text.lower()).encode("utf-8")).hexdigest()


_SALT, _HASHES = _load()


def check(typed: str) -> bool:
    """Заканчивается ли набранное на одну из допустимых комбинаций (без учёта регистра)."""
    if not _HASHES:
        return False
    tail = typed[-MAX_LEN:]
    return any(_hash(_SALT, tail[i:]) in _HASHES for i in range(len(tail)))


def add(password: str) -> None:
    salt, hashes = _load()
    if not salt:
        salt = secrets.token_hex(8)
    hashes.add(_hash(salt, password))
    PASSWORDS_FILE.write_text(
        HEADER + f"salt:{salt}\n" + "\n".join(sorted(hashes)) + "\n", encoding="utf-8")


if __name__ == "__main__":
    command = sys.argv[1:2]
    if command == ["add"]:
        value = getpass.getpass("Новая комбинация: ")
        if len(value) < 6:
            sys.exit("Слишком короткая комбинация (минимум 6 символов)")
        add(value)
        print(f"Готово. Комбинаций в файле: {len(_load()[1])}")
    elif command == ["test"]:
        value = getpass.getpass("Проверить комбинацию: ")
        print("Совпадает" if check(value) else "Не совпадает",
              f"(комбинаций в файле: {len(_HASHES)})")
    else:
        print("Использование: python debug_mode/gate.py add | test")
