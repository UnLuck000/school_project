r"""Перенос данных другой версии (релизной в тестовую и наоборот, 14.11.2026).

У версий всё своё: настройки пользователя (%APPDATA%\StretchBitConfiguration[-test]), данные
службы (%ProgramData%\StretchBIT[-test]\service: журнал защиты, белый список, журнал
действий службы, её настройки) и карантин в папке программы. Без переноса новая версия
начинала с нуля: без белого списка, исключений, профилей VPN, журнала и карантина.

Когда переносится:
  * сама, по умолчанию — у этой версии данных ещё нет (первый запуск), а у другой есть:
    копия, у другой всё остаётся;
  * по просьбе установщика — пользователь выбрал «Удалить» другую версию (installer.iss
    пишет метку app\transfer_from.txt с отметкой времени): её данные заменяют данные этой
    версии, прежние откладываются во вложенную папку before-<отметка>. Один раз на отметку
    (в папке данных — transfer.done). Карантин и свою базу хэшей (они в папке программы,
    которую деинсталлятор другой версии удаляет) установщик копирует сам до её удаления.

Что поправляется после копии:
  * полные пути старой папки в журнале действий и журнале защиты (копии для отмены);
  * подписи журнала действий: запись, подпись которой сошлась с ключом другой версии
    (%ProgramData%\...\cache.key, читают только администраторы и система), подписывается
    своим ключом; подпись не сошлась — остаётся (отмена запрещена, как у подделки); проверить
    нечем (нет прав) — подпись снимается: отмена спросит пользователя (UnsignedRecord);
  * белый список, исключения, переопределения баз и защищённые настройки (trustseal) берутся
    из защищённых копий другой версии, если они есть, и принимаются как записанные программой;
  * копии состояния VPN для возврата после сбоя (kill switch, DNS, прокси) не переносятся:
    они относятся к прошлому подключению другой версии.

Только в собранной программе: из исходников (python gui.py, тесты) — ничего.
"""
import hmac
import json
import os
import re
import shutil
import sys
from pathlib import Path

DONE = "transfer.done"
BACKUP_PREFIX = "before-"   # прежние данные этой версии при замене (по просьбе установщика)
MARKER = "transfer_from.txt"
SEALED = ("whitelist.json", "exclusions.json", "overrides.json", "secure_settings.json")
PATH_FILES = ("journal/actions.jsonl", "journal/threats.json")
VPN_STATE_KEYS = ("killswitch_backup", "dns_backup", "proxy_backup")  # раздел [vpn]
LINK_TAGS = {0xA0000003, 0xA000000C}  # ссылка-папка и символическая ссылка
STAMP_RE = re.compile(r"^[0-9A-Za-z_.-]{1,64}$")


def _root_secured(root: Path) -> bool:
    import trustseal
    return root.is_dir() and trustseal._root_secured(root)


# ---------- где что лежит ----------
def other_config_dir() -> Path:
    import userdata
    from diag import edition
    return userdata.CONFIG_DIR.with_name(userdata.NAME + ("" if edition.is_test() else "-test"))


def other_root() -> Path:
    """%ProgramData%\\StretchBIT[-test] другой версии."""
    import trustseal
    from diag import edition
    return trustseal.protected_dir().with_name("StretchBIT" if edition.is_test()
                                               else "StretchBIT-test")


def requested(app_dir: Path | None = None) -> str:
    """Отметка просьбы установщика (другую версию удалили) или ''. Метка лежит в папке
    программы, которую меняют только администраторы."""
    if app_dir is None:
        import userdata
        app_dir = userdata.APP_DIR
    try:
        stamp = (Path(app_dir) / MARKER).read_text(encoding="utf-8-sig").strip()
    except OSError:
        return ""
    return stamp if STAMP_RE.match(stamp) else ""


# ---------- файлы ----------
def _is_link(path: str) -> bool:
    try:
        return getattr(os.lstat(path), "st_reparse_tag", 0) in LINK_TAGS or os.path.islink(path)
    except OSError:
        return True


def _has_files(folder: Path) -> bool:
    """В папке есть хоть один файл (кроме отметки переноса); ссылки не обходятся."""
    if not folder.is_dir():
        return False
    for current, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if not _is_link(os.path.join(current, d))
                   and not (Path(current) == folder and d.startswith(BACKUP_PREFIX))]
        if any(f != DONE for f in files):
            return True
    return False


def _copy(src: Path, dst: Path) -> list[str]:
    """Копия папки без ссылок (ссылка-папка увела бы копирование в чужое место). Ошибки
    отдельных файлов (занят) — в список, остальное копируется."""
    def ignore(folder, names):
        top = Path(folder) == src
        return [n for n in names if n == DONE or _is_link(os.path.join(folder, n))
                or (top and n.startswith(BACKUP_PREFIX))]
    try:
        shutil.copytree(src, dst, ignore=ignore, dirs_exist_ok=True)
    except shutil.Error as e:
        return [f"не скопировано: {item[0]} ({item[2]})" for item in e.args[0][:20]]
    return []


def _replace_paths(text: str, old: Path, new: Path) -> str:
    """Полные пути старой папки → новой: как есть и в JSON (обратные слэши удвоены). Только
    целым именем папки: «...Configuration» не задевает «...Configuration-test»."""
    for a, b in ((str(old), str(new)),
                 (str(old).replace("\\", "\\\\"), str(new).replace("\\", "\\\\"))):
        text = re.sub(re.escape(a) + r"(?![\w-])", lambda _m, b=b: b, text, flags=re.IGNORECASE)
    return text


def _read_key(root: Path) -> bytes:
    """Ключ подписи другой версии — только из закрытого корня (иначе ключ мог подложить кто
    угодно и «подписать» им свои записи)."""
    if not _root_secured(root):
        return b""
    try:
        return (root / "cache.key").read_bytes()
    except OSError:
        return b""


def _own_key() -> bytes:
    import trustseal
    try:
        return trustseal.mac_key()
    except OSError:
        return b""


def _resign_journal(src: Path, dst: Path, other_key: bytes, own_key: bytes) -> int:
    """actions.jsonl: подпись проверяется по исходной записи (до правки путей), затем
    запись с новыми путями подписывается своим ключом. Возвращает число переподписанных."""
    from recovery.journal import signature_with
    src_file, dst_file = src / "journal" / "actions.jsonl", dst / "journal" / "actions.jsonl"
    if not src_file.is_file():
        return 0
    out, resigned = [], 0
    for line in src_file.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
            fixed = json.loads(_replace_paths(line, src, dst))
        except ValueError:
            continue
        if not isinstance(record, dict) or not isinstance(fixed, dict):
            continue
        mac = record.get("mac") or ""
        verdict = "unsigned"
        if mac and other_key:
            expected = signature_with(record, other_key)
            verdict = "ok" if hmac.compare_digest(mac, expected) else "forged"
        elif mac:
            verdict = "unknown"
        if verdict == "ok" and own_key:
            fixed["mac"] = signature_with(fixed, own_key)
            resigned += 1
        elif verdict != "forged":
            fixed.pop("mac", None)   # проверить нечем — отмена спросит пользователя
        out.append(json.dumps(fixed, ensure_ascii=False) + "\n")
    dst_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst_file.with_suffix(".jsonl.tmp")
    tmp.write_text("".join(out), encoding="utf-8")
    os.replace(tmp, dst_file)
    return resigned


def _sealed_content(src_file: Path, root: Path) -> bytes | None:
    """Содержимое списка доверия другой версии, которому можно верить: её защищённая копия;
    копий у неё нет вовсе — сам файл (доверие при первом использовании, как у trustseal);
    копии нет только у этого файла, а она уже всё приняла — None (файл появился не из
    программы, она сама его не принимала)."""
    import hashlib
    try:
        data = src_file.read_bytes()
    except OSError:
        data = b""
    trusted = root / "trusted"
    if not trusted.is_dir() or not _root_secured(root):
        return data
    tag = hashlib.sha256(os.path.normcase(str(src_file)).encode("utf-8")).hexdigest()[:10]
    mirror = trusted / f"{src_file.name}.{tag}"
    try:
        return mirror.read_bytes()
    except OSError:
        return None if (trusted / ".initialized").exists() else data


def _seal(src: Path, dst: Path, root: Path) -> list[str]:
    import trustseal
    notes = []
    for name in SEALED:
        src_file, dst_file = src / name, dst / name
        if not src_file.exists():
            continue
        data = _sealed_content(src_file, root)
        try:
            if data is None:
                dst_file.unlink(missing_ok=True)
                notes.append(f"{name}: не перенесён — у другой версии он изменён не программой")
                continue
            dst_file.write_bytes(data)
        except OSError as e:
            notes.append(f"{name}: {e}")
            continue
        trustseal.saved(dst_file)
    return notes


def _drop_vpn_state(settings: Path) -> None:
    """Из settings.ini — копии для возврата после сбоя VPN другой версии (раздел [vpn])."""
    try:
        lines = settings.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError):
        return
    out, section = [], ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].lower()
        elif section == "vpn" and stripped.split("=", 1)[0].strip() in VPN_STATE_KEYS:
            continue
        out.append(line)
    if len(out) != len(lines):
        try:
            settings.write_text("".join(out), encoding="utf-8")
        except OSError:
            pass


def _aside(dst: Path, stamp: str) -> Path:
    """Свои данные — во вложенную папку before-<отметка>: внутри той же папки остаются и её
    права (у службы — только администраторы и система: журнал защиты с путями файлов всех
    пользователей; рядом, в корне ProgramData, папку читали бы все)."""
    backup = dst / f"{BACKUP_PREFIX}{stamp}"
    n = 1
    while backup.exists():
        n += 1
        backup = dst / f"{BACKUP_PREFIX}{stamp}-{n}"
    backup.mkdir()
    for child in list(dst.iterdir()):
        if child == backup or child.name == DONE or child.name.startswith(BACKUP_PREFIX):
            continue
        os.replace(child, backup / child.name)
    return backup


# ---------- перенос ----------
def transfer(src: Path, dst: Path, root: Path, stamp: str = "") -> list[str]:
    """Перенести папку данных другой версии src в свою dst. root — %ProgramData% другой
    версии (её ключ подписи и защищённые копии). stamp — просьба установщика (заменить свои
    данные); без неё — только если своих данных нет. Возвращает строки для журнала."""
    src, dst, root = Path(src), Path(dst), Path(root)
    done_file = dst / DONE
    try:
        done = done_file.read_text(encoding="utf-8").strip()
    except OSError:
        done = ""
    if stamp and done == stamp:
        return []
    mine = _has_files(dst)
    if mine and not stamp:
        return []
    if not _has_files(src) or src.resolve() == dst.resolve():
        if stamp:
            _write_done(done_file, stamp)
        return []
    lines = []
    if mine:
        try:
            lines.append(f"прежние данные этой версии отложены: {_aside(dst, stamp)}")
        except OSError as e:
            return [f"не перенесено: свои данные не отложить ({e})"]
    dst.mkdir(parents=True, exist_ok=True)
    lines += _copy(src, dst)
    for name in PATH_FILES:
        if name == "journal/actions.jsonl":
            continue
        f = dst / name
        try:
            text = f.read_text(encoding="utf-8")
            fixed = _replace_paths(text, src, dst)
            if fixed != text:
                f.write_text(fixed, encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    try:
        n = _resign_journal(src, dst, _read_key(root), _own_key())
        if n:
            lines.append(f"журнал действий: переподписано записей — {n}")
    except (OSError, UnicodeDecodeError) as e:
        lines.append(f"журнал действий: {e}")
    lines += _seal(src, dst, root)
    _drop_vpn_state(dst / "settings.ini")
    _write_done(done_file, stamp or "auto")
    lines.insert(0, f"перенесены данные другой версии: {src} -> {dst}")
    return lines


def _write_done(done_file: Path, stamp: str) -> None:
    try:
        done_file.parent.mkdir(parents=True, exist_ok=True)
        done_file.write_text(stamp, encoding="utf-8")
    except OSError:
        pass


def _enabled() -> bool:
    return bool(getattr(sys, "frozen", False)) and sys.platform == "win32"


def window() -> list[str]:
    """Окно: папка конфигурации пользователя (вызывается в начале gui.py)."""
    if not _enabled():
        return []
    import userdata
    return transfer(other_config_dir(), userdata.CONFIG_DIR, other_root(), requested())


def service(folder: Path) -> list[str]:
    """Служба: её папка данных в ProgramData (до запуска ядра)."""
    if not _enabled():
        return []
    return transfer(other_root() / "service", Path(folder), other_root(), requested())
