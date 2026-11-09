"""Разбор файла на составные части для вкладки «Декомпилятор».

Файл не запускается: всё извлекается чтением. Получается дерево Node:
- PyInstaller (архив CArchive в оверлее PE): скрипты, модули из PYZ (.pyc с восстановленным
  заголовком), библиотеки и данные; зашифрованный PYZ (старый --key) — пометкой;
- .NET: пространства имён и типы (sbit-dotnet tree), встроенные ресурсы — файлами;
- ZIP и всё на нём (jar, apk, docx, nupkg...): файлы архива, .class — для CFR;
- UPX: распакованная копия (upx -d над копией в папке разбора);
- PE: ресурсы с вложенными файлами (MZ, PK, 7z, Rar, крупные RCDATA) и оверлей.
Каждый извлечённый файл разбирается так же (до MAX_DEPTH), потом все проверяются сканером
(check_tree: хэши, YARA, эвристика — scanner.pool в рабочих процессах).

Извлечённое лежит в cache/unpack/<sha256[:16]> внутри папки программы: защита файлов её не
проверяет (exclude), старые разборы удаляются (KEEP_RUNS).
"""
from __future__ import annotations

import hashlib
import json
import marshal
import os
import re
import shutil
import struct
import subprocess
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UNPACK_DIR = ROOT / "cache" / "unpack"
TOOLS = ROOT / "tools" / "bin"
KEEP_RUNS = 5
MAX_DEPTH = 5
MAX_FILES = 5000
MAX_TOTAL = 1024 * 1024 * 1024        # всего извлечено, байт
MAX_ONE = 256 * 1024 * 1024           # один извлекаемый файл
TOOL_TIMEOUT = 120
NO_WINDOW = 0x08000000

PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYI_COOKIE = struct.Struct("!8sIIii64s")
PYI_COOKIE_OLD = struct.Struct("!8sIIii")
PYI_ENTRY = struct.Struct("!IIIIBc")
# магические числа .pyc по версиям: нужны, если в архиве нет PYZ, откуда их взять
PYC_MAGIC = {(3, 6): 3379, (3, 7): 3394, (3, 8): 3413, (3, 9): 3425, (3, 10): 3439,
             (3, 11): 3495, (3, 12): 3531, (3, 13): 3571}
PYI_TYPES = {"s": "скрипт (точка входа)", "m": "модуль", "M": "модуль", "z": "архив PYZ",
             "Z": "архив PYZ", "b": "библиотека", "x": "данные", "o": "параметр запуска",
             "d": "зависимость", "l": "заставка", "n": "символическая ссылка"}
# типы ресурсов PE, в которых вложенных программ не бывает
PLAIN_RESOURCES = {1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 14, 16, 17, 19, 20, 21, 22, 24}
ARCHIVE_HEADS = (b"MZ", b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"\xca\xfe\xba\xbe",
                 b"\x1f\x8b")

KIND_TEXT = {
    "root": "Файл", "pe": "Программа (PE)", "dotnet": "Сборка .NET", "pyinstaller": "PyInstaller",
    "pyz": "Архив PYZ", "pyc": "Python (.pyc)", "zip": "Архив ZIP", "class": "Java (.class)",
    "namespace": "Пространство имён", "type": ".NET тип", "resource": "Ресурс", "overlay":
    "Оверлей", "upx": "Распаковано из UPX", "folder": "Папка", "file": "Файл", "note": "Сведения",
    "function": "Функция (C)",
}


@dataclass
class Node:
    name: str
    kind: str = "file"
    path: str = ""            # извлечённый файл на диске; "" — узел без файла (тип, папка)
    size: int = 0
    note: str = ""
    lang: str = ""            # python | java | csharp | native — чем показывать код
    ref: str = ""             # тип .NET (полное имя) или сборка, которой он принадлежит
    owner: str = ""           # файл сборки .NET для узлов-типов
    children: list[Node] = field(default_factory=list)
    level: str = ""           # threat | suspicious | clean | error — после проверки
    verdict: str = ""

    def add(self, child: Node) -> Node:
        self.children.append(child)
        return child

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def files(self) -> list[Node]:
        return [n for n in self.walk() if n.path and n is not self]


class Budget:
    """Ограничения разбора: zip-бомба или тысячи вложенных файлов не повесят программу."""

    def __init__(self, cancel=None, progress=None):
        self.files = 0
        self.total = 0
        self.cancel = cancel
        self.progress = progress
        self.notes: list[str] = []

    def _limited(self) -> bool:
        if not self.notes:
            self.notes.append(f"Разбор ограничен: не больше {MAX_FILES} файлов и "
                              f"{MAX_TOTAL // 2 ** 20} МБ, один файл до {MAX_ONE // 2 ** 20} МБ")
        return True

    def exhausted(self) -> bool:
        if self.cancel is not None and self.cancel.is_set():
            return True
        return (self.files >= MAX_FILES or self.total >= MAX_TOTAL) and self._limited()

    def take(self, size: int) -> bool:
        if self.cancel is not None and self.cancel.is_set():
            return False
        if self.files >= MAX_FILES or self.total + size > MAX_TOTAL or size > MAX_ONE:
            self._limited()
            return False
        self.files += 1
        self.total += size
        if self.progress and self.files % 50 == 0:
            self.progress(f"Извлечено файлов: {self.files}")
        return True


def tool(*parts: str) -> Path | None:
    p = TOOLS.joinpath(*parts)
    return p if p.is_file() else None


def run_tool(args: list[str], timeout: int = TOOL_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, timeout=timeout,
                          creationflags=NO_WINDOW if os.name == "nt" else 0)


def _safe(name: str) -> str:
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name).strip(" .") or "_"
    return name[:120]


def _write(base: Path, rel: str, data: bytes) -> Path:
    parts = [_safe(p) for p in re.split(r"[\\/]+", rel) if p not in ("", ".", "..")]
    target = base.joinpath(*parts) if parts else base / "_"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target = target.with_name(f"{target.stem}_{len(list(target.parent.iterdir()))}"
                                  f"{target.suffix}")
    target.write_bytes(data)
    return target


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def workdir_for(path: Path) -> Path:
    """Своя папка разбора; старые разборы (больше KEEP_RUNS) удаляются."""
    UNPACK_DIR.mkdir(parents=True, exist_ok=True)
    runs = sorted((d for d in UNPACK_DIR.iterdir() if d.is_dir()),
                  key=lambda d: d.stat().st_mtime)
    for old in runs[:-KEEP_RUNS + 1] if len(runs) >= KEEP_RUNS else []:
        shutil.rmtree(old, ignore_errors=True)
    work = UNPACK_DIR / _sha256(path)[:16]
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    return work


# ---------------------------------------------------------------- разбор
def unpack(path: Path, cancel=None, progress=None) -> Node:
    """Главная функция: дерево частей файла. Медленная — не из GUI-потока."""
    path = Path(path)
    budget = Budget(cancel, progress)
    work = workdir_for(path)
    root = Node(path.name, "root", str(path), path.stat().st_size)
    _explore(root, path, work, budget, 0)
    for text in budget.notes:
        root.add(Node(text, "note"))
    return root


def _explore(node: Node, path: Path, work: Path, budget: Budget, depth: int) -> None:
    """Определяет, что за файл, и добавляет его части в node.children."""
    if depth > MAX_DEPTH:
        node.note = "Глубже не разбирается"
        return
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError as e:
        node.note = f"Не читается: {e}"
        return
    suffix = path.suffix.lower()
    try:
        if head.startswith(b"MZ"):
            _explore_pe(node, path, work, budget, depth)
        elif head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
            _explore_zip(node, path, work, budget, depth)
        elif head.startswith(b"\xca\xfe\xba\xbe") and suffix == ".class":
            node.kind, node.lang = "class", "java"
        elif suffix == ".pyc" or _looks_pyc(head):
            node.kind, node.lang = "pyc", "python"
        elif head.startswith(b"PYZ\x00"):
            _explore_pyz(node, path.read_bytes(), work, budget, depth, None)
    except Exception as e:  # повреждённый или нарочно испорченный файл не роняет разбор
        node.add(Node(f"Ошибка разбора: {type(e).__name__}: {e}", "note"))


def _looks_pyc(head: bytes) -> bool:
    return len(head) >= 4 and head[2:4] == b"\r\n" and \
        any(struct.pack("<H", m) == head[:2] for m in PYC_MAGIC.values())


def _child_file(parent: Node, name: str, kind: str, data: bytes, base: Path, rel: str,
                budget: Budget, depth: int, note: str = "") -> Node | None:
    if not budget.take(len(data)):
        return None
    file = _write(base, rel, data)
    child = parent.add(Node(name, kind, str(file), len(data), note))
    _explore(child, file, base, budget, depth + 1)
    return child


# ---------- PE
def _explore_pe(node: Node, path: Path, work: Path, budget: Budget, depth: int) -> None:
    import pefile
    pe = pefile.PE(str(path), fast_load=True)
    try:
        if node.kind == "file":
            node.kind = "pe"
        node.lang = node.lang or "native"
        sections = [s.Name.rstrip(b"\x00").decode("latin-1", "replace") for s in pe.sections]
        com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14] if len(
            pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 else None
        is_dotnet = bool(com and com.VirtualAddress and com.Size)
        overlay_at = pe.get_overlay_data_start_offset()
        cert = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        size = path.stat().st_size
        overlay_end = cert.VirtualAddress if cert.VirtualAddress and cert.Size and \
            cert.VirtualAddress >= (overlay_at or 0) else size
        if any(s.upper().startswith("UPX") for s in sections):
            _unpack_upx(node, path, work, budget, depth)
        if is_dotnet:
            node.lang = "csharp"
            _explore_dotnet(node, path, work, budget, depth)
        _explore_resources(node, pe, path, work, budget, depth)
    finally:
        pe.close()
    if overlay_at and overlay_end > overlay_at:
        _explore_overlay(node, path, overlay_at, overlay_end, work, budget, depth)


def _unpack_upx(node: Node, path: Path, work: Path, budget: Budget, depth: int) -> None:
    upx = tool("upx", "upx.exe")
    if upx is None:
        node.add(Node("Упакован UPX: распаковщик не найден (tools/bin/upx)", "note"))
        return
    out = work / "upx" / (path.stem + "_unpacked" + path.suffix)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.unlink(missing_ok=True)
    result = run_tool([str(upx), "-d", "-q", "-o", str(out), str(path)])
    if result.returncode != 0 or not out.is_file():
        reason = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        node.add(Node("UPX: не распаковался (возможно, изменён нарочно)", "note",
                      note=reason[-300:]))
        return
    if not budget.take(out.stat().st_size):
        return
    child = node.add(Node(f"{path.name} (распакован UPX)", "upx", str(out), out.stat().st_size,
                          "Исходный файл был сжат UPX; здесь — восстановленный"))
    _explore(child, out, work, budget, depth + 1)


def _explore_resources(node: Node, pe, path: Path, work: Path, budget: Budget,
                       depth: int) -> None:
    import pefile
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return
    group = None
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_id = rtype.id if rtype.id is not None else -1
        if type_id in PLAIN_RESOURCES:
            continue
        type_name = str(rtype.name) if rtype.name else pefile.RESOURCE_TYPE.get(type_id, str(type_id))
        for entry in getattr(getattr(rtype, "directory", None), "entries", []):
            for lang in getattr(getattr(entry, "directory", None), "entries", []):
                rva, size = lang.data.struct.OffsetToData, lang.data.struct.Size
                if size < 16:
                    continue
                data = pe.get_data(rva, min(size, MAX_ONE))
                if not (data.startswith(ARCHIVE_HEADS) or size >= 32 * 1024):
                    continue
                name = str(entry.name) if entry.name else str(entry.id)
                if group is None:
                    group = node.add(Node("Ресурсы", "folder"))
                _child_file(group, f"{type_name} / {name}", "resource", data, work,
                            f"res/{path.stem}/{type_name}_{name}.bin", budget, depth,
                            "Ресурс PE: программы прячут так вложенные файлы")


def _explore_overlay(node: Node, path: Path, start: int, end: int, work: Path, budget: Budget,
                     depth: int) -> None:
    with open(path, "rb") as f:
        f.seek(start)
        data = f.read(min(end - start, MAX_ONE + 1))
    if PYI_MAGIC in data:
        _explore_pyinstaller(node, data, work, budget, depth)
        return
    if len(data) < 512:
        return
    what = "архив ZIP" if data.startswith(b"PK") else "программа" if data.startswith(b"MZ") \
        else "7-Zip" if data.startswith(b"7z") else "данные"
    if data[:16].find(b"Nullsoft") >= 0 or b"NullsoftInst" in data[:64]:
        what = "установщик NSIS"
    elif b"Inno Setup" in data[:64] or b"zlb\x1a" in data[:8]:
        what = "установщик Inno Setup"
    _child_file(node, f"Оверлей ({what})", "overlay", data[:MAX_ONE], work,
                f"overlay/{path.stem}.overlay", budget, depth,
                f"Данные после конца образа PE, {len(data)} байт: {what}")


# ---------- PyInstaller
def _pyver(raw: int) -> tuple[int, int]:
    return (raw // 100, raw % 100) if raw >= 100 else (raw // 10, raw % 10)


def _pyc_header(magic: bytes, ver: tuple[int, int]) -> bytes:
    if ver >= (3, 7):
        return magic + b"\x00" * 12
    if ver >= (3, 3):
        return magic + b"\x00" * 8
    return magic + b"\x00" * 4


def _explore_pyinstaller(node: Node, blob: bytes, work: Path, budget: Budget,
                         depth: int) -> None:
    pos = blob.rfind(PYI_MAGIC)
    tail = blob[pos:]
    if len(tail) >= PYI_COOKIE.size:
        _, length, toc_off, toc_len, pyvers, pylib = PYI_COOKIE.unpack_from(tail)
        cookie_size = PYI_COOKIE.size
    else:
        _, length, toc_off, toc_len, pyvers = PYI_COOKIE_OLD.unpack_from(tail)
        cookie_size, pylib = PYI_COOKIE_OLD.size, b""
    start = pos + cookie_size - length
    if start < 0:
        raise ValueError("повреждённый архив PyInstaller")
    ver = _pyver(pyvers)
    lib = pylib.split(b"\x00", 1)[0].decode("latin-1", "replace")
    pyi = node.add(Node(f"PyInstaller: Python {ver[0]}.{ver[1]}", "pyinstaller",
                        note=f"Архив внутри программы; библиотека Python: {lib or '?'}"))
    entries = []
    toc = blob[start + toc_off:start + toc_off + toc_len]
    i = 0
    while i + PYI_ENTRY.size <= len(toc):
        size, off, clen, ulen, compressed, code = PYI_ENTRY.unpack_from(toc, i)
        if size <= 0:
            break
        name = toc[i + PYI_ENTRY.size:i + size].rstrip(b"\x00").decode("utf-8", "replace")
        entries.append((name, off, clen, compressed, code.decode("latin-1")))
        i += size
    # магическое число .pyc — из PYZ, иначе по версии Python
    magic = struct.pack("<H", PYC_MAGIC.get(ver, 0)) + b"\r\n"
    for name, off, clen, compressed, code in entries:
        if code in "zZ":
            data = blob[start + off:start + off + clen]
            if data[:4] == b"PYZ\x00":
                magic = data[4:8]
    pyz_nodes = []
    for name, off, clen, compressed, code in entries:
        if budget.cancel is not None and budget.cancel.is_set():
            return
        data = blob[start + off:start + off + clen]
        if compressed:
            try:
                data = zlib.decompress(data)
            except zlib.error:
                pyi.add(Node(f"{name}: не распаковывается", "note"))
                continue
        what = PYI_TYPES.get(code, f"тип {code}")
        if code in "zZ":
            pyz_nodes.append((name, data))
            continue
        if code == "o":
            continue                      # параметры запуска интерпретатора
        if code == "s":
            data = _pyc_header(magic, ver) + data
            _child_file(pyi, name + ".pyc", "pyc", data, work, f"pyinstaller/{name}.pyc",
                        budget, depth, "Скрипт, который PyInstaller запускает первым — "
                                       "обычно здесь главная логика программы")
        elif code in "mM":
            if not data[2:4] == b"\r\n":
                data = _pyc_header(magic, ver) + data
            _child_file(pyi, name + ".pyc", "pyc", data, work, f"pyinstaller/{name}.pyc",
                        budget, depth, what)
        else:
            _child_file(pyi, name, "file", data, work, f"pyinstaller/files/{name}", budget,
                        depth, what)
    for name, data in pyz_nodes:
        pyz = pyi.add(Node(name, "pyz", note="Модули Python программы и библиотек"))
        _explore_pyz(pyz, data, work, budget, depth, ver)


def _explore_pyz(node: Node, data: bytes, work: Path, budget: Budget, depth: int,
                 ver: tuple[int, int] | None) -> None:
    node.kind = "pyz"
    magic = data[4:8]
    if ver is None:
        number = struct.unpack("<H", magic[:2])[0]
        ver = next((v for v, m in PYC_MAGIC.items() if m == number), (3, 8))
    toc_off = struct.unpack("!i", data[8:12])[0]
    toc = marshal.loads(data[toc_off:])
    items = toc.items() if isinstance(toc, dict) else toc
    packages: dict[str, Node] = {}
    encrypted = 0
    for name, info in sorted(items, key=lambda kv: kv[0]):
        if budget.cancel is not None and budget.cancel.is_set():
            return
        if isinstance(name, bytes):
            name = name.decode("utf-8", "replace")
        typecode, off, length = info[0], info[1], info[2]
        raw = data[off:off + length]
        try:
            code = zlib.decompress(raw)
        except zlib.error:
            encrypted += 1
            continue
        parent = _package_node(node, packages, name.rsplit(".", 1)[0] if "." in name else "")
        short = name.rsplit(".", 1)[-1]
        if typecode in (1, 3):             # пакет: его __init__
            short += "/__init__"
        if typecode == 2:                  # данные внутри PYZ (редко)
            _child_file(parent, short, "file", code, work, f"pyz/{name}", budget, depth)
            continue
        _child_file(parent, short + ".pyc", "pyc", _pyc_header(magic, ver) + code, work,
                    "pyz/" + name.replace(".", "/") + (
                        "/__init__" if typecode in (1, 3) else "") + ".pyc", budget, depth)
    if encrypted:
        node.add(Node(f"Зашифровано модулей: {encrypted} (PyInstaller --key)", "note",
                      note="Ключ лежит в модуле pyimod00_crypto_key; расшифровка не делается"))


def _package_node(root: Node, packages: dict[str, Node], package: str) -> Node:
    if not package:
        return root
    if package in packages:
        return packages[package]
    parent = _package_node(root, packages, package.rsplit(".", 1)[0] if "." in package else "")
    node = parent.add(Node(package.rsplit(".", 1)[-1], "folder"))
    packages[package] = node
    return node


# ---------- ZIP, JAR
def _explore_zip(node: Node, path: Path, work: Path, budget: Budget, depth: int) -> None:
    if node.kind == "file":
        node.kind = "zip"
    base = f"zip/{path.stem}_{depth}"
    with zipfile.ZipFile(path) as z:
        folders: dict[str, Node] = {}
        for info in z.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                node.add(Node(f"{info.filename}: зашифрован паролем", "note"))
                continue
            if budget.exhausted():
                break
            if info.file_size > MAX_ONE:
                node.add(Node(f"{info.filename}: больше {MAX_ONE // 2 ** 20} МБ, пропущен", "note"))
                continue
            parts = info.filename.replace("\\", "/").split("/")
            parent = node
            for i, part in enumerate(parts[:-1]):
                key = "/".join(parts[:i + 1])
                if key not in folders:
                    folders[key] = parent.add(Node(part, "folder"))
                parent = folders[key]
            _child_file(parent, parts[-1], "file", z.read(info), work,
                        f"{base}/{info.filename}", budget, depth)


# ---------- .NET
def _explore_dotnet(node: Node, path: Path, work: Path, budget: Budget, depth: int) -> None:
    exe = tool("dotnet", "sbit-dotnet.exe")
    if exe is None:
        node.add(Node(".NET: помощник не найден (tools/bin/dotnet)", "note"))
        return
    result = run_tool([str(exe), "tree", str(path)])
    if result.returncode != 0:
        node.add(Node(".NET: метаданные не читаются", "note",
                      note=result.stderr.decode("utf-8", "replace")[-300:]))
        return
    info = json.loads(result.stdout.decode("utf-8"))
    asm = node.add(Node(f".NET: {info.get('assembly') or info.get('module')} "
                        f"{info.get('version', '')}".strip(), "dotnet", lang="csharp",
                        owner=str(path),
                        note=f"Платформа: {info.get('framework') or '?'}; ссылки: "
                             + ", ".join(info.get("references", [])[:20])))
    spaces: dict[str, Node] = {}
    for t in info.get("types", []):
        if t["name"] == "<Module>":
            continue
        ns = t["namespace"] or "(без пространства имён)"
        if ns not in spaces:
            spaces[ns] = asm.add(Node(ns, "namespace"))
        _add_type(spaces[ns], t, str(path))
    resources = [r for r in info.get("resources", []) if r.get("kind") == "Embedded"]
    if resources:
        res_dir = work / "dotnet" / _safe(path.stem)
        result = run_tool([str(exe), "resources", str(path), str(res_dir)])
        if result.returncode == 0:
            group = asm.add(Node("Ресурсы", "folder"))
            for r in json.loads(result.stdout.decode("utf-8")):
                file = Path(r["file"])
                if not budget.take(file.stat().st_size):
                    break
                child = group.add(Node(r["name"], "resource", str(file), file.stat().st_size,
                                       "Встроенный ресурс .NET: частое место для второй "
                                       "стадии вредоноса"))
                _explore(child, file, work, budget, depth + 1)


def _add_type(parent: Node, t: dict, owner: str) -> None:
    note = f"Методов: {len(t['methods'])}, полей: {t['fields']}"
    if t.get("entry"):
        note += "; здесь точка входа (Main)"
    node = parent.add(Node(t["name"] + ("  ← Main" if t.get("entry") else ""), "type",
                           note=note, lang="csharp", ref=t["full"], owner=owner))
    for nested in t.get("nested", []):
        _add_type(node, nested, owner)


# ---------------------------------------------------------------- проверка
def check_tree(root: Node, cancel=None, progress=None) -> dict[str, int]:
    """Проверяет все извлечённые файлы (хэши, YARA, эвристика) и красит узлы."""
    from analyzer.folderview import classify, rules_and_bases
    from scanner import pool
    nodes = {}
    for n in root.files():
        nodes.setdefault(n.path, []).append(n)
    if not nodes:
        return {"files": 0}
    signatures, rules, whitelist = rules_and_bases()
    counts = {"files": len(nodes), "threat": 0, "suspicious": 0, "error": 0}
    done = 0
    for path, reason, error in pool.check_files(list(nodes), signatures, rules, whitelist,
                                                cancel=cancel):
        done += 1
        if error is not None:
            level, text = "error", f"Не проверен: {error}"
        else:
            level, text = classify(reason)
        counts[level] = counts.get(level, 0) + 1
        for n in nodes.get(path, []):
            n.level, n.verdict = level, text
        if progress and done % 25 == 0:
            progress(f"Проверено {done} из {len(nodes)}")
    _roll_up(root)
    return counts


ORDER = {"": 0, "clean": 1, "error": 2, "suspicious": 3, "threat": 4}


def _roll_up(node: Node) -> str:
    """Папки и типы получают худший уровень вложенного: угрозу видно сверху."""
    worst = node.level
    for c in node.children:
        lvl = _roll_up(c)
        if ORDER[lvl] > ORDER[worst]:
            worst = lvl
    if not node.path and worst in ("threat", "suspicious"):
        node.level = worst
        node.verdict = node.verdict or ("Внутри угроза" if worst == "threat"
                                        else "Внутри подозрительное")
    return worst
