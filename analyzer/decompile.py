"""Код части файла для вкладки «Декомпилятор» (узел analyzer.unpack.Node).

python — pycdc (Decompyle++), при неудаче pycdas (байт-код); java — CFR (нужна Java);
csharp — sbit-dotnet (ILSpy); машинный код (native) — rizin + rz-ghidra (analyzer/rizin.py):
сначала список функций, потом код выбранной. Инструменты — tools/bin (вне Git, в релиз).
Файлы не запускаются: все инструменты только читают.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from analyzer.unpack import KIND_TEXT, Node, run_tool, tool

MAX_OUTPUT = 3 * 1024 * 1024
HIGHLIGHT = {"python": "py", "java": "java", "csharp": "cs", "native": "c"}


def _text(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    if len(text) > MAX_OUTPUT:
        text = text[:MAX_OUTPUT] + "\n\n// ... вывод обрезан (больше 3 МБ)"
    return text


java_refused = ""  # почему найденная Java не запускается (для сообщения)


def find_java() -> str | None:
    """java.exe из JAVA_HOME или PATH. Обе переменные пользователь без прав задаёт сам
    (HKCU/Environment действует и на окно с правами администратора): с правами запускается
    только java.exe, который меняют одни администраторы (winacl), иначе чужая программа
    под именем java.exe получила бы наши права."""
    global java_refused
    java_refused = ""
    home = os.environ.get("JAVA_HOME")
    found = str(Path(home) / "bin" / "java.exe") if home and (
        Path(home) / "bin" / "java.exe").is_file() else shutil.which("java")
    if not found:
        return None
    try:
        from processmanager.system import is_admin
        elevated = is_admin()
    except Exception:  # noqa: BLE001 — права не узнать: проверяем как с правами
        elevated = True
    if elevated:
        import winacl
        ok, reason = winacl.admin_only(found)
        if not ok:
            java_refused = f"{found}: {reason}"
            return None
    return found


def decompile(node: Node) -> tuple[str, str, str]:
    """(текст, язык подсветки, пояснение). Медленная функция — не из GUI-потока."""
    if node.lang == "python" and node.path:
        return _python(Path(node.path))
    if node.lang == "java" and node.path:
        return _java(Path(node.path))
    if node.lang == "csharp" and node.owner:
        return _csharp(node)
    if node.kind == "function":
        return native_function(node)
    if node.lang == "native":
        return (describe(node) + "\n\nМашинный код: функции появятся в дереве под этой частью "
                "после анализа (rizin + декомпилятор Ghidra).", "", "")
    return describe(node) + _preview(node), "", ""


def native_functions(node: Node) -> tuple[list[Node], str]:
    """Функции программы (анализ rizin, один раз на файл) — узлы для дерева."""
    from analyzer import rizin
    if not rizin.available():
        return [], "Декомпилятор машинного кода не найден (tools/bin/rizin)."
    funcs = rizin.session(node.path).functions()
    nodes = []
    for f in funcs:
        name = f["name"]
        note = {0: "Точка входа или main — начните отсюда",
                1: "Экспортируемая или известная по символам функция",
                2: "Библиотечная функция, узнана по сигнатурам (sigdb)"}.get(f["rank"], "")
        nodes.append(Node(f"{name}  {f['addr']:#x}", "function", size=f["size"], note=note,
                          lang="c", ref=f"{f['addr']:#x}", owner=node.path))
    return nodes, f"Функций: {len(nodes)}"


def native_function(node: Node) -> tuple[str, str, str]:
    from analyzer import rizin
    s = rizin.session(node.owner)
    text, removed = s.decompile(int(node.ref, 16))
    note = "Декомпилятор Ghidra (rz-ghidra). Имена вида fcn.*, var_*, uVar — восстановленные: " \
           "настоящих имён в программе нет."
    if removed:
        note += f" Убрано служебных предупреждений о стеке: {removed}."
    if not text.strip():
        return s.disassemble(int(node.ref, 16)), "asm", "Декомпиляция не удалась: дизассемблер"
    return text, "c", note


def _python(path: Path) -> tuple[str, str, str]:
    pycdc = tool("pycdc", "pycdc.exe")
    if pycdc is None:
        return "Декомпилятор Python не найден (tools/bin/pycdc).", "", ""
    result = run_tool([str(pycdc), str(path)], timeout=60)
    text, err = _text(result.stdout), result.stderr.decode("utf-8", "replace").strip()
    if result.returncode == 0 and text.strip():
        note = ""
        if err or "WARNING: Decompyle incomplete" in text:
            note = ("Декомпиляция неполная: новые версии Python (3.11+) pycdc восстанавливает "
                    "не целиком. Вся логика — кнопка «Байт-код».")
        return text, "py", note
    return python_bytecode(path)[0], "", "pycdc не справился: показан байт-код (pycdas). " + err[-200:]


def python_bytecode(path: Path) -> tuple[str, str, str]:
    pycdas = tool("pycdc", "pycdas.exe")
    if pycdas is None:
        return "pycdas не найден (tools/bin/pycdc).", "", ""
    result = run_tool([str(pycdas), str(path)], timeout=60)
    return _text(result.stdout) or result.stderr.decode("utf-8", "replace"), "", "Байт-код Python"


def _java(path: Path) -> tuple[str, str, str]:
    cfr = tool("cfr", "cfr-0.152.jar")
    java = find_java()
    if cfr is None:
        return "Декомпилятор Java не найден (tools/bin/cfr).", "", ""
    if java is None and java_refused:
        return ("Java найдена, но не запущена: программа работает с правами администратора, "
                "а этот файл может подменить любая программа без прав. " + java_refused,
                "", "")
    if java is None:
        return ("Для декомпиляции .class нужна Java (не найдена: JAVA_HOME, PATH). Дерево "
                "классов и проверка файлов работают и без неё.", "", "")
    result = run_tool([java, "-jar", str(cfr), str(path), "--silent", "true"], timeout=90)
    text = _text(result.stdout)
    if result.returncode != 0 or not text.strip():
        return result.stderr.decode("utf-8", "replace")[-2000:] or "CFR ничего не вывел", "", ""
    return text, "java", ""


def _csharp(node: Node) -> tuple[str, str, str]:
    exe = tool("dotnet", "sbit-dotnet.exe")
    if exe is None:
        return "Помощник .NET не найден (tools/bin/dotnet).", "", ""
    args = [str(exe), "decompile", node.owner] + ([node.ref] if node.ref else [])
    result = run_tool(args, timeout=180)
    if result.returncode != 0:
        return result.stderr.decode("utf-8", "replace")[-2000:] or "Ошибка декомпиляции", "", ""
    note = "" if node.ref else "Вся сборка целиком; отдельный тип — выберите его в дереве"
    return _text(result.stdout), "cs", note


def describe(node: Node) -> str:
    lines = [f"{node.name}", f"Что это: {KIND_TEXT.get(node.kind, node.kind)}"]
    if node.size:
        lines.append(f"Размер: {node.size:,} байт".replace(",", " "))
    if node.verdict:
        lines.append(f"Проверка: {node.verdict}")
    if node.note:
        lines.append(node.note)
    if node.path:
        lines.append(f"Извлечён в: {node.path}")
    if node.children:
        lines.append(f"Вложенных элементов: {len(node.children)}")
    return "\n".join(lines)


def _preview(node: Node) -> str:
    """Небольшой текстовый файл — показать содержимое (конфиги, скрипты, манифесты)."""
    if not node.path or node.size > 512 * 1024:
        return ""
    try:
        raw = Path(node.path).read_bytes()
    except OSError:
        return ""
    if b"\x00" in raw[:4096]:
        return ""
    for enc in ("utf-8-sig", "cp1251"):
        try:
            return "\n\n" + "-" * 60 + "\n" + raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return ""
