"""Декомпилятор машинного кода: rizin + rz-ghidra (движок декомпиляции Ghidra, без Java).

Один процесс rizin на файл (RizinSession): анализ функций (aaa) делается один раз, потом
каждая функция декомпилируется командой pdg. Обмен — режим «-0» (как rzpipe): команда в
stdin, ответ в stdout до байта \\x00. Файл не запускается: rizin только читает.

Набор файлов — tools/bin/rizin (из выпуска Cutter: rizin.exe, rz_*.dll, модуль
lib/rizin/plugins/core_ghidra.dll, описания процессоров rz_ghidra_sleigh, данные share с
сигнатурами библиотечных функций sigdb/pe; рядом — среда выполнения Visual C++).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from pathlib import Path

from analyzer.unpack import NO_WINDOW, TOOLS

RIZIN_DIR = TOOLS / "rizin"
RIZIN = RIZIN_DIR / "rizin.exe"
SLEIGH = RIZIN_DIR / "lib" / "rizin" / "plugins" / "rz_ghidra_sleigh"
FULL_ANALYSIS_LIMIT = 16 * 1024 * 1024   # крупнее — быстрый анализ (aa), иначе минуты
MAX_FUNCTIONS = 20000
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

_sessions: dict[str, RizinSession] = {}
_registry_lock = threading.Lock()


def available() -> bool:
    return RIZIN.is_file() and SLEIGH.is_dir()


class RizinSession:
    def __init__(self, path: Path):
        self.path = Path(path).resolve()           # rizin работает из своей папки
        self.lock = threading.Lock()
        self.analyzed = False
        self.proc = subprocess.Popen(
            [str(RIZIN), "-q0", "-e", "scr.color=0", "-e", "scr.interactive=false",
             "-e", "bin.relocs.apply=true", str(self.path)],
            cwd=str(RIZIN_DIR), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, creationflags=NO_WINDOW if os.name == "nt" else 0)
        self._read()                                   # rizin готов: первый \x00
        # переменная модуля появляется только после его загрузки — задаётся командой
        self.cmd("e ghidra.sleighhome=" + str(SLEIGH).replace("\\", "/"))

    def _read(self) -> str:
        out = bytearray()
        while True:
            chunk = self.proc.stdout.read1(65536) if hasattr(self.proc.stdout, "read1") \
                else self.proc.stdout.read(1)
            if not chunk:
                raise RuntimeError("rizin завершился")
            end = chunk.find(b"\x00")
            if end >= 0:
                out += chunk[:end]
                break
            out += chunk
        return ANSI.sub("", out.decode("utf-8", "replace"))

    def cmd(self, command: str) -> str:
        with self.lock:
            if self.proc.poll() is not None:
                raise RuntimeError("rizin завершился")
            self.proc.stdin.write(command.encode("utf-8") + b"\n")
            self.proc.stdin.flush()
            return self._read()

    def close(self) -> None:
        try:
            self.proc.stdin.write(b"q!\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()

    # ---------- функции
    def functions(self) -> list[dict]:
        if not self.analyzed:
            size = self.path.stat().st_size
            self.cmd("aaa" if size <= FULL_ANALYSIS_LIMIT else "aa")
            self.analyzed = True
        try:
            items = json.loads(self.cmd("aflj") or "[]")
        except ValueError:
            items = []
        entry = self._entry()
        result = []
        for f in items[:MAX_FUNCTIONS]:
            name = f.get("name", "")
            result.append({"name": name, "addr": int(f.get("offset", 0)),
                           "size": int(f.get("size", 0)), "rank": _rank(name, f, entry)})
        result.sort(key=lambda f: (f["rank"], f["addr"]))
        return result

    def _entry(self) -> int:
        try:
            return int(json.loads(self.cmd("iej") or "[]")[0]["vaddr"])
        except (ValueError, LookupError, TypeError):
            return -1

    def decompile(self, addr: int) -> tuple[str, int]:
        """(код C, сколько служебных предупреждений rz-ghidra убрано)."""
        return clean(self.cmd(f"pdg @ {addr:#x}"))

    def disassemble(self, addr: int) -> str:
        return self.cmd(f"pdf @ {addr:#x}").replace("\r\n", "\n")


# предупреждения о раскладке стека: на смысл кода не влияют, а занимают первые экраны
NOISE = ("// WARNING: [rz-ghidra] Detected overlap", "// WARNING: Variable defined which "
         "should be unmapped")


def clean(text: str) -> tuple[str, int]:
    lines = text.replace("\r\n", "\n").split("\n")
    kept = [line for line in lines if not line.startswith(NOISE)]
    out = re.sub(r"\n{3,}", "\n\n", "\n".join(kept)).strip("\n") + "\n"
    return out, len(lines) - len(kept)


def _rank(name: str, f: dict, entry: int) -> int:
    """Порядок в дереве: точка входа и main — первыми, затем экспорт, именованные
    (библиотечные по сигнатурам), остальные — по адресу."""
    low = name.lower()
    if f.get("offset") == entry or low in ("entry0", "main", "sym.main", "winmain",
                                           "sym.winmain", "dllmain", "sym.dllmain"):
        return 0
    if low.startswith(("sym.", "exp.")):
        return 1
    if low.startswith("fcn."):
        return 3
    return 2


def session(path: str | Path) -> RizinSession:
    key = os.path.normcase(str(path))
    with _registry_lock:
        s = _sessions.get(key)
        if s is None or s.proc.poll() is not None:
            s = _sessions[key] = RizinSession(Path(path))
        return s


def close_all() -> None:
    """Новый файл в анализаторе: прежние процессы rizin больше не нужны."""
    with _registry_lock:
        sessions = list(_sessions.values())
        _sessions.clear()
    for s in sessions:
        s.close()
