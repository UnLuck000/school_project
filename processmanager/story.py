"""Сводка по процессу: кто запустил → что запустил сам → что создал → куда подключался.

Сведения копятся в памяти с момента запуска программы из уже работающих источников:
• запуски процессов — контроль запуска (scanner.launchguard: ETW Kernel-Process или опрос);
• созданные и перезаписанные файлы — ETW Kernel-File защиты от стилеров
  (toolbox.stealerguard, только с правами администратора): событие Create с типом
  открытия «создать / перезаписать»; запоминаются программы, скрипты, документы с
  макросами и архивы — то, что вредонос обычно «сбрасывает» на диск;
• DNS-запросы, TLS (сайт по SNI) и соединения TCP — мониторинг сети (networkmonitor.netmon).
Источник выключен — раздела в сводке нет, вместо него пояснение. Для живого процесса
недостающее берётся из текущего снимка: цепочка родителей (ntsnap) и открытые соединения
(psutil). PID после выхода процесса Windows может отдать новому — запись тогда заменяется
(started() с тем же PID).
"""
import os
import threading
import time
from dataclasses import dataclass, field

MAX_PROCS = 3000      # процессов в памяти (старые по последнему событию — вон)
MAX_FILES = 300       # созданных файлов на процесс
MAX_TARGETS = 300     # адресов и доменов на процесс
MAX_CHAIN = 8         # глубина цепочки «кто запустил»
# что стоит запомнить из созданного: исполняемое, скрипты, макросы, архивы, ярлыки
WATCH_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".msi", ".msp", ".pif",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".lnk", ".url", ".jar", ".py", ".docm", ".xlsm", ".pptm", ".dotm", ".xlam",
    ".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx", ".cab",
}
# у события Kernel-File Create (x64: Irp, FileObject, IssuingThreadId, CreateOptions,
# CreateAttributes, ShareAccess, затем имя с 32-го байта; проверено 12.11.2026 на Windows 11)
# старший байт CreateOptions (байты 20–23) — CreateDisposition:
# 0 SUPERSEDE, 2 CREATE (CREATE_NEW), 4 OVERWRITE (TRUNCATE_EXISTING), 5 OVERWRITE_IF
# (CREATE_ALWAYS) — файл создаётся или переписывается; 1 OPEN и 3 OPEN_IF — обычное открытие
WRITE_DISPOSITIONS = {0, 2, 4, 5}


@dataclass
class Target:
    first: float
    last: float
    count: int = 1
    kind: str = "tcp"     # tcp | dns | tls
    detail: str = ""      # домен для адреса, адрес для домена


@dataclass
class Record:
    pid: int
    ppid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    started: float = 0.0  # 0 — запуск не видели (процесс шёл до нас)
    last: float = 0.0
    files: dict[str, tuple[float, int]] = field(default_factory=dict)  # путь → (время, раз)
    targets: dict[str, Target] = field(default_factory=dict)          # адрес или домен → …
    children: list[int] = field(default_factory=list)


class Story:
    def __init__(self):
        self._lock = threading.Lock()
        self._procs: dict[int, Record] = {}
        self.sources: set[str] = set()  # launch | files | net — что сейчас пишет в сводку

    # ---------- запись событий ----------
    def _get(self, pid: int, now: float) -> Record:
        rec = self._procs.get(pid)
        if rec is None:
            if len(self._procs) >= MAX_PROCS:
                for old in sorted(self._procs.values(), key=lambda r: r.last)[:MAX_PROCS // 10]:
                    self._procs.pop(old.pid, None)
            rec = self._procs[pid] = Record(pid, last=now)
        rec.last = now
        return rec

    def started(self, pid: int, ppid: int, exe: str, cmdline: list[str] | str = "",
                when: float | None = None, name: str = "") -> None:
        now = when or time.time()
        text = cmdline if isinstance(cmdline, str) else " ".join(cmdline)
        with self._lock:
            self._procs.pop(pid, None)  # PID занят новым процессом
            rec = self._get(pid, now)
            rec.ppid, rec.exe, rec.cmdline, rec.started = ppid, exe, text[:1000], now
            rec.name = os.path.basename(exe) if exe else name
            if ppid:
                parent = self._get(ppid, now)
                if pid not in parent.children:
                    parent.children = (parent.children + [pid])[-200:]

    def known(self, pid: int, ppid: int, name: str) -> None:
        """Процесс шёл до нас (снимок при включении контроля запуска): только родитель и
        имя — для цепочки «кто запустил», если он завершится раньше потомков."""
        with self._lock:
            if pid not in self._procs:
                rec = self._get(pid, time.time())
                rec.ppid, rec.name = ppid, name

    def identify(self, pid: int, exe: str, cmdline: list[str] | None = None) -> None:
        """Полный путь и командная строка стали известны позже события запуска."""
        with self._lock:
            rec = self._procs.get(pid)
            if rec is None:
                return
            if exe and not rec.exe:
                rec.exe, rec.name = exe, os.path.basename(exe)
            if cmdline and not rec.cmdline:
                rec.cmdline = " ".join(cmdline)[:1000]

    def file_written(self, pid: int, path: str, when: float | None = None) -> None:
        if not pid or os.path.splitext(path)[1].lower() not in WATCH_EXTS:
            return
        now = when or time.time()
        with self._lock:
            rec = self._get(pid, now)
            seen = rec.files.get(path)
            if seen is None and len(rec.files) >= MAX_FILES:
                return
            rec.files[path] = (seen[0] if seen else now, (seen[1] if seen else 0) + 1)

    def contacted(self, pid: int, target: str, kind: str = "tcp", detail: str = "",
                  when: float | None = None) -> None:
        if not pid or not target:
            return
        now = when or time.time()
        with self._lock:
            rec = self._get(pid, now)
            t = rec.targets.get(target)
            if t is None:
                if len(rec.targets) >= MAX_TARGETS:
                    return
                rec.targets[target] = Target(now, now, 1, kind, detail)
            else:
                t.last, t.count = now, t.count + 1
                if detail and not t.detail:
                    t.detail = detail

    def forget(self) -> None:
        with self._lock:
            self._procs.clear()

    # ---------- чтение ----------
    def record(self, pid: int) -> Record | None:
        with self._lock:
            rec = self._procs.get(pid)
            if rec is None:
                return None
            return Record(rec.pid, rec.ppid, rec.name, rec.exe, rec.cmdline, rec.started,
                          rec.last, dict(rec.files),
                          {k: Target(v.first, v.last, v.count, v.kind, v.detail)
                           for k, v in rec.targets.items()}, list(rec.children))

    def chain(self, pid: int, live: dict[int, tuple[int, str]] | None = None) -> list[tuple[int, str]]:
        """Кто запустил: [(pid, имя)] от родителя вверх. live — {pid: (ppid, имя)} снимка
        процессов: родитель, запущенный до нас, известен только из него."""
        out, seen = [], {pid}
        current = pid
        for _ in range(MAX_CHAIN):
            rec = self.record(current)
            ppid = rec.ppid if rec and rec.ppid else (live or {}).get(current, (0, ""))[0]
            if not ppid or ppid in seen:
                break
            seen.add(ppid)
            parent = self.record(ppid)
            name = (parent.name if parent and parent.name else "") or \
                (live or {}).get(ppid, (0, ""))[1]
            out.append((ppid, name or "?"))
            current = ppid
        return out


STORY = Story()


def _fmt(ts: float) -> str:
    return time.strftime("%d.%m %H:%M:%S", time.localtime(ts)) if ts else "?"


def _live_processes() -> dict[int, tuple[int, str]]:
    try:
        from processmanager import ntsnap
        return {p.pid: (p.ppid, p.name) for p in ntsnap.list_processes()}
    except (OSError, ImportError, AttributeError):
        return {}


def _live_connections(pid: int) -> list[str]:
    try:
        import psutil
        conns = psutil.Process(pid).net_connections(kind="inet")
    except Exception:  # noqa: BLE001 — процесс вышел или нет доступа: соединений не видно
        return []
    return sorted({f"{c.raddr.ip}:{c.raddr.port}" for c in conns if c.raddr})


def show(parent, pid: int, text: str | None = None) -> None:
    """Окно сводки (текст прокручивается и копируется). text — уже собранная сводка
    (сохранённая в журнале защиты на момент находки)."""
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QApplication, QDialog, QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout,
    )
    body = render(pid) if text is None else text
    dialog = QDialog(parent)
    dialog.setWindowTitle(f"Что делал процесс (PID {pid})")
    dialog.resize(980, 620)
    box = QVBoxLayout(dialog)
    view = QPlainTextEdit(body)
    view.setReadOnly(True)
    view.setFont(QFont("Consolas", 10))
    box.addWidget(view, 1)
    row = QHBoxLayout()
    copy = QPushButton("Копировать")
    copy.clicked.connect(lambda: QApplication.clipboard().setText(body))
    row.addWidget(copy)
    if text is None:
        again = QPushButton("Обновить")
        again.clicked.connect(lambda: view.setPlainText(render(pid)))
        row.addWidget(again)
    row.addStretch()
    close = QPushButton("Закрыть")
    close.clicked.connect(dialog.accept)
    row.addWidget(close)
    box.addLayout(row)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()


def render(pid: int, story: Story = STORY, live: dict | None = None,
           live_conns: list[str] | None = None) -> str:
    """Текст сводки по процессу (абзацы через пустую строку)."""
    live = _live_processes() if live is None else live
    rec = story.record(pid)
    name = (rec.name if rec and rec.name else "") or live.get(pid, (0, "?"))[1]
    parts = [f"Процесс: {name} (PID {pid})"]
    if rec and rec.exe:
        parts[0] += f"\nФайл: {rec.exe}"
    if rec and rec.cmdline:
        parts[0] += f"\nКомандная строка: {rec.cmdline}"
    if rec and rec.started:
        parts[0] += f"\nЗапущен: {_fmt(rec.started)}"
    elif "launch" not in story.sources:
        parts[0] += "\nЗапуск не отслеживался: контроль запуска выключен."
    else:
        parts[0] += "\nЗапущен до того, как программа начала следить за запусками."

    chain = story.chain(pid, live)
    parts.append("Кто запустил: " + (" ← ".join(f"{n} (PID {p})" for p, n in chain)
                                    if chain else "неизвестно (родитель уже завершился)"))

    if rec and rec.children:
        lines = []
        for child in rec.children[-30:]:
            c = story.record(child)
            if c is None:
                continue
            lines.append(f"• {_fmt(c.started)} {c.name or '?'} (PID {child})"
                         + (f": {c.cmdline[:200]}" if c.cmdline else ""))
        parts.append(f"Что запустил ({len(rec.children)}):\n" + "\n".join(lines))
    else:
        parts.append("Что запустил: ничего" if "launch" in story.sources
                     else "Что запустил: не отслеживалось (контроль запуска выключен).")

    if "files" not in story.sources:
        parts.append("Что создал: не отслеживалось — нужна защита от стилеров с правами "
                     "администратора (события файлов ETW).")
    elif rec and rec.files:
        items = sorted(rec.files.items(), key=lambda kv: kv[1][0])
        lines = [f"• {_fmt(t)} {path}" + (f" (×{n})" if n > 1 else "")
                 + ("" if os.path.exists(path) else " — файла уже нет")
                 for path, (t, n) in items[:40]]
        more = f"\n...и ещё {len(items) - 40}" if len(items) > 40 else ""
        parts.append(f"Что создал или перезаписал ({len(items)}; программы, скрипты, "
                     "макросы, архивы, ярлыки):\n" + "\n".join(lines) + more)
    else:
        parts.append("Что создал: программ, скриптов и архивов не создавал.")

    targets = rec.targets if rec else {}
    conns = _live_connections(pid) if live_conns is None else live_conns
    if targets or conns:
        lines = []
        for key, t in sorted(targets.items(), key=lambda kv: kv[1].first)[:50]:
            what = {"dns": "DNS", "tls": "сайт", "tcp": "TCP"}.get(t.kind, t.kind)
            lines.append(f"• {_fmt(t.first)} {what} {key}" + (f" ({t.detail})" if t.detail else "")
                         + (f", ×{t.count}, последний раз {_fmt(t.last)}" if t.count > 1 else ""))
        now_only = [c for c in conns if c not in targets]
        if now_only:
            lines.append("Открыто сейчас: " + ", ".join(now_only[:20]))
        parts.append(f"Куда подключался ({len(targets)}):\n" + "\n".join(lines))
    elif "net" not in story.sources:
        parts.append("Куда подключался: не отслеживалось — мониторинг сети выключен.")
    else:
        parts.append("Куда подключался: соединений не было.")
    return "\n\n".join(parts)
