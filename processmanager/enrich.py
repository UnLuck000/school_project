import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PySide6.QtCore import QObject, Signal

import userdata

from scanner.heuristics import analyze_pe
from scanner.signature import describe, inspect_signature

CACHE_FILE = userdata.PROCESS_INFO_FILE  # папка конфигурации пользователя
MAX_CACHE = 4000
EMIT_INTERVAL = 0.4  # не чаще: интерфейсу не нужно обновляться на каждую программу


_save_lock = threading.Lock()


class Enricher(QObject):
    """Фоновая проверка подписей и упаковки программ запущенных процессов.
    Результат: (подпись, статус, упакован, .NET). Хранится в памяти и на диске."""
    changed = Signal()

    def __init__(self, workers: int = 3):
        super().__init__()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="enrich")
        self._results: dict[str, tuple] = {}
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._last_emit = 0.0
        self._load()

    @staticmethod
    def _key(exe: str):
        try:
            st = os.stat(exe)
        except OSError:
            return None
        return f"{exe}|{st.st_size}|{st.st_mtime_ns}"  # изменился файл: проверка повторится

    def peek(self, exe: str):
        """Готовый результат или None. Проверку не запускает."""
        key = self._key(exe)
        return self._results.get(key) if key else None

    def lookup(self, exe: str):
        """Готовый результат или None; в последнем случае проверка ставится в очередь."""
        key = self._key(exe)
        if key is None:
            return None
        result = self._results.get(key)
        if result is not None:
            return result
        with self._lock:
            if key in self._pending:
                return None
            self._pending.add(key)
        self._pool.submit(self._job, exe, key)
        return None

    def _job(self, exe: str, key: str) -> None:
        try:
            info = inspect_signature(Path(exe))
            sig_text, status = describe(info) or "—", info.status
        except Exception:
            sig_text, status = "—", ""
        packed = dotnet = False
        if status != "valid":  # у файлов с действительной подписью упаковку не ищем
            try:
                report = analyze_pe(Path(exe))
                packed = sum(f.points for f in report.findings if f.category == "pack") >= 4
                dotnet = report.dotnet
            except Exception:
                from diag.log import swallowed
                swallowed("enrich: разбор PE")
        with self._lock:
            self._results[key] = (sig_text, status, packed, dotnet)
            self._pending.discard(key)
            idle = not self._pending
        if idle:
            self.save()
        now = time.monotonic()
        if idle or now - self._last_emit > EMIT_INTERVAL:
            self._last_emit = now
            self.changed.emit()

    # ---------- кэш на диске ----------
    def _load(self) -> None:
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            self._results = {k: tuple(v) for k, v in data.items() if len(v) == 4}
        except (OSError, ValueError, AttributeError):
            self._results = {}

    def save(self) -> None:
        # сохраняют и рабочий поток, и shutdown: без блокировки они пишут один временный
        # файл одновременно, и замена срывается у обоих
        with _save_lock:
            try:
                with self._lock:
                    items = list(self._results.items())[-MAX_CACHE:]
                CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
                tmp = CACHE_FILE.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(dict(items), ensure_ascii=False), encoding="utf-8")
                os.replace(tmp, CACHE_FILE)
            except OSError:
                pass  # кэш не критичен

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
        self.save()
