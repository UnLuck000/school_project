"""Ядро службы в отдельном процессе для tests/test_service.py (как настоящая служба: окно
и служба — разные процессы). Аргументы: имя канала, папка данных. Рабочая папка — временная:
карантин и своя база хэшей (относительные пути) — там же. Выход — когда закрыт stdin."""
import sys
from pathlib import Path

import userdata

userdata.set_root(Path(sys.argv[2]) / "config")
from service.core import ServiceCore  # noqa: E402


class Monitor:
    def __init__(self, folders, on_event):
        self.on_event = on_event

    def start(self):
        self.on_event("status", "Защита включена (тест)")

    def stop(self):
        self.on_event("stopped", "Защита выключена")

    def reload_bases(self):
        pass


core = ServiceCore(Path(sys.argv[2]) / "svc", monitor_factory=Monitor)
core.start_pipe(sys.argv[1])
print("ready", flush=True)
sys.stdin.read()
core.stop()
