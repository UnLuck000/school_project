"""Повторная проверка памяти (processmanager/memcache.py): что пропускается и что нет."""
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from processmanager import memcache
from processmanager.memscan import MemResult

# дочерний процесс по команде выделяет память с правами «запись + выполнение» — как
# внедрённый код
CHILD = ("import ctypes, sys\n"
         "k = ctypes.windll.kernel32\n"
         "k.VirtualAlloc.restype = ctypes.c_void_p\n"
         "print('ready', flush=True)\n"
         "sys.stdin.readline()\n"
         "k.VirtualAlloc(None, 65536, 0x3000, 0x40)\n"
         "print('injected', flush=True)\n"
         "sys.stdin.readline()\n")


@pytest.fixture
def child():
    proc = subprocess.Popen([sys._base_executable, "-c", CHILD], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "ready"
    memcache.forget()
    yield proc
    proc.kill()
    memcache.forget()


@pytest.mark.skipif(sys.platform != "win32", reason="память процессов — только Windows")
def test_system_process_skipped_until_changed(child, monkeypatch):
    p = SimpleNamespace(pid=child.pid, created=123.0, exe=sys._base_executable, masq=False)
    monkeypatch.setattr(memcache, "is_system", lambda proc: True)
    cached, fp = memcache.lookup(p, "rules-1")
    assert cached is None and fp                       # первая проверка — сканировать
    memcache.store(p, "rules-1", fp, MemResult("clean", scanned=1))
    cached, _ = memcache.lookup(p, "rules-1")
    assert cached is not None and cached.cached and "не изменился" in cached.text()

    assert memcache.lookup(p, "rules-2")[0] is None    # другие правила
    assert memcache.lookup(p, "rules-1", now=time.time() + memcache.TTL + 1)[0] is None

    child.stdin.write("go\n")
    child.stdin.flush()
    assert child.stdout.readline().strip() == "injected"
    assert memcache.lookup(p, "rules-1")[0] is None    # появился исполняемый регион


@pytest.mark.skipif(sys.platform != "win32", reason="память процессов — только Windows")
def test_ordinary_apps_and_matches_not_cached(child, monkeypatch):
    p = SimpleNamespace(pid=child.pid, created=1.0, exe=sys._base_executable, masq=False)
    assert not memcache.is_system(p)                   # python.exe не из папки Windows
    assert memcache.lookup(p, "r") == (None, None)
    monkeypatch.setattr(memcache, "is_system", lambda proc: True)
    _, fp = memcache.lookup(p, "r")
    memcache.store(p, "r", fp, MemResult("match", ["Evil"]))
    assert memcache.lookup(p, "r")[0] is None          # совпадение — всегда заново
    memcache.store(p, "r", fp, MemResult("clean"))
    monkeypatch.setattr(memcache, "exe_stamp", lambda exe: ("changed", 1, 1))
    assert memcache.lookup(p, "r")[0] is None          # файл программы изменён


@pytest.mark.skipif(sys.platform != "win32", reason="только Windows")
def test_real_system_process_is_system():
    import os
    exe = os.path.join(os.environ["SystemRoot"], "System32", "notepad.exe")
    assert memcache.is_system(SimpleNamespace(exe=exe, masq=False))
    assert not memcache.is_system(SimpleNamespace(exe=exe, masq=True))  # подделка имени


def test_kernel_processes_without_file():
    from processmanager.memscan import kernel_process
    assert kernel_process(4, 0, "") and kernel_process(0, 0, "")
    assert kernel_process(232, 4, "Registry") and kernel_process(4488, 4, "MemCompression")
    assert not kernel_process(856, 4, r"C:\Windows\System32\smss.exe")  # с файлом — проверяем
    assert not kernel_process(1000, 856, "")                             # не ребёнок System
