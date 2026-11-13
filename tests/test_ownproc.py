"""Свои процессы программы (ownproc.py): служба не трогает собственное окно."""
import os
import sys

import ownproc
from scanner import launchguard
from toolbox import decoys, stealerguard

APP = r"C:\Program Files\StretchBIT\StretchBIT.exe"
CHROME_STATE = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Local State"


def frozen(monkeypatch, safe: bool = True):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", APP)
    monkeypatch.setattr(ownproc, "_dir_safe", safe)


def test_from_sources_only_this_process(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert ownproc.program_exe() == ""
    assert ownproc.is_program(os.getpid())
    # python.exe из исходников своим не считается: им был бы любой скрипт
    assert not ownproc.is_program(4321, sys.executable)
    assert not ownproc.in_program_dir(sys.executable)


def test_program_image_and_folder(monkeypatch):
    frozen(monkeypatch)
    assert ownproc.is_program(4321, APP.upper())
    assert not ownproc.is_program(4321, r"C:\Users\u\Downloads\StretchBIT.exe")
    assert ownproc.in_program_dir(r"C:\Program Files\StretchBIT\app\vpn\bin\xray.exe")
    assert not ownproc.in_program_dir(r"C:\Program Files\StretchBIT-evil\x.exe")
    monkeypatch.setattr(ownproc, "_dir_safe", False)  # папку может менять пользователь
    assert not ownproc.in_program_dir(r"C:\Program Files\StretchBIT\app\vpn\bin\xray.exe")


def test_stealer_guard_allows_own_window(monkeypatch):
    """Окно читает Local State («Расширения»), проверка дисков — Cookies: это не стилер."""
    guard = stealerguard.StealerGuard(lambda info: None)
    guard._trusted = set()
    monkeypatch.setattr(stealerguard, "_signed", lambda exe: False)
    assert not guard.allowed(4321, APP, CHROME_STATE)  # из исходников путь ничего не значит
    frozen(monkeypatch)
    assert guard.allowed(4321, APP, CHROME_STATE)
    assert not guard.allowed(4321, r"C:\Users\u\AppData\Roaming\StretchBIT.exe", CHROME_STATE)


def test_temp_profiles_are_not_secrets():
    """Одноразовый профиль во временной папке (тесты, Selenium) — не секреты пользователя."""
    temp = r"C:\Users\u\AppData\Local\Temp\pytest-1\Local\Google\Chrome\User Data"
    assert stealerguard.secret_kind(temp + r"\Local State") is None
    assert stealerguard.secret_kind(temp + r"\Default\Login Data") is None
    assert stealerguard.secret_kind(r"C:\Windows\Temp\profile\Cookies") is None
    assert stealerguard.secret_kind(CHROME_STATE) == "ключ расшифровки паролей"
    # папка с похожим именем — не временная
    assert stealerguard.secret_kind(r"D:\Temp files\Chrome\Default\Login Data") == "пароли"


def test_launch_guard_skips_own_files(monkeypatch, tmp_path):
    frozen(monkeypatch)
    events = []
    guard = launchguard.LaunchGuard(lambda kind, info: events.append((kind, info)))
    checked = []
    monkeypatch.setattr(guard, "_verdict", lambda paths: checked.extend(paths) or {})
    monkeypatch.setattr(launchguard, "_suspend", lambda pid: checked.append("suspend") or False)
    guard._check_new(4321, 1, APP, ["--scan-worker"])
    guard._check_new(4322, 1, r"C:\Program Files\StretchBIT\app\vpn\bin\xray.exe", [])
    assert checked == [] and events == []


def test_decoy_culprit_is_not_own_window(monkeypatch):
    frozen(monkeypatch)
    watcher = decoys.DecoyWatcher(lambda changed, culprit: None)
    watcher._history.clear()
    watcher._history.extend([(0.0, {50: (0, "StretchBIT.exe"), 60: (0, "evil.exe")}),
                             (1.0, {50: (9_000_000, "StretchBIT.exe"), 60: (1000, "evil.exe")})])
    monkeypatch.setattr(decoys, "_exe", lambda pid: APP if pid == 50 else r"C:\Temp\evil.exe")
    monkeypatch.setattr(decoys, "_signed", lambda exe: False)
    assert watcher.find_culprit()["pid"] == 60
