"""Сбои системных программ (diag/systool): причина, предупреждение, запись в журнале."""
import os
import subprocess
import sys

import pytest

import syscmd
from diag import systool
from recovery import journal

PS = syscmd.POWERSHELL


@pytest.fixture(autouse=True)
def _fresh():
    systool.reset()
    yield
    systool.reset()


def test_blocked_start_and_policy():
    e = OSError(13, "Отказано в доступе")
    e.winerror = 5
    f = systool.diagnose([PS, "-Command", "x"], error=e, command="PowerShell: x")
    assert f.cause == "blocked" and "антивирус" in f.short_text().lower()
    e.winerror = 1260
    assert systool.diagnose([PS], error=e).cause == "policy"


def test_status_codes_and_output():
    assert systool.diagnose([PS], returncode=-1073741790).cause == "blocked"   # 0xC0000022
    assert systool.diagnose([PS], returncode=0xC0000142).cause == "init_failed"
    out = "Get-NetAdapter : The term 'Get-NetAdapter' is not recognized as the name of a cmdlet"
    assert systool.diagnose([PS], returncode=1, output=out).cause == "cmdlet"
    assert systool.diagnose([PS], returncode=1, output="Недопустимый класс").cause == "wmi"
    assert systool.diagnose([PS], returncode=1, output="Cannot invoke method. Method "
                            "invocation is supported only on core types in this language "
                            "mode.").cause == "constrained"


def test_ignored_cases():
    assert systool.diagnose([PS], returncode=1, output="ERROR: задание не найдено") is None
    assert systool.diagnose(["schtasks"], returncode=1, output="ERROR: Access is denied.") is None
    assert systool.diagnose([r"C:\Users\x\powershell.exe"], returncode=0xC0000022) is None
    assert systool.diagnose(["xray.exe"], returncode=0xC0000022) is None
    assert systool.diagnose(["schtasks", "/query"], returncode=-1073741790).cause == "blocked"


def test_report_once_journal_notice_and_listener():
    got = []
    failure = systool.Failure("powershell.exe", "blocked", "PowerShell: Get-Date", "WinError 5")
    systool.report(failure)          # слушателя ещё нет — сбой ждёт его
    systool.add_listener(got.append)
    try:
        systool.report(failure)      # повтор той же причины — без второго предупреждения
        with systool.context("Сканер автозапуска"):
            systool.report(systool.Failure("netsh.exe", "policy", "netsh wfp", "WinError 1260"))
    finally:
        systool._listeners.remove(got.append)
    assert [f.tool for f in got] == ["powershell.exe", "netsh.exe"]
    assert got[1].where == "Сканер автозапуска"
    notices = [r for r in journal.read_all() if r.get("notice")]
    assert len(notices) == 2 and "Что сделать" in notices[0]["data"]["details"]
    with pytest.raises(ValueError, match="отменять нечего"):
        journal.undo(notices[0]["id"])
    journal.cleanup()                # записи о сбое не убираются как «снятые»
    assert len([r for r in journal.read_all() if r.get("notice")]) == 2


@pytest.mark.skipif(sys.platform != "win32" or not os.path.isfile(PS), reason="нужен PowerShell")
def test_real_powershell_missing_command():
    """Настоящий PowerShell: несуществующая команда — причина «нет команды»."""
    from diag import proc
    proc.install()
    got = []
    systool.add_listener(got.append)
    try:
        subprocess.run(syscmd.PS_ARGS + ["Get-SbitNoSuchCommand"], capture_output=True,
                       timeout=60, creationflags=syscmd.CREATE_NO_WINDOW)
    finally:
        systool._listeners.remove(got.append)
    assert got and got[0].cause == "cmdlet" and got[0].tool == "powershell.exe"
