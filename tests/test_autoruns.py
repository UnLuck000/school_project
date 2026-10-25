import sys

import pytest

from autoruns import actions
from autoruns.model import Entry
from autoruns.scanner import Context, assess
from recovery import journal


@pytest.fixture()
def tmp_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "journal")
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "journal" / "actions.jsonl")
    monkeypatch.setattr(journal, "BACKUP_DIR", tmp_path / "journal" / "backup")


def test_assess_suspicious_command():
    e = Entry(kind="run", name="x", location="", command="powershell -enc AAAA")
    assess(e, Context(set(), None, set()))
    assert e.level == "suspicious"
    assert e.assessed


def test_startup_file_move_and_undo(tmp_path, tmp_journal):
    src = tmp_path / "start.bat"
    src.write_text("echo hi")
    e = Entry(kind="startup", name="start.bat", location="", command=str(src),
              extra={"file": str(src)})

    actions.move_startup_file(e)
    assert not src.exists()

    record = journal.read_all()[0]
    assert not record["undone"]
    journal.undo(record["id"])
    assert src.exists()
    assert journal.read_all()[0]["undone"]
    with pytest.raises(ValueError):  # повторный откат запрещён
        journal.undo(record["id"])


def test_cannot_change_winlogon():
    e = Entry(kind="winlogon", name="Shell", location="", command="x", assessed=True)
    assert actions.can_remediate(e)[0] is False


@pytest.mark.skipif(sys.platform != "win32", reason="нужен реестр Windows")
def test_registry_remove_and_undo(tmp_journal):
    import winreg
    path = r"Software\StudyAVTest\Run"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "TestEntry", 0, winreg.REG_SZ, r"C:\test\app.exe")
    try:
        e = Entry(kind="run", name="TestEntry", location="", command="",
                  extra={"hive": "HKCU", "path": path, "value": "TestEntry"})
        actions.remove_registry_value(e)
        with pytest.raises(OSError):
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                winreg.QueryValueEx(key, "TestEntry")

        journal.undo(journal.read_all()[0]["id"])
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            assert winreg.QueryValueEx(key, "TestEntry")[0] == r"C:\test\app.exe"
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\StudyAVTest")