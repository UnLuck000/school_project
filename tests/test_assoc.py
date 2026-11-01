import sys

import pytest

from recovery import assoc, journal

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="нужен реестр Windows")

EXT = ".studyavtest"


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Временные журнал и снимки; тестовое расширение только в HKCU."""
    import winreg
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path)
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "actions.jsonl")
    monkeypatch.setattr(journal, "BACKUP_DIR", tmp_path / "backup")
    monkeypatch.setattr(assoc, "SNAPSHOT_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(assoc, "SNAPSHOT_EXTS", [EXT])
    monkeypatch.setattr(assoc, "all_extensions", lambda: [])
    yield winreg
    for path in (rf"{assoc.CLASSES}\{EXT}", rf"{assoc.CLASSES}\studyavevil\shell\open\command",
                 rf"{assoc.CLASSES}\studyavevil\shell\open", rf"{assoc.CLASSES}\studyavevil\shell",
                 rf"{assoc.CLASSES}\studyavevil"):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except OSError:
            pass


def test_norm_cmd_accepts_expanded_system_root():
    assert assoc._cmd_ok(r'"C:\WINDOWS\System32\cmd.exe" /c "%1" %*', assoc.CRITICAL[".bat"][1])
    assert not assoc._cmd_ok(r'"C:\evil.exe" "%1"', assoc.CRITICAL[".exe"][1])


def test_snapshot_compare_restore_and_undo(sandbox):
    winreg = sandbox
    snapshot = assoc.load_snapshot(assoc.take_snapshot("до перехвата"))
    assert assoc.compare(snapshot) == []

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"{assoc.CLASSES}\{EXT}") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, "studyavevil")
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                          rf"{assoc.CLASSES}\studyavevil\shell\open\command") as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, r'"C:\evil.exe" "%1"')

    diffs = assoc.compare(snapshot)
    assert any(d.field == "ProgID (HKCU)" and d.now == "studyavevil" for d in diffs)
    assert any("studyavevil" in d.field and "evil.exe" in d.now for d in diffs)
    ops = [op for d in diffs for op in d.ops]
    assert ops and all(op.hive == "HKCU" for op in ops)

    assoc.apply_ops(ops, "тест")
    assert assoc.compare(snapshot) == []

    record = journal.read_all()[-1]
    assert record["op"] == "assoc_restore"
    journal.undo(record["id"])
    assert assoc.read_state(EXT)["ProgID (HKCU)"]["value"] == "studyavevil"


def test_critical_check_on_clean_system_has_no_hkcu_ops():
    for issue in assoc.check_critical():
        if issue.level == "ok":
            assert not issue.ops
