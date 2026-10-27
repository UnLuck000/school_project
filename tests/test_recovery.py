import sys

import pytest

from recovery import actions, journal
from recovery import system as rsys


@pytest.fixture()
def tmp_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "journal")
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "journal" / "actions.jsonl")
    monkeypatch.setattr(journal, "BACKUP_DIR", tmp_path / "journal" / "backup")


def _hosts(tmp_path, monkeypatch, text: str):
    hosts = tmp_path / "hosts"
    hosts.write_text(text, encoding="utf-8")
    monkeypatch.setattr(rsys, "HOSTS_FILE", hosts)
    return hosts


def test_default_hosts_is_clean(tmp_path, monkeypatch):
    _hosts(tmp_path, monkeypatch, "# стандартный файл\n\n# 127.0.0.1 localhost\n")
    findings = rsys.check_hosts()
    assert findings[0].level == "ok"


def test_hosts_security_domain_is_flagged(tmp_path, monkeypatch):
    _hosts(tmp_path, monkeypatch,
           "0.0.0.0 ads.example.com\n10.1.2.3 login.bank.example\n"
           "0.0.0.0 update.kaspersky.com\n")
    findings = {f.title: f for f in rsys.check_hosts()}
    assert findings["hosts: update.kaspersky.com"].level == "bad"
    assert findings["hosts: login.bank.example"].level == "warning"
    assert any("блокировки доменов" in f.title for f in findings.values())


def test_hosts_fix_and_undo(tmp_path, monkeypatch, tmp_journal):
    hosts = _hosts(tmp_path, monkeypatch, "# заголовок\n10.1.2.3 login.bank.example\n")
    finding = [f for f in rsys.check_hosts() if f.fix][0]
    actions.apply_fix(finding)
    assert "bank.example" not in hosts.read_text(encoding="utf-8")

    journal.undo(journal.read_all()[0]["id"])
    assert "bank.example" in hosts.read_text(encoding="utf-8")


def test_hosts_in_utf16_is_refused(tmp_path, monkeypatch, tmp_journal):
    hosts = tmp_path / "hosts"
    hosts.write_bytes("10.1.2.3 a.example\n".encode("utf-16"))
    monkeypatch.setattr(rsys, "HOSTS_FILE", hosts)
    with pytest.raises(OSError):
        actions.apply_fix(rsys.Finding("hosts", "x", "x", "10.1.2.3 a.example", "warning",
                                       "x", {"op": "hosts_remove", "raw": "10.1.2.3 a.example"}))


def test_run_command_ascii_and_utf16():
    chunks = []
    code = rsys.run_command([sys.executable, "-c", "print('hello')"], chunks.append)
    assert code == 0 and "hello" in "".join(chunks)

    chunks.clear()
    script = "import sys; sys.stdout.buffer.write('ok\\n'.encode('utf-16-le'))"
    rsys.run_command([sys.executable, "-c", script], chunks.append)
    assert "ok" in "".join(chunks)


def test_parse_restore_time():
    assert rsys._parse_wmi_time("20261027101530.123456-000") == "2026-10-27 10:15:30"


@pytest.mark.skipif(sys.platform != "win32", reason="нужен реестр Windows")
def test_registry_fix_and_undo(tmp_journal):
    import winreg
    path = r"Software\StudyAVTest\Policies"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Flag", 0, winreg.REG_DWORD, 0)
    try:
        finding = rsys.Finding("policy", "t", "s", "d", "bad", "fix", {
            "op": "reg_set", "hive": "HKCU", "path": path, "name": "Flag",
            "value": 1, "type": rsys.REG_DWORD})
        actions.apply_fix(finding)
        assert rsys.read_value("HKCU", path, "Flag")[1] == 1

        journal.undo(journal.read_all()[0]["id"])
        assert rsys.read_value("HKCU", path, "Flag")[1] == 0

        delete = rsys.Finding("policy", "t", "s", "d", "bad", "fix", {
            "op": "reg_delete", "hive": "HKCU", "path": path, "name": "Flag"})
        actions.apply_fix(delete)
        assert rsys.read_value("HKCU", path, "Flag")[0] is False
        journal.undo(journal.read_all()[1]["id"])
        assert rsys.read_value("HKCU", path, "Flag")[1] == 0
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\StudyAVTest")