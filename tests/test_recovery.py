import sys

import pytest

from recovery import actions, checks, journal, policies
from recovery import system as rsys
from recovery.registry import REG_DWORD, read_value


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
    assert checks.check_hosts()[0].level == "ok"


def test_hosts_flags_security_domains(tmp_path, monkeypatch):
    _hosts(tmp_path, monkeypatch,
           "0.0.0.0 ads.example.com\n10.1.2.3 login.bank.example\n"
           "0.0.0.0 update.kaspersky.com\n0.0.0.0 preset.example.com\n")
    findings = {f.title: f for f in checks.check_hosts()}
    assert findings["hosts: update.kaspersky.com"].level == "bad"
    assert findings["hosts: login.bank.example"].level == "warning"
    assert "hosts: preset.example.com" not in findings  # «eset» внутри слова не считается
    assert any("блокировки доменов" in title for title in findings)


def test_hosts_fix_and_undo(tmp_path, monkeypatch, tmp_journal):
    hosts = _hosts(tmp_path, monkeypatch, "# заголовок\n10.1.2.3 login.bank.example\n")
    actions.apply_fix([f for f in checks.check_hosts() if f.fix][0])
    assert "bank.example" not in hosts.read_text(encoding="utf-8")
    journal.undo(journal.read_all()[0]["id"])
    assert "bank.example" in hosts.read_text(encoding="utf-8")


def test_hosts_in_utf16_is_refused(tmp_path, monkeypatch, tmp_journal):
    hosts = tmp_path / "hosts"
    hosts.write_bytes("10.1.2.3 a.example\n".encode("utf-16"))
    monkeypatch.setattr(rsys, "HOSTS_FILE", hosts)
    finding = rsys.Finding("hosts", "x", "x", "10.1.2.3 a.example", "warning", "x",
                           {"op": "hosts_remove", "raw": "10.1.2.3 a.example"})
    with pytest.raises(OSError):
        actions.apply_fix(finding)


def test_run_command_ascii_and_utf16():
    chunks = []
    assert rsys.run_command([sys.executable, "-c", "print('hello')"], chunks.append) == 0
    assert "hello" in "".join(chunks)
    chunks.clear()
    script = "import sys; sys.stdout.buffer.write('ok\\n'.encode('utf-16-le'))"
    rsys.run_command([sys.executable, "-c", script], chunks.append)
    assert "ok" in "".join(chunks)


def test_parse_restore_time():
    assert rsys._parse_wmi_time("20261027101530.123456-000") == "2026-10-27 10:15:30"


def test_parse_winhttp():
    proxy, bypass = b"127.0.0.1:8888", b"<local>"
    data = (b"\x28\x00\x00\x00" + b"\x01\x00\x00\x00" + (3).to_bytes(4, "little")
            + len(proxy).to_bytes(4, "little") + proxy
            + len(bypass).to_bytes(4, "little") + bypass)
    assert checks.parse_winhttp(data) == ("127.0.0.1:8888", "<local>")
    direct = b"\x28\x00\x00\x00" + b"\x01\x00\x00\x00" + b"\x01\x00\x00\x00" + b"\x00" * 4
    assert checks.parse_winhttp(direct) is None


def test_bcd_analysis():
    text = ("Windows Boot Loader\n-------------------\n"
            "identifier              {current}\n"
            "testsigning             Yes\n"
            "recoveryenabled         No\n"
            "bootstatuspolicy        IgnoreAllFailures\n")
    findings = checks.analyze_bcd(checks.parse_bcd(text))
    assert {f.fix["element"] for f in findings} == {
        "testsigning", "recoveryenabled", "bootstatuspolicy"}
    assert checks.analyze_bcd({"testsigning": "No"}) == []


def test_firewall_rules():
    base = "v2.31|Action={}|Active=TRUE|Dir={}|Protocol=6|App={}|Name={}|"
    assert checks.analyze_rule("id1", base.format(
        "Allow", "In", r"C:\Users\me\Downloads\tool.exe", "Tool")).level == "warning"
    assert checks.analyze_rule("id2", base.format(
        "Allow", "In", r"C:\Program Files\App\app.exe", "App")) is None
    assert checks.analyze_rule("id3", base.format(
        "Block", "Out", r"C:\Program Files\Kaspersky Lab\avp.exe", "Block")).level == "bad"
    assert checks.analyze_rule("id4", base.format("Block", "Out", "", "Preset")) is None
    assert checks.analyze_rule("id5", base.replace("TRUE", "FALSE").format(
        "Allow", "In", r"C:\Temp\x.exe", "x")) is None


@pytest.mark.skipif(sys.platform != "win32", reason="нужен реестр Windows")
def test_registry_fix_and_undo(tmp_journal):
    import winreg
    path = r"Software\SBITTest\Fix"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Flag", 0, winreg.REG_DWORD, 0)
    try:
        actions.apply_fix(rsys.Finding("x", "t", "s", "d", "bad", "fix", {
            "op": "reg_set", "hive": "HKCU", "path": path, "name": "Flag",
            "value": 1, "type": REG_DWORD}))
        assert read_value("HKCU", path, "Flag")[1] == 1
        journal.undo(journal.read_all()[0]["id"])
        assert read_value("HKCU", path, "Flag")[1] == 0

        actions.apply_fix(rsys.Finding("x", "t", "s", "d", "bad", "fix", {
            "op": "reg_delete", "hive": "HKCU", "path": path, "name": "Flag"}))
        assert read_value("HKCU", path, "Flag")[0] is False
        journal.undo(journal.read_all()[1]["id"])
        assert read_value("HKCU", path, "Flag")[1] == 0
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\SBITTest")


@pytest.mark.skipif(sys.platform != "win32", reason="нужен реестр Windows")
def test_policy_scan_unlock_and_undo(tmp_journal, monkeypatch):
    import winreg
    pol = r"Software\SBITTest\Pol"
    monkeypatch.setattr(policies, "CATALOG", [
        policies.Restriction("TestFlag", "Тест", (pol,)),
        policies.Restriction("TestDefault", "Тест со значением по умолчанию", (pol,),
                             default=1, bad=(0,))])
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, pol, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "TestFlag", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "TestDefault", 0, winreg.REG_DWORD, 0)
    try:
        hits = [h for h in policies.scan_restrictions() if h.hive == "HKCU" and h.path == pol]
        assert {h.name for h in hits} == {"TestFlag", "TestDefault"}

        actions.unlock_hits(hits)
        assert read_value("HKCU", pol, "TestFlag")[0] is False       # удалено
        assert read_value("HKCU", pol, "TestDefault")[1] == 1        # возвращено значение по умолчанию

        journal.undo(journal.read_all()[0]["id"])                    # одно действие отменяет всё
        assert read_value("HKCU", pol, "TestFlag")[1] == 1
        assert read_value("HKCU", pol, "TestDefault")[1] == 0
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, pol)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\SBITTest")


@pytest.mark.skipif(sys.platform != "win32", reason="нужен реестр Windows")
def test_disallow_run_list_is_found(tmp_journal, monkeypatch):
    import winreg
    explorer = r"Software\SBITTest\Explorer"
    monkeypatch.setattr(policies, "EXPLORER", explorer)
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, explorer + r"\DisallowRun", 0,
                            winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "1", 0, winreg.REG_SZ, "blocked_test.exe")
    try:
        hits = [h for h in policies.scan_restrictions()
                if h.hive == "HKCU" and h.kind == "disallow"]
        assert hits and "blocked_test.exe" in hits[0].title
        actions.unlock_hits(hits)
        assert read_value("HKCU", explorer + r"\DisallowRun", "1")[0] is False
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, explorer + r"\DisallowRun")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, explorer)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\SBITTest")
