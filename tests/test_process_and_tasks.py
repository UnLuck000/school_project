import json
import time

from autoruns import scanner
from processmanager import enrich
from processmanager import system as pm_system
from scanner.signature import SignatureInfo


def test_parse_tasklist():
    text = ('"System Idle Process","0","N/A"\n'
            '"svchost.exe","888","BrokerInfrastructure,DcomLaunch"\n'
            '"svchost.exe","1200","Schedule"\n'
            '"notepad.exe","4000","Н/Д"\n')
    pids, schedule = pm_system.parse_tasklist(text)
    assert pids == {888, 1200}
    assert schedule == 1200


def test_collect_tasks_from_scheduler(monkeypatch):
    sample = json.dumps([
        {"p": "\\", "n": "MyTask", "s": "Ready", "c": r"C:\Tools\app.exe", "g": "--silent",
         "k": ["Logon"]},
        {"p": "\\Microsoft\\Windows\\X\\", "n": "Com", "s": "Ready", "c": None, "g": None, "k": []},
        {"p": "\\Folder\\", "n": "Off", "s": "Disabled", "c": r"C:\Tools\b.exe", "g": None,
         "k": "Boot"},
    ])
    monkeypatch.setattr(scanner, "_powershell", lambda script, env_extra=None, timeout=20: sample)
    entries, notes = scanner.collect_tasks()
    names = {e.name: e for e in entries}
    assert set(names) == {"\\MyTask", "\\Folder\\Off"}
    assert names["\\MyTask"].command.endswith("--silent") and names["\\MyTask"].enabled
    assert not names["\\Folder\\Off"].enabled
    assert "Boot" in names["\\Folder\\Off"].location
    assert notes  # одна задача без исполняемого файла пропущена


def test_enricher_caches_results(tmp_path, monkeypatch):
    monkeypatch.setattr(enrich, "CACHE_FILE", tmp_path / "cache.json")
    monkeypatch.setattr(enrich, "inspect_signature",
                        lambda path: SignatureInfo("valid", "ACME", "embedded"))
    exe = tmp_path / "a.exe"
    exe.write_bytes(b"MZ")
    enricher = enrich.Enricher(workers=1)
    assert enricher.lookup(str(exe)) is None  # проверка поставлена в очередь
    deadline = time.time() + 5
    while enricher.peek(str(exe)) is None and time.time() < deadline:
        time.sleep(0.05)
    result = enricher.peek(str(exe))
    assert result is not None and result[1] == "valid" and result[0].startswith("Действительна")
    assert enricher.lookup(str(exe)) == result  # второй раз берётся из кэша
    enricher.shutdown()
    assert (tmp_path / "cache.json").exists()

    exe.write_bytes(b"MZ-changed")  # файл изменился: старый результат не подходит
    assert enricher.peek(str(exe)) is None