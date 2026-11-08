"""Журнал действий (снятые и повторные записи), журнал защиты, исключение программ из слоёв,
меню трея, правила брандмауэра Windows, этапы быстрой и полной проверки."""
import json
import threading

import pytest

from recovery import journal, threatlog


@pytest.fixture
def tmp_journal(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path)
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "actions.jsonl")
    monkeypatch.setattr(threatlog, "THREATS_FILE", tmp_path / "threats.json")
    return tmp_path


def test_cleanup_removes_settled_and_repeated(tmp_journal, monkeypatch):
    state = {"on": False}
    monkeypatch.setitem(journal.ACTIVE_CHECKS, "t_switch", lambda d: state["on"])
    journal.log_action("переключатель", "t_switch", {"x": 1})      # уже снят другим путём
    for _ in range(3):                                              # повторы одного и того же
        journal.log_action("одно и то же", "t_same", {"a": 1})
    journal.log_action("другое", "t_same", {"a": 2})
    assert journal.cleanup() == 3
    left = journal.read_all()
    assert [(r["op"], r["data"]) for r in left] == [("t_same", {"a": 1}), ("t_same", {"a": 2})]
    state["on"] = True
    journal.log_action("переключатель", "t_switch", {"x": 1})
    assert journal.cleanup() == 0                                    # в силе — остаётся


def test_forget_by_match(tmp_journal):
    journal.log_action("блокировка A", "t_block", {"names": ["a"]})
    journal.log_action("блокировка B", "t_block", {"names": ["b"]})
    assert journal.forget("t_block", lambda d: "a" in d["names"]) == 1
    assert [r["data"]["names"] for r in journal.read_all()] == [["b"]]


def test_threatlog_dedup_and_status(tmp_journal, tmp_path, monkeypatch):
    import quarantine
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "q")
    f = tmp_path / "bad.exe"
    f.write_bytes(b"MZ")
    first = threatlog.add(str(f), "threat", "YARA: x", "Защита файлов")
    again = threatlog.add(str(f), "threat", "YARA: x", "Полная проверка")
    assert first == again
    records = threatlog.merged()
    assert len(records) == 1 and records[0]["count"] == 2
    threatlog.mark_path(str(f), threatlog.QUARANTINED, "qid1")
    threatlog.dismiss(first)
    assert threatlog.merged() == []                                 # убрано из списка
    assert threatlog.merged(include_done=True)[0]["status"] == threatlog.DISMISSED


def test_file_exclusion_layers(tmp_path, monkeypatch, tmp_journal):
    from scanner import overrides
    monkeypatch.setattr(overrides, "OVERRIDES_FILE", tmp_path / "overrides.json")
    monkeypatch.setattr(overrides, "_cache", None)
    digest = "ab" * 32
    assert overrides.filter_reason(digest, "YARA: Rule") == "YARA: Rule"
    assert overrides.exclude_file(digest, r"C:\x\tool.exe", ["yara"])
    assert overrides.filter_reason(digest, "YARA: Rule") is None
    assert overrides.filter_reason(digest, "hash match") == "hash match"  # хэши — действуют
    assert overrides.filter_reason(digest, "Heuristic: 80") == "Heuristic: 80"
    overrides.ignore_hash("cd" * 32)  # правка хэшей не стирает исключённые программы
    assert overrides.file_excluded(digest, "yara")
    record = [r for r in journal.read_all() if r["op"] == "fp_file_include"][0]
    journal.undo(record["id"])
    assert not overrides.file_excluded(digest, "yara")


def test_tray_lists_all_tools():
    from ui import access, tray
    ids = [b for b, _ in tray.TRAY_TOOLS if b != "-"]
    assert ids[:3] == [tray.RECOVERY, "btnAutoruns", "btnProcessManager"]
    assert set(access.TOOL_LOCKS) <= set(ids)                       # все инструменты


def test_firewall_rule_string():
    from networkmonitor import firewall
    raw = ("v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RA4=1.2.3.4|RA4=5.6.7.8|"
           "App=%SystemRoot%\\x.exe|Name=Тест|")
    f = firewall.parse_rule_string(raw)
    assert f["Action"] == ["Block"] and f["RA4"] == ["1.2.3.4", "5.6.7.8"]
    assert f["Name"] == ["Тест"]


def test_scan_extras_by_mode(monkeypatch):
    from scanner import extras, fullscan
    called = []
    monkeypatch.setattr(extras, "scan_autoruns", lambda *a, **k: called.append("autoruns") or 5)
    monkeypatch.setattr(extras, "scan_system", lambda *a, **k: called.append("system") or 7)
    monkeypatch.setattr(extras, "scan_memory", lambda *a, **k: called.append("memory") or 9)
    stats, cancel = fullscan.Stats(), threading.Event()
    fullscan.run_extras("quick", stats, None, None, None, None, cancel, lambda t: None)
    assert called == ["autoruns"] and stats.autoruns == 5
    called.clear()
    fullscan.run_extras("full", stats, None, None, None, None, cancel, lambda t: None)
    assert called == ["autoruns", "system", "memory"]
    assert (stats.checks, stats.processes) == (7, 9)


def test_folder_files_stops_over_limit(tmp_path):
    from analyzer import fileops
    for i in range(5):
        (tmp_path / f"{i}.bin").write_bytes(b"x" * 1000)
    files, size, count, _ = fileops.folder_files(str(tmp_path), 1500, stop_over=True)
    assert files is None and size > 1500 and count < 5            # подсчёт остановлен
    files, size, count, _ = fileops.folder_files(str(tmp_path), 1500)
    assert files is None and size == 5000 and count == 5           # без stop_over — целиком


def test_journal_places_cover_vpn_and_firewall():
    from recovery.journal_page import PLACES
    for op in ("vpn_killswitch_off", "firewall_remove", "quarantine_restore", "reg_set"):
        assert op in PLACES
    json.dumps(PLACES)
