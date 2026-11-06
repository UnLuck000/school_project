import hashlib

import pytest

from recovery import journal
from scanner import overrides, verdict_cache
from scanner.engine import check_file
from scanner.fpcheck import explain_file
from scanner.hashing import load_all_signatures
from scanner.yara_engine import load_rules
from ui.textutil import elide, elide_lines


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(overrides, "OVERRIDES_FILE", tmp_path / "overrides.json")
    monkeypatch.setattr(overrides, "_cache", None)
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "journal")
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "journal" / "actions.jsonl")
    monkeypatch.setattr(verdict_cache, "CACHE_FILE", tmp_path / "verdicts.sqlite")
    import scanner.yara_engine as ye
    monkeypatch.setattr(ye, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(ye, "LOG_FILE", tmp_path / "yara.log")
    sample = tmp_path / "files" / "tool.bin"
    sample.parent.mkdir()
    sample.write_bytes(b"harmless tool FP_MARKER_123")
    sigs = tmp_path / "sigs"
    (sigs / "feeds").mkdir(parents=True)
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    (sigs / "feeds" / "threatfox.txt").write_text(digest + "\n")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r.yar").write_text('rule FP_Rule { strings: $a = "FP_MARKER_123" condition: $a }')
    rules, _ = load_rules(rules_dir)
    return sample, digest, load_all_signatures(sigs), rules


def test_ignored_hash_and_disabled_rule(isolated):
    sample, digest, db, rules = isolated
    assert check_file(sample, db, rules, heuristics=False) == "hash match"
    assert db.source(digest) == "threatfox.txt"

    assert overrides.ignore_hash(digest, str(sample), "threatfox.txt")
    assert check_file(sample, db, rules, heuristics=False) == "YARA: FP_Rule"
    assert overrides.disable_rule("FP_Rule", "r")
    assert check_file(sample, db, rules, heuristics=False) is None

    hits = explain_file(sample, db, rules)  # разбор показывает и исключённое
    assert {h.layer for h in hits} == {"hash", "yara"}
    assert all(h.excluded and not h.active for h in hits)

    for record in reversed(journal.read_all()):  # отмена из журнала возвращает всё
        journal.undo(record["id"])
    assert check_file(sample, db, rules, heuristics=False) == "hash match"


def test_verdict_cache_skips_unchanged_file(isolated, monkeypatch):
    sample, _, db, rules = isolated
    assert check_file(sample, db, rules, heuristics=False) == "hash match"
    import scanner.engine as engine

    def boom(*a):
        raise AssertionError("файл не должен читаться повторно")
    monkeypatch.setattr(engine, "file_hashes", boom)
    assert check_file(sample, db, rules, heuristics=False) == "hash match"
    verdict_cache.flush()
    assert verdict_cache.get(sample, sample.stat(), "другая версия") is None


def test_empty_file_is_not_judged_by_hash(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    md5_empty = hashlib.md5(b"").hexdigest()
    assert check_file(empty, {md5_empty}, heuristics=False) is None


def test_elide_long_text():
    long = "x" * 1000
    assert len(elide(long)) == 300 and elide(long).endswith("…")
    assert elide("short") == "short"
    text = elide_lines(long + "\nвторая строка")
    assert text.endswith("вторая строка") and len(text.split("\n")[0]) == 300
