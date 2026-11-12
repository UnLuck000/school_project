import hashlib

import pytest

import updater
from monitor import RealtimeMonitor
from processmanager import memscan
from scanner.engine import check_file
from scanner.hashing import load_all_signatures
from scanner.yara_engine import fix_rules_source, load_rules, match_file


def test_fix_rules_keeps_good_rules():
    src = '''rule ok1 { strings: $a = "abc" condition: $a }
rule bad_mod { condition: cuckoo.network.http_request(/x/) }
rule ok2 { condition: filename == "x.exe" and myvar == "" }
rule ok1 { condition: true }
rule dep { condition: bad_mod }
rule info { meta: category = "INFO" condition: true }
rule ok3 { strings: $b = "zzz" condition: $b }
'''
    text, externals, fixes, error = fix_rules_source(src)
    assert error == "" and text is not None
    for name in ("ok1", "ok2", "ok3"):
        assert f"rule {name}" in text
    for name in ("bad_mod", "dep", "info"):
        assert f"rule {name}" not in text
    assert "myvar" in externals and "filename" in externals
    assert text.count("\n") == src.count("\n")  # номера строк не сдвигаются


def test_unfixable_file_is_reported():
    text, _, _, error = fix_rules_source('import "nonexistent_module"\nrule a { condition: true }')
    assert text is None and error


def test_load_rules_uses_cache_and_externals(tmp_path, monkeypatch):
    import scanner.yara_engine as ye
    monkeypatch.setattr(ye, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(ye, "LOG_FILE", tmp_path / "yara.log")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text('rule by_name { condition: filename == "evil.bin" }')
    rules, errors = load_rules(rules_dir)
    assert rules is not None and errors == []
    assert list((tmp_path / "cache").glob("yara_*.bin"))
    target = tmp_path / "evil.bin"
    target.write_bytes(b"x")
    assert match_file(rules, target) == ["by_name"]
    cached, _ = load_rules(rules_dir)  # второй раз из кэша
    assert match_file(cached, target) == ["by_name"]


def test_hashdb_text_and_binary(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"malware sample")
    md5 = hashlib.md5(sample.read_bytes()).hexdigest()
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    others = [hashlib.md5(str(i).encode()).hexdigest() for i in range(1000)]
    raw = "\n".join(others + [md5]).encode()
    (feeds / "virusshare_00001.md5.bin").write_bytes(updater.md5_bin(raw))
    (feeds / "x.txt").write_text("# c\n" + "a" * 64 + "\n")
    db = load_all_signatures(tmp_path)
    assert len(db) == 1002
    assert md5 in db and md5.upper() in db and "a" * 64 in db
    assert "b" * 32 not in db and "b" * 64 not in db and "zz" not in db
    assert check_file(sample, db, heuristics=False) == "hash match (MD5)"


def test_update_due_counts_from_1970():
    day = updater.UPDATE_INTERVAL
    assert updater.update_due(0, now=1_000_000_000)  # ни разу: обновить сразу
    assert not updater.update_due(1000, now=1000 + day - 1)
    assert updater.update_due(1000, now=1000 + day)
    assert updater.update_due(5000, now=1000)  # часы перевели назад


def test_monitor_filters_system_folders(tmp_path):
    user, system, startup = tmp_path / "user", tmp_path / "sys", tmp_path / "startup"
    mon = RealtimeMonitor([user], tmp_path, tmp_path, [], lambda *a: None,
                          system=[(system, False, False), (startup, True, True)])
    assert mon._wanted(user / "deep" / "notes.txt")          # папка пользователя: всё
    assert mon._wanted(system / "evil.exe")
    assert not mon._wanted(system / "log.etl")               # системная: только исполняемые
    assert not mon._wanted(system / "sub" / "evil.exe")      # без подпапок
    assert mon._wanted(startup / "a" / "task")               # автозагрузка: все файлы
    assert not mon._wanted(user / "file.crdownload")


def test_memory_batches_join_small_regions():
    regions = [(i, b"a" * 1000) for i in range(10)] + [(99, b"b" * memscan.BATCH)]
    blocks = sorted(memscan._batches(regions), key=len)
    assert len(blocks) == 2  # мелкие склеены в один блок, крупный отдельно
    assert blocks[0].count(b"a") == 10_000 and blocks[1] == b"b" * memscan.BATCH


@pytest.mark.skipif(memscan._read_native is None, reason="нет собранного модуля C++")
def test_native_reader_finds_marker():
    import os
    marker = bytearray(b"SBIT_NATIVE_" + b"Z" * 20)  # живёт в куче этого процесса
    chunks = memscan.read_regions(os.getpid())
    assert any(bytes(marker) in data for _, data in chunks)
    with pytest.raises(OSError):
        memscan.read_regions(4)  # System: нет доступа даже у администратора к памяти
