"""Исключения тестовой версии попадают в релиз; кэш вердиктов и YARA на «неудобных» файлах;
DNS, заданный в Windows, в конфигурации sing-box."""
import json
import os
from types import SimpleNamespace

from recovery import journal


def _journal(tmp_path, monkeypatch):
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path)
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "actions.jsonl")


def test_verdict_cache_skips_huge_mtime(tmp_path, monkeypatch):
    from scanner import verdict_cache
    monkeypatch.setattr(verdict_cache, "CACHE_FILE", tmp_path / "v.sqlite")
    monkeypatch.setattr(verdict_cache, "_conn", None)
    st = SimpleNamespace(st_size=10, st_mtime_ns=2 ** 70)   # дата за пределами int64
    verdict_cache.put(tmp_path / "a.exe", st, "v1", "ab", None)
    verdict_cache.flush()                                    # без OverflowError
    assert verdict_cache.get(tmp_path / "a.exe", st, "v1") is None


def test_yara_matches_cyrillic_path(tmp_path):
    import yara
    from scanner.yara_engine import match_details
    rules = yara.compile(source='rule T { strings: $a = "MARKER" condition: $a }')
    path = tmp_path / "Русы не против Ящерок.url"
    path.write_bytes(b"xx MARKER xx")
    assert [m.rule for m in match_details(rules, path, raw=True)] == ["T"]


def test_test_edition_writes_release_overrides(tmp_path, monkeypatch):
    from scanner import overrides
    _journal(tmp_path, monkeypatch)
    monkeypatch.setattr(overrides, "OVERRIDES_FILE", tmp_path / "overrides.json")
    overrides.write_file(overrides.OVERRIDES_FILE, {"hashes": {"aa" * 32: {}}})
    profile = os.environ.get("USERPROFILE", r"C:\Users\x")
    assert overrides.exclude_file("bb" * 32, profile + r"\tool.exe", ["yara"])
    release = json.loads(overrides.RELEASE_FILE.read_text(encoding="utf-8"))
    assert release["files"]["bb" * 32]["path"] == r"%USERPROFILE%\tool.exe"  # без имени
    assert overrides.hash_ignored("aa" * 32)                 # локальный файл тоже читается
    assert overrides.file_excluded("bb" * 32, "yara")
    assert overrides.include_file("bb" * 32)
    assert not overrides.file_excluded("bb" * 32, "yara")


def test_network_exclusions_go_to_release(tmp_path, monkeypatch):
    from scanner import exclusions
    monkeypatch.setattr(exclusions, "EXCLUSIONS_FILE", tmp_path / "exclusions.json")
    monkeypatch.setattr(exclusions, "RELEASE_FILE", tmp_path / "release_exclusions.json")
    key = exclusions.program_key(r"C:\x\App.exe", "Example Ltd")
    assert key == "app.exe|pub:Example Ltd"
    exclusions.add("network", key, "App.exe", r"C:\x\App.exe")
    release = json.loads(exclusions.RELEASE_FILE.read_text(encoding="utf-8"))
    assert key in release["network"]                         # тестовая версия → релиз
    assert key in exclusions.load()["network"]
    assert exclusions.remove("network", key)
    assert key not in exclusions.load().get("network", {})


def test_singbox_uses_windows_dns_by_family():
    from vpn import singbox
    win = {"v4": ["8.8.8.8"], "v6": ["2001:4860:4860::8888"]}
    cfg = singbox.build_config(10808, r"C:\x\xray.exe", "prefer_ipv6", windows_dns=win)
    rules = {r["query_type"][0]: r["server"] for r in cfg["dns"]["rules"]}
    assert rules == {"A": "dns-win4", "AAAA": "dns-win6"}
    assert cfg["dns"]["final"] == "dns-remote"
    only4 = singbox.build_config(10808, r"C:\x\xray.exe", "ipv4", windows_dns=win)
    assert [r["server"] for r in only4["dns"]["rules"]] == ["dns-win4"]  # IPv6 закрыт
    assert "rules" not in singbox.build_config(10808, r"C:\x\xray.exe")["dns"]


def test_scans_skip_decoys(tmp_path, monkeypatch):
    """Проверка дисков и защита файлов не читают ловушки; занятый файл — не изменение."""
    from analyzer import fileops
    from scanner import fullscan
    from toolbox import decoys
    name = decoys.DECOY_NAME.lower()
    assert name in fullscan.SKIP_DIRS and name in fileops.DECOY_DIR
    for old in decoys.LEGACY_NAMES:  # папки прежних версий тоже не читаем
        assert old.lower() in fullscan.SKIP_DIRS and old.lower() in fileops.DECOY_DIR
    assert decoys.is_decoy(tmp_path / decoys.DECOY_NAME / "Пароли.txt")
    trap = tmp_path / decoys.DECOY_NAME
    trap.mkdir()
    (trap / "a.txt").write_bytes(b"x")
    (tmp_path / "b.txt").write_bytes(b"y")
    files, *_ = fileops.folder_files(str(tmp_path), 10 ** 6)
    assert [os.path.basename(f) for f in files] == ["b.txt"]
    calls = []

    def busy(path):
        calls.append(path)
        if len(calls) < 3:
            raise PermissionError(32, "занят")
        return "sha"
    monkeypatch.setattr(decoys, "_sha", busy)
    monkeypatch.setattr(decoys, "LOCK_WAIT", 0)
    assert decoys.changed_files({str(trap / "a.txt"): "sha"}) == []


def test_watchdog_ignores_reads():
    """Защита и ловушки не получают событий от чтения файлов (время доступа, атрибуты)."""
    import monitor  # noqa: F401  (ставит флаги при импорте)
    from watchdog.observers import winapi
    from scanner import watchflags
    assert winapi.WATCHDOG_FILE_NOTIFY_FLAGS == watchflags.CONTENT_FLAGS
    assert not watchflags.CONTENT_FLAGS & 0x20   # FILE_NOTIFY_CHANGE_LAST_ACCESS
    assert watchflags.CONTENT_FLAGS & 0x10       # запись остаётся


def test_vpn_builtin_rules_listed():
    from vpn import routing
    from vpn.window import builtin_rules
    rules = builtin_rules()
    assert any("geoip:private" in line for line in rules["rules_direct"])
    if routing.active().route_ru:
        assert "geosite:category-ru" in rules["rules_direct"]
