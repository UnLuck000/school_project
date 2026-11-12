"""Усиление защиты: списки доверия, кэш вердиктов, карантин, пароль, автокарантин."""
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

import trustseal


@pytest.fixture
def seal(tmp_path, monkeypatch):
    monkeypatch.setenv(trustseal.ENV_DIR, str(tmp_path / "seal"))
    monkeypatch.delenv(trustseal.ENV_OFF, raising=False)
    trustseal.reset_state()
    yield tmp_path
    trustseal.reset_state()


# ---------- списки доверия ----------
def test_foreign_change_of_whitelist_is_ignored(seal, monkeypatch):
    from scanner import whitelist
    path = seal / "cfg" / "whitelist.json"
    monkeypatch.setattr(whitelist, "WHITELIST_FILE", path)
    assert whitelist.add_to_whitelist("a" * 64, r"C:\good.exe")
    trustseal.finish_first_run([path])

    # «вредонос» дописывает свой хэш прямо в файл
    path.write_text(path.read_text(encoding="utf-8").replace("a" * 64, "b" * 64),
                    encoding="utf-8")
    trustseal.reset_state()  # как после перезапуска: программа этого не писала
    assert set(whitelist.load_whitelist()) == {"a" * 64}
    assert str(path) in trustseal.pending()

    trustseal.reject(path)
    assert set(whitelist.load_whitelist()) == {"a" * 64} and not trustseal.pending()
    assert "b" * 64 not in path.read_text(encoding="utf-8")


def test_accepted_change_takes_effect(seal, monkeypatch):
    from scanner import whitelist
    path = seal / "cfg" / "whitelist.json"
    monkeypatch.setattr(whitelist, "WHITELIST_FILE", path)
    whitelist.add_to_whitelist("a" * 64, "x")
    trustseal.finish_first_run([path])
    path.write_text('{"%s": {"path": "y"}}' % ("c" * 64), encoding="utf-8")
    trustseal.reset_state()
    assert set(whitelist.load_whitelist()) == {"a" * 64}
    trustseal.accept(path)
    assert set(whitelist.load_whitelist()) == {"c" * 64}


def test_first_run_trusts_existing_files(seal, monkeypatch):
    """Обновление со старой версии: защищённых копий ещё нет — файлы принимаются как есть."""
    from scanner import whitelist
    path = seal / "cfg" / "whitelist.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"%s": {"path": "old"}}' % ("d" * 64), encoding="utf-8")
    monkeypatch.setattr(whitelist, "WHITELIST_FILE", path)
    assert set(whitelist.load_whitelist()) == {"d" * 64} and not trustseal.pending()


# ---------- кэш вердиктов ----------
@pytest.fixture
def cache(seal, monkeypatch):
    from scanner import verdict_cache
    monkeypatch.setattr(verdict_cache, "CACHE_FILE", seal / "verdicts.sqlite")
    monkeypatch.setattr(verdict_cache, "_conn", None)
    verdict_cache._pending.clear()
    return verdict_cache


def test_cache_row_cannot_be_forged(cache, seal):
    exe = seal / "tool.exe"
    exe.write_bytes(b"MZ" + b"\0" * 64)
    st = exe.stat()
    cache.put(exe, st, "v1", "s" * 64, "hash match")
    cache.flush()
    assert cache.get(exe, st, "v1") == ("s" * 64, "hash match")

    # правим вердикт на «чисто» прямо в базе, как сделал бы вредонос
    conn = sqlite3.connect(str(seal / "verdicts.sqlite"))
    conn.execute("UPDATE verdicts2 SET reason = NULL")
    conn.commit()
    conn.close()
    assert cache.get(exe, st, "v1") is None  # подпись строки не сошлась — проверяем заново


def test_cache_notices_rewritten_exe_with_old_date(cache, seal):
    """Файл переписали и вернули прежнюю дату изменения: ChangeTime выдаёт подмену."""
    import os
    exe = seal / "app.exe"
    exe.write_bytes(b"MZ" + b"A" * 64)
    st = exe.stat()
    if not cache.change_time(exe):
        pytest.skip("ChangeTime недоступен на этой файловой системе")
    cache.put(exe, st, "v1", "s" * 64, None)
    cache.flush()
    exe.write_bytes(b"MZ" + b"B" * 64)
    os.utime(exe, ns=(st.st_atime_ns, st.st_mtime_ns))
    again = exe.stat()
    assert (again.st_size, again.st_mtime_ns) == (st.st_size, st.st_mtime_ns)
    assert cache.get(exe, again, "v1") is None


def test_change_time_only_for_executables(cache, seal):
    doc = seal / "note.txt"
    doc.write_text("x")
    assert cache.change_time(doc) == 0


# ---------- карантин ----------
def test_quarantine_stores_file_neutralized(tmp_path, monkeypatch):
    import quarantine
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "q")
    monkeypatch.setattr(quarantine, "add_to_whitelist", lambda *a: True)
    body = b"MZ" + bytes(range(256)) * 9000  # больше одного куска чтения
    src = tmp_path / "evil.exe"
    src.write_bytes(body)
    item = quarantine.quarantine_file(src, "test")
    stored = tmp_path / "q" / f"{item}.quar"
    assert not src.exists() and stored.stat().st_size == len(body)
    assert stored.read_bytes()[:2] != b"MZ" and stored.read_bytes() != body
    assert quarantine.restore_file(item) == src.resolve()
    assert src.read_bytes() == body and not stored.exists()


def test_quarantine_restores_items_of_old_versions(tmp_path, monkeypatch):
    """Записи без «encoding» (прежние версии) лежат как есть."""
    import json

    import quarantine
    from scanner.hashing import sha256_of
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "q")
    monkeypatch.setattr(quarantine, "add_to_whitelist", lambda *a: True)
    (tmp_path / "q").mkdir()
    stored = tmp_path / "q" / "old1.quar"
    stored.write_bytes(b"plain content")
    dest = tmp_path / "back.bin"
    (tmp_path / "q" / "old1.json").write_text(json.dumps({
        "id": "old1", "status": "quarantined", "original_path": str(dest),
        "sha256": sha256_of(stored), "quarantined_at": "2026-01-01T00:00:00"}), encoding="utf-8")
    quarantine.restore_file("old1")
    assert dest.read_bytes() == b"plain content"


# ---------- пароль ----------
def test_new_password_uses_pbkdf2_and_old_still_works(tmp_path):
    from ui.debug_mode import PBKDF2_PREFIX, PasswordGate
    path = tmp_path / "passwords.txt"
    gate = PasswordGate(path, default=("", ""))
    gate.set_password("Secret-1")
    assert PBKDF2_PREFIX in path.read_text(encoding="utf-8")
    assert gate.check("secret-1") and not gate.check("secret-2")

    # файл прежней версии: соль и один проход SHA-256
    old = tmp_path / "old.txt"
    old.write_text("salt:abc\n" + PasswordGate._hash("abc", "legacy1") + "\n", encoding="utf-8")
    assert PasswordGate(old, default=("", "")).check("LEGACY1")


# ---------- автокарантин и ярлыки ----------
def test_auto_quarantine_only_by_hash_outside_windows(monkeypatch):
    import monitor
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert monitor.auto_quarantine(r"C:\Users\u\Downloads\x.exe", "hash match")
    assert monitor.auto_quarantine(r"D:\x.exe", "hash match (MD5)")
    assert not monitor.auto_quarantine(r"C:\Users\u\x.exe", "YARA: Some_Rule")
    assert not monitor.auto_quarantine(r"C:\Users\u\x.exe", "Heuristic: 80")
    assert not monitor.auto_quarantine(r"C:\Windows\System32\x.dll", "hash match")


def test_launcher_shortcut_is_not_a_threat(tmp_path, monkeypatch):
    from scanner import engine
    steam = tmp_path / "Game.url"
    steam.write_bytes(b"[InternetShortcut]\r\nURL=steam://rungameid/123\r\nIconFile=x.ico\r\n")
    odd = tmp_path / "Odd.url"
    odd.write_bytes(b"[InternetShortcut]\r\nURL=file://evil/share/x.hta\r\n")
    assert engine.launcher_shortcut(steam) and not engine.launcher_shortcut(odd)
    assert not engine.launcher_shortcut(tmp_path / "Game.lnk")

    rule = SimpleNamespace(rule="Methodology_Contains_Shortcut_OtherURIhandlers",
                           namespace="x", meta={})
    monkeypatch.setattr(engine, "match_details", lambda rules, p, data=None: [rule])
    monkeypatch.setattr(engine, "inspect_signature",
                        lambda p: SimpleNamespace(status="unsigned"))
    assert engine.analyze(steam, object(), heuristics=False) is None
    assert engine.analyze(odd, object(), heuristics=False).startswith("YARA: Methodology_")


# ---------- настройки и диагностика ----------
def test_settings_reset_works():
    from ui import settings as cfg
    cfg.set_("general/on_top", True)
    cfg.reset()
    assert cfg.get("general/on_top") is cfg.DEFAULTS["general/on_top"]


def test_bundle_name():
    import appinfo
    from diag import bundle
    name = bundle.default_name(0)
    assert name.startswith(f"logs-SBIT-v{appinfo.VERSION}-") and name.endswith(".zip")


def test_powershell_runs_by_full_path():
    import syscmd
    assert Path(syscmd.POWERSHELL).is_absolute() and syscmd.PS_ARGS[0] == syscmd.POWERSHELL


# ---------- сторож ----------
@pytest.fixture
def guard(tmp_path, monkeypatch):
    import selfguard
    monkeypatch.setattr(selfguard, "SESSION", tmp_path / "session.json")
    monkeypatch.setattr(selfguard, "STATE", tmp_path / "selfguard.json")
    monkeypatch.setattr(selfguard, "NO_RESTART", tmp_path / "no_restart")
    monkeypatch.setattr(selfguard, "CRASH_LOG", tmp_path / "crash.log")
    monkeypatch.setattr(selfguard, "_installer_running", lambda: False)
    return selfguard


def test_watchdog_restarts_only_after_abnormal_exit(guard):
    assert guard.decide(4321) == ""  # метки сеанса нет: выход был обычным
    guard.SESSION.write_text('{"pid": 4321, "started": 1}', encoding="utf-8")
    assert guard.decide(1111) == ""  # метка другого процесса
    assert guard.decide(4321) == "restart"


def test_watchdog_respects_setup_and_limit(guard, monkeypatch):
    guard.SESSION.write_text('{"pid": 7, "started": 1}', encoding="utf-8")
    guard.forbid_restart()
    assert "установка" in guard.decide(7)
    guard.NO_RESTART.unlink()
    monkeypatch.setattr(guard, "_installer_running", lambda: True)
    assert "установщик" in guard.decide(7)
    monkeypatch.setattr(guard, "_installer_running", lambda: False)
    assert [guard.decide(7) for _ in range(3)] == ["restart"] * 3
    assert "перезапусков" in guard.decide(7)  # четвёртый раз за 10 минут — нет


def test_watchdog_is_off_for_source_runs(monkeypatch):
    import selfguard
    monkeypatch.delenv("STRETCHBIT_WATCHDOG", raising=False)
    monkeypatch.delattr("sys.frozen", raising=False)
    assert not selfguard.allowed() and not selfguard.start()


# ---------- быстрый путь: крупная подписанная программа без YARA ----------
def _big_exe(tmp_path, name="big.exe"):
    from scanner import engine
    exe = tmp_path / name
    exe.write_bytes(b"MZ" + b"\0" * engine.SIGNATURE_FIRST)
    return exe


def test_signed_large_program_skips_yara(tmp_path, monkeypatch):
    from scanner import engine
    from scanner.signature import SignatureInfo
    exe = _big_exe(tmp_path)
    calls = []
    monkeypatch.setattr(engine, "match_details",
                        lambda rules, p, data=None: calls.append(p) or [])
    monkeypatch.setattr(engine, "inspect_signature",
                        lambda p: SignatureInfo("valid", "Vendor", "embedded", cert="aa"))
    assert engine.analyze(exe, object(), heuristics=False, revocation=False) is None
    assert calls == []  # правила не запускались

    small = tmp_path / "small.exe"
    small.write_bytes(b"MZ" + b"\0" * 1000)
    engine.analyze(small, object(), heuristics=False, revocation=False)
    assert calls == [small]  # мелкий файл — обычным путём


def test_unsigned_or_revoked_large_program_goes_full_way(tmp_path, monkeypatch):
    from scanner import engine
    from scanner.signature import SignatureInfo
    exe = _big_exe(tmp_path)
    rule = SimpleNamespace(rule="Evil_Rule", namespace="x", meta={})
    monkeypatch.setattr(engine, "match_details", lambda rules, p, data=None: [rule])
    monkeypatch.setattr(engine, "inspect_signature", lambda p: SignatureInfo("unsigned"))
    assert engine.analyze(exe, object(), heuristics=False, revocation=False) == "YARA: Evil_Rule"

    monkeypatch.setattr(engine, "inspect_signature",
                        lambda p: SignatureInfo("valid", "Vendor", "embedded", cert="bb"))
    monkeypatch.setattr(engine, "trusted_fast",
                        lambda p, info, revocation: SignatureInfo("revoked", "Vendor",
                                                                  "embedded", "revoked", "bb"))
    assert engine.analyze(exe, object(), heuristics=False, revocation=True) == \
        "YARA: Evil_Rule [сертификат отозван]"


def test_revocation_is_asked_once_per_certificate(tmp_path, monkeypatch):
    from dataclasses import replace

    from scanner import signature
    asked = []
    monkeypatch.setattr(signature, "check_revocation",
                        lambda path, info: asked.append(path) or replace(info, revocation="ok"))
    monkeypatch.setattr(signature, "_cert_checked", {})
    info = signature.SignatureInfo("valid", "Vendor", "embedded", cert="cc")
    a, b = tmp_path / "a.exe", tmp_path / "b.exe"
    assert signature.trusted_fast(a, info, True).revocation == "ok"
    assert signature.trusted_fast(b, info, True).revocation == "ok"
    assert asked == [a]  # второй файл того же сертификата — без запроса
    other = replace(info, cert="dd")
    signature.trusted_fast(b, other, True)
    assert asked == [a, b]
    assert signature.trusted_fast(a, info, False) is info and len(asked) == 2  # отзыв выключен


def test_check_stream_matches_check_files(tmp_path):
    from scanner import pool
    from scanner.hashing import sha256_of
    files = []
    for i in range(40):
        f = tmp_path / f"f{i}.bin"
        f.write_bytes(b"data-%d" % i)
        files.append(str(f))
    bad = sha256_of(Path(files[7]))
    scan = pool.ScanPool(2)
    try:
        stream = {p: (r, e) for p, r, e in pool.check_stream(
            iter(files + [str(tmp_path / "missing.bin")]), {bad}, None, pool=scan, window=4)}
    finally:
        scan.shutdown()
    assert len(stream) == 41 and stream[files[7]][0] == "hash match"
    assert isinstance(stream[str(tmp_path / "missing.bin")][1], OSError)
    assert all(r is None and e is None for p, (r, e) in stream.items()
               if p not in (files[7], str(tmp_path / "missing.bin")))
