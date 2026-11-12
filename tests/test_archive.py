"""Вложенные файлы архивов при обычной проверке (scanner/archive.py)."""
import hashlib
import zipfile
from pathlib import Path
from types import SimpleNamespace

from scanner import archive, engine

EVIL = b"MZ" + b"evil-program-body" * 50


def _zip(path, files, password=False):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return path


def test_members_only_programs_scripts_macros(tmp_path):
    z = _zip(tmp_path / "a.zip", {
        "readme.txt": b"hello " * 100, "pic.png": b"\x89PNG" + b"x" * 500,
        "tool.bin": EVIL,                      # программа без расширения — по «MZ»
        "run.ps1": b"Write-Host hi" * 10, "word/vbaProject.bin": b"macro" * 40,
        "lib/A.class": b"\xca\xfe\xba\xbe" + b"c" * 300})
    names = {n for n, _ in archive.members(z)}
    assert names == {"tool.bin", "run.ps1", "word/vbaProject.bin"}
    assert not archive.is_archive(b"MZ not a zip") and archive.is_archive(z.read_bytes())


def test_zip_bomb_and_broken_archives_are_skipped(tmp_path):
    bomb = _zip(tmp_path / "bomb.zip", {"big.exe": b"MZ" + b"\0" * (4 << 20)})
    assert list(archive.members(bomb)) == []       # сжато сильнее 200 раз
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"PK\x03\x04" + b"garbage" * 100)
    assert archive.inspect(broken, None, None) == (None, [])


def test_hash_of_member_is_found_by_check_file(tmp_path):
    z = _zip(tmp_path / "pack.zip", {"docs/readme.txt": b"x" * 300, "bin/evil.exe": EVIL})
    digest = hashlib.sha256(EVIL).hexdigest()
    reason = engine.check_file(z, {digest}, None, use_cache=False)
    assert reason == "hash match (в архиве: bin/evil.exe)"
    assert engine.check_file(z, {"0" * 64}, None, use_cache=False) is None


def test_yara_on_members_ignores_weak_rules(tmp_path, monkeypatch):
    z = _zip(tmp_path / "pack.zip", {"evil.exe": EVIL})
    strong = SimpleNamespace(rule="Trojan_X", namespace="mal", meta={"score": 90})
    weak = SimpleNamespace(rule="SUSP_Thing", namespace="gen", meta={"score": 40})
    monkeypatch.setattr(archive, "match_details", lambda rules, p, data=None: [weak])
    assert archive.inspect(z, None, object())[0] is None
    monkeypatch.setattr(archive, "match_details", lambda rules, p, data=None: [weak, strong])
    assert archive.inspect(z, None, object())[0] == "YARA: Trojan_X (в архиве: evil.exe)"


def test_pool_checks_members_too(tmp_path):
    from scanner import pool
    z = _zip(tmp_path / "pack.zip", {"evil.exe": EVIL})
    clean = _zip(tmp_path / "clean.zip", {"good.exe": b"MZ" + b"fine" * 100})
    digest = hashlib.sha256(EVIL).hexdigest()
    scan = pool.ScanPool(1)
    try:
        got = {Path(p).name: r for p, r, e in pool.check_files(
            [str(z), str(clean)], {digest}, None, pool=scan)}
    finally:
        scan.shutdown()
    assert got == {"pack.zip": "hash match (в архиве: evil.exe)", "clean.zip": None}
