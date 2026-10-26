import hashlib
import sys
from pathlib import Path

import pytest

from analyzer.report import INTERESTING, build_report, detect_type


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_clean_text_file(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello world, visit https://example.com now")
    report = build_report(f, set(), None, set())
    assert report.sha256 == _sha256(f)
    assert report.size == f.stat().st_size
    assert report.type_key == "text"
    assert report.level == "clean"
    assert any(INTERESTING.search(s) for _, _, s in report.strings)


def test_hash_match_is_threat(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"some bytes here")
    report = build_report(f, {_sha256(f)}, None, set())
    assert report.level == "threat"


def test_whitelist_wins_over_hash(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"some bytes here")
    digest = _sha256(f)
    report = build_report(f, {digest}, None, {digest})
    assert report.level == "info"


def test_pe_disguised_as_image(tmp_path):
    f = tmp_path / "photo.jpg"
    f.write_bytes(b"MZ" + b"\x00" * 200)
    report = build_report(f, set(), None, set())
    assert report.type_key == "pe"
    assert report.level == "suspicious"


def test_double_extension(tmp_path):
    f = tmp_path / "invoice.pdf.exe"
    f.write_bytes(b"MZ" + b"\x00" * 200)
    report = build_report(f, set(), None, set())
    assert report.level == "suspicious"
    assert any("Двойное расширение" in n for n in report.notes)


def test_detect_type():
    assert detect_type(b"%PDF-1.7", ".pdf")[0] == "pdf"
    assert detect_type(b"\x89PNG\r\n\x1a\n....", ".png")[0] == "png"
    assert detect_type(b"echo hi", ".bat")[0] == "script"


def test_real_exe_has_pe_details():
    report = build_report(Path(sys.executable), set(), None, set())
    if report.type_key != "pe":
        pytest.skip("интерпретатор не PE-файл")
    assert report.pe is not None
    assert report.pe.sections