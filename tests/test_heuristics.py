import sys
from pathlib import Path

import pytest

from scanner.features import entropy
from scanner.heuristics import (
    HEURISTIC_THRESHOLD, Finding, analyze_pe, api_findings, combine,
)


def test_entropy():
    assert entropy(b"") == 0.0
    assert entropy(b"\x00" * 1000) == 0.0
    assert abs(entropy(bytes(range(256)) * 4) - 8.0) < 1e-9


def test_api_group_needs_all_parts():
    full = {"virtualallocex", "writeprocessmemory", "createremotethread"}
    assert [f.points for f in api_findings(full)] == [4]
    assert api_findings({"virtualallocex", "writeprocessmemory"}) == []


def test_packing_alone_is_not_enough():
    packed = [Finding("pack", "x", 3)] * 4  # 12 баллов, но потолок 4
    assert combine(packed) < HEURISTIC_THRESHOLD


def test_packing_plus_injection_is_flagged():
    findings = [Finding("pack", "x", 3)] * 4 + [Finding("api", "y", 4)]
    assert combine(findings) >= HEURISTIC_THRESHOLD


def test_not_a_pe(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    assert analyze_pe(f).is_pe is False


def test_real_executable_is_not_flagged():
    report = analyze_pe(Path(sys.executable))
    if not report.is_pe:
        pytest.skip("интерпретатор не PE-файл")
    assert report.score < HEURISTIC_THRESHOLD


def test_garbage_import_name_does_not_blind_heuristics(monkeypatch):
    """Байт не из UTF-8 в имени функции ронял нативный разбор, и файл считался «не
    программой»: эвристика молчала. Теперь имя пропускается, а при любом сбое нативного
    разбора файл разбирает pefile."""
    import os
    from pathlib import Path

    from scanner import heuristics
    data = bytearray((Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe").read_bytes())
    good = heuristics.pe_info(Path("x"), bytes(data))
    name = good["imports"][0].encode()
    pos = bytes(data).lower().find(name + bytes(1))
    assert pos > 0
    data[pos] = 0xFF
    report = heuristics.analyze_pe(Path("x"), bytes(data))
    assert report.is_pe
    info = heuristics.pe_info(Path("x"), bytes(data))
    assert info["total_imports"] >= good["total_imports"] - 1 and name.decode() not in \
        info["imports"]

    def broken(path, data=None):
        raise UnicodeDecodeError("utf-8", bytes(1), 0, 1, "сбой нативного разбора")
    monkeypatch.setattr(heuristics, "_native_info", broken)
    assert heuristics.analyze_pe(Path("x"), bytes(data)).is_pe
