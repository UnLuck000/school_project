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