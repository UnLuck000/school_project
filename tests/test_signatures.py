import os
import pytest

from scanner import engine, features
from scanner.heuristics import Finding, PEReport
from scanner.signature import VALID, SignatureInfo, describe, verify_signature


def test_text_file_is_not_validly_signed(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    assert verify_signature(f) != VALID


def test_valid_signature_suppresses_heuristic(tmp_path, monkeypatch):
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ")
    monkeypatch.setattr(engine, "analyze_pe",
                        lambda p, data=None: PEReport(is_pe=True, findings=[Finding("api", "x", 9)]))
    monkeypatch.setattr(engine, "inspect_signature", lambda p: SignatureInfo("valid"))
    assert engine.check_file(f, set()) is None
    monkeypatch.setattr(engine, "inspect_signature", lambda p: SignatureInfo("unsigned"))
    assert engine.check_file(f, set()).startswith("Heuristic")


def test_native_matches_python():
    if features._native is None:
        pytest.skip("C++-модуль не собран")
    data = os.urandom(5000) + b"A" * 3000
    assert abs(features._native.entropy(data) - features._py_entropy(data)) < 1e-9


def test_describe():
    assert describe(SignatureInfo("valid", "ACME", "catalog")) == "Действительна (ACME), каталог"
    assert describe(SignatureInfo("unsigned")) == "Нет подписи"
    assert describe(SignatureInfo("unavailable")) == ""
