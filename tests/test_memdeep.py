import os
import sys

import pytest

from processmanager import memdeep as m


def _region(protect, kind, size=4096, pe=False, base=0x10000):
    return m.Region(base, base, size, m.MEM_COMMIT, protect, protect, kind, has_pe_header=pe)


def test_protect_text():
    assert m.protect_text(m.PAGE_EXECUTE_READWRITE) == "RWX"
    assert m.protect_text(m.PAGE_READONLY | m.PAGE_GUARD) == "R-- guard"


def test_assess_marks_injection_signs():
    report = m.MemoryReport(1, "sample.exe", regions=[
        _region(m.PAGE_EXECUTE_READWRITE, m.MEM_PRIVATE, size=1 << 20),     # большой RWX
        _region(m.PAGE_EXECUTE_READWRITE, m.MEM_PRIVATE),                   # переходник 4 КБ
        _region(m.PAGE_EXECUTE_READ, m.MEM_PRIVATE, pe=True),               # MZ в приватной
        _region(m.PAGE_READWRITE, m.MEM_PRIVATE),                           # данные
    ])
    m._assess(report)
    levels = [r.level for r in report.regions]
    assert levels == ["suspicious", "check", "suspicious", "normal"]


def test_jit_process_is_softened():
    report = m.MemoryReport(1, "app.exe", regions=[
        _region(m.PAGE_EXECUTE_READWRITE, m.MEM_PRIVATE, size=1 << 20)],
        modules=[m.Module(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll", 1, 1)])
    m._assess(report)
    assert report.regions[0].level == "check"


@pytest.mark.skipif(sys.platform != "win32", reason="нужен Windows")
def test_own_process_map():
    report = m.inspect_process(os.getpid(), "python.exe")
    assert not report.error
    assert any(r.executable for r in report.regions)
    assert any(mod.path.lower().endswith("python.exe") for mod in report.modules)
