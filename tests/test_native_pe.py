"""Разбор PE на C++ совпадает с pefile; отбор правил YARA для Windows."""
import os
import sys
from pathlib import Path

import pytest

from scanner import heuristics as h
from scanner import yara_engine as ye

SYSTEM32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
native = pytest.mark.skipif(h.pe_backend() != "C++", reason="нативный модуль не собран")


@native
@pytest.mark.skipif(sys.platform != "win32", reason="нужны файлы Windows")
def test_native_matches_pefile():
    files = sorted(p for p in SYSTEM32.iterdir()
                   if p.suffix.lower() in (".exe", ".dll") and p.is_file())[:150]
    assert files
    for f in files:
        a, b = h.report_from_info(h._native_info(f)), h.report_from_info(h._pefile_info(f))
        assert (a.is_pe, sorted(a.findings), a.dotnet) == (b.is_pe, sorted(b.findings), b.dotnet), f


@native
def test_native_rejects_garbage(tmp_path):
    for name, data in (("empty.exe", b""), ("text.exe", b"hello" * 100),
                       ("mz_only.exe", b"MZ" + b"\0" * 200), ("broken.exe", b"MZ" + os.urandom(4000))):
        f = tmp_path / name
        f.write_bytes(data)
        assert h._native_info(f) is None or isinstance(h._native_info(f), dict)
        assert h.analyze_pe(f).score >= 0


def test_filter_rules_drops_other_os_and_memory_only():
    text = '''
rule Win_Good { strings: $a = "x" condition: $a }
rule Linux_Bad { strings: $a = "y" condition: $a }
rule Elastic_Mac { meta: os = "macos" strings: $a = "z" condition: $a }
rule Elf_Only { strings: $a = "q" condition: uint32(0) == 0x464c457f and $a }
rule Pe_Or_Other { strings: $a = "w" condition: (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and $a }
rule Mem { meta: scan_context = "memory" strings: $a = "m" condition: $a }
'''
    kept, dropped = ye.filter_rules(text, "rules.yar", "file", set())
    names = {m.group(1) for m in ye.RULE_HEAD_RE.finditer(kept)}
    assert names == {"Win_Good", "Pe_Or_Other"}
    assert sorted(dropped["other_os"]) == ["Elastic_Mac", "Elf_Only", "Linux_Bad"]
    assert dropped["memory_only"] == ["Mem"]
    assert kept.count("\n") == text.count("\n")  # номера строк для ошибок не сдвинулись
    kept, _ = ye.filter_rules(text, "rules.yar", "memory", set())
    assert "rule Mem" in kept
    _, dropped = ye.filter_rules(text, "Linux_Trojan_Mirai.yar", "file", set())
    assert len(dropped["other_os"]) == 6  # весь файл для Linux


def test_filter_rules_duplicates_and_references():
    seen: set[str] = set()
    ye.filter_rules('rule A { strings: $a = "dup" condition: $a }', "one.yar", "file", seen)
    text = ('rule B { strings: $a = "dup" condition: $a }\n'
            'rule C { strings: $a = "dup" condition: $a }\nrule D { condition: C }\n')
    kept, dropped = ye.filter_rules(text, "two.yar", "file", seen)
    assert dropped == {"duplicate": ["B"]}   # C тоже дубль, но на него ссылается D
    assert "rule C" in kept


def test_load_rules_with_filter(tmp_path):
    (tmp_path / "win.yar").write_text('rule W { strings: $a = "win" condition: $a }\n'
                                      'rule Linux_X { strings: $a = "lin" condition: $a }\n'
                                      'rule Uses { condition: Linux_X }\n')
    rules, errors = ye.load_rules(tmp_path, use_cache=False)
    assert not errors
    assert {r.identifier for r in rules} == {"W"}  # Uses ссылался на убранное правило


def test_pe_info_from_bytes_matches_file():
    """Одно чтение файла: разбор PE по байтам совпадает с разбором по пути."""
    import os
    from pathlib import Path
    from scanner import heuristics
    folder = Path(os.environ["SystemRoot"]) / "System32"
    for name in ("notepad.exe", "kernel32.dll", "cmd.exe"):
        path = folder / name
        data = path.read_bytes()
        assert heuristics.pe_info(path, data) == heuristics.pe_info(path)
        assert heuristics._pefile_info(path, data) == heuristics._pefile_info(path)
    assert heuristics.pe_info(Path("x.txt"), b"not a pe file at all" * 10) is None
