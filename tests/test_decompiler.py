"""Вкладка «Декомпилятор»: разбор PyInstaller, ZIP, лимиты, уровни угроз, код .pyc."""
import importlib.util
import io
import marshal
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from analyzer import decompile, unpack

MAGIC = importlib.util.MAGIC_NUMBER


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    monkeypatch.setattr(unpack, "UNPACK_DIR", tmp_path / "unpack")


def _pyinstaller_blob() -> bytes:
    """CArchive как в PyInstaller 6: скрипт (s) и PYZ с одним модулем."""
    script = marshal.dumps(compile("print('привет из main')\nSECRET = 'c2.example.org'\n",
                                   "main.py", "exec"))
    module = zlib.compress(marshal.dumps(compile("def evil():\n    return 42\n", "pkg/mod.py",
                                                 "exec")))
    # PYZ: «PYZ\0», магическое число .pyc, смещение TOC; модуль сразу за заголовком (12 байт)
    toc = marshal.dumps([("pkg.mod", (0, 12, len(module)))])
    pyz = b"PYZ\x00" + MAGIC + struct.pack("!i", 12 + len(module)) + module + toc
    data = b""
    entries = b""
    for name, payload, code, compress in (("main", script, b"s", 1), ("PYZ.pyz", pyz, b"z", 0)):
        stored = zlib.compress(payload) if compress else payload
        raw_name = name.encode() + b"\x00"
        raw_name += b"\x00" * (-(18 + len(raw_name)) % 16)
        entries += struct.pack("!IIIIBc", 18 + len(raw_name), len(data), len(stored),
                               len(payload), compress, code) + raw_name
        data += stored
    package_len = len(data) + len(entries) + unpack.PYI_COOKIE.size
    cookie = unpack.PYI_COOKIE.pack(unpack.PYI_MAGIC, package_len, len(data), len(entries),
                                    312, b"python312.dll")
    return b"junk-before-archive" + data + entries + cookie


def test_pyinstaller_archive_unpacked(tmp_path):
    root = unpack.Node("app.exe", "root")
    budget = unpack.Budget()
    unpack._explore_pyinstaller(root, _pyinstaller_blob(), tmp_path, budget, 0)
    pyi = root.children[0]
    assert pyi.kind == "pyinstaller" and "3.12" in pyi.name
    names = [n.name for n in pyi.walk()]
    assert "main.pyc" in names and "mod.pyc" in names
    main = next(n for n in pyi.walk() if n.name == "main.pyc")
    head = Path(main.path).read_bytes()[:16]
    assert head[:4] == MAGIC and head[4:] == b"\x00" * 12     # заголовок .pyc восстановлен
    assert main.lang == "python" and "точка входа" in unpack.PYI_TYPES["s"]


@pytest.mark.skipif(unpack.tool("pycdc", "pycdc.exe") is None, reason="нет tools/bin/pycdc")
def test_pyc_decompiled(tmp_path):
    root = unpack.Node("app.exe", "root")
    unpack._explore_pyinstaller(root, _pyinstaller_blob(), tmp_path, unpack.Budget(), 0)
    main = next(n for n in root.walk() if n.name == "main.pyc")
    text, lang, _ = decompile.decompile(main)
    assert "c2.example.org" in text and lang == "py"


def test_nested_zip_tree(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("com/x/Payload.class", b"\xca\xfe\xba\xbe" + b"\x00" * 20)
    outer = tmp_path / "bundle.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("lib/inner.jar", inner.getvalue())
        z.writestr("readme.txt", "hello")
    root = unpack.unpack(outer)
    cls = next(n for n in root.walk() if n.name == "Payload.class")
    assert cls.kind == "class" and cls.lang == "java" and Path(cls.path).is_file()
    readme = next(n for n in root.walk() if n.name == "readme.txt")
    assert "hello" in decompile.decompile(readme)[0]          # текст показывается целиком


def test_budget_limits_files(tmp_path, monkeypatch):
    monkeypatch.setattr(unpack, "MAX_FILES", 3)
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for i in range(10):
            z.writestr(f"f{i}.txt", "x")
    root = unpack.unpack(archive)
    assert len(root.files()) == 3
    assert any("ограничен" in n.name for n in root.children)


def test_threat_rolls_up_to_folders():
    root = unpack.Node("a.exe", "root", "a.exe")
    folder = root.add(unpack.Node("lib", "folder"))
    bad = folder.add(unpack.Node("x.dll", "file", "x.dll", level="threat", verdict="Угроза"))
    folder.add(unpack.Node("y.dll", "file", "y.dll", level="clean"))
    unpack._roll_up(root)
    assert folder.level == "threat" and bad.level == "threat"


def test_rizin_noise_removed():
    from analyzer import rizin
    raw = ("\r\n// WARNING: [rz-ghidra] Detected overlap for variable var_8h\r\n"
           "// WARNING: Variable defined which should be unmapped: var_10h\r\n\r\n\r\n"
           "// WARNING: Removing unreachable block\r\nvoid main(void)\r\n{\r\n}\r\n")
    text, removed = rizin.clean(raw)
    assert removed == 2 and "Detected overlap" not in text
    assert "Removing unreachable block" in text and "\r" not in text   # важное остаётся


@pytest.mark.skipif(not __import__("analyzer.rizin", fromlist=["available"]).available()
                    or unpack.tool("pycdc", "pycdas.exe") is None,
                    reason="нет tools/bin/rizin или образца")
def test_native_functions_and_code():
    from analyzer import rizin
    sample = unpack.tool("pycdc", "pycdas.exe")
    node = unpack.Node("pycdas.exe", "pe", str(sample), lang="native")
    try:
        nodes, summary = decompile.native_functions(node)
        assert len(nodes) > 50 and nodes[0].kind == "function"
        main = next(n for n in nodes if n.name.startswith("main"))
        assert nodes.index(main) < 2                       # точка входа и main — первыми
        text, lang, _ = decompile.decompile(main)
        assert lang == "c" and "main(" in text and "{" in text
    finally:
        rizin.close_all()


def test_unpack_dirs_trimmed(tmp_path, monkeypatch):
    monkeypatch.setattr(unpack, "KEEP_RUNS", 2)
    files = []
    for i in range(4):
        f = tmp_path / f"f{i}.bin"
        f.write_bytes(bytes([i]) * 10)
        files.append(f)
        unpack.workdir_for(f)
    assert len(list(unpack.UNPACK_DIR.iterdir())) == 2


# ---------- чужой файл не роняет и не вешает разбор ----------
def test_toc_reader_matches_marshal():
    """Свой разбор оглавления PYZ даёт то же, что marshal, но без marshal.loads."""
    toc = [("pkg", (1, 100, 20)), ("pkg.mod", (0, 120, 30)), ("pkg.mod2", (0, 150, 30)),
           ("a" * 300, (3, 2 ** 31 - 1, 7))]
    for version in (2, 3, 4):
        raw = marshal.dumps(toc, version)
        assert unpack.read_toc(raw) == sorted((n, t, o, ln) for n, (t, o, ln) in toc)
    old = marshal.dumps({"mod": (False, 12, 34), b"pkg": (True, 50, 60)}, 2)  # старый вид
    assert unpack.read_toc(old) == [("mod", 0, 12, 34), ("pkg", 1, 50, 60)]


@pytest.mark.parametrize("raw", [
    b"", b"[", b"[\xff\xff\xff\x7f", b"[\x01\x00\x00\x00c", b"r\x05\x00\x00\x00",
    marshal.dumps([("m", ("x", 1, 2))]), marshal.dumps([("m", (0, -5, 2))]),
    marshal.dumps([1, 2, 3]), marshal.dumps("строка"), b"[" * 64,
    marshal.dumps([("m", (0, 1.5, 2))]),
])
def test_toc_reader_rejects_garbage(raw):
    with pytest.raises(ValueError):
        unpack.read_toc(raw)


def test_zlib_bomb_is_limited(monkeypatch):
    monkeypatch.setattr(unpack, "MAX_ONE", 1024 * 1024)
    bomb = zlib.compress(b"\0" * (64 * 1024 * 1024), 9)
    assert len(bomb) < 100_000
    with pytest.raises(unpack.TooBig):
        unpack._inflate(bomb, unpack.MAX_ONE)
    assert unpack._inflate(zlib.compress(b"abc")) == b"abc"
    with pytest.raises(zlib.error):
        unpack._inflate(zlib.compress(b"abc" * 100)[:-4])


def test_device_names_and_deep_folders(tmp_path):
    assert unpack._safe("CON") == "_CON" and unpack._safe("com1.pyc") == "_com1.pyc"
    assert unpack._safe("console.txt") == "console.txt"
    archive = tmp_path / "deep.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("/".join(["d"] * 3000) + "/file.txt", "x")
        z.writestr("NUL", "y")
    root = unpack.unpack(archive)
    files = root.files()                       # обход дерева не упирается в предел рекурсии
    assert {Path(n.path).name for n in files} == {"file.txt", "_NUL"}
    depth = max(len(Path(n.path).relative_to(unpack.UNPACK_DIR).parts) for n in files)
    assert depth < 3000


def test_pyinstaller_garbage_toc_does_not_hang():
    """Оглавление из записей «длиной в байт» раньше обходилось по байту на шаг."""
    toc = struct.pack("!IIIIBc", 1, 0, 0, 0, 0, b"x") * 4
    blob = toc + unpack.PYI_COOKIE.pack(unpack.PYI_MAGIC, len(toc) + unpack.PYI_COOKIE.size,
                                        0, len(toc), 312, b"python312.dll")
    node = unpack.Node("x.exe", "pe")
    unpack._explore_pyinstaller(node, blob, Path("."), unpack.Budget(), 0)
    assert node.children[0].kind == "pyinstaller" and not node.children[0].children


def test_rizin_path_with_space(tmp_path, monkeypatch):
    """Установленная программа лежит в «C:/Program Files»: путь к описаниям процессоров
    передаётся в кавычках, иначе rizin обрезал его по пробелу и код C не получался."""
    from analyzer import rizin
    assert rizin.quote("C:/Program Files/x") == "'C:/Program Files/x'"
    assert rizin.quote("C:/O'Brien/x") == '"C:/O\'Brien/x"'
    if not rizin.available():
        pytest.skip("rizin не установлен (tools/bin/rizin)")
    import _winapi
    link = tmp_path / "with space" / "sleigh"
    link.parent.mkdir()
    _winapi.CreateJunction(str(rizin.SLEIGH), str(link))
    monkeypatch.setattr(rizin, "SLEIGH", link)
    import os
    s = rizin.RizinSession(Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe")
    try:
        s.cmd("af @ entry0")
        code, _ = s.decompile(int(s.cmd("s entry0; s").strip(), 16))
    finally:
        s.close()
    assert "{" in code and "}" in code
