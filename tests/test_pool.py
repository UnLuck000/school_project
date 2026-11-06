"""Рабочие процессы проверки, выбор ядер P/E, связь библиотек с подписанными программами."""
import hashlib
from types import SimpleNamespace

import pytest

from scanner import cpucores, pool, relations


def test_pool_checks_small_and_split_files(tmp_path, monkeypatch):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"malware sample for test")
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 4096)
    clean = tmp_path / "clean.txt"
    clean.write_text("hello")
    monkeypatch.setattr(pool, "SPLIT_SIZE", 1024)  # big.bin пойдёт двумя задачами
    signatures = {hashlib.sha256(bad.read_bytes()).hexdigest(),
                  hashlib.md5(big.read_bytes()).hexdigest()}
    scan = pool.ScanPool(2)
    try:
        results = {p: (reason, error) for p, reason, error in pool.check_files(
            [bad, big, clean, tmp_path / "missing.bin"], signatures, None, pool=scan)}
    finally:
        scan.shutdown()
    assert results[str(bad)] == ("hash match", None)
    assert results[str(big)] == ("hash match (MD5)", None)
    assert results[str(clean)] == (None, None)
    assert isinstance(results[str(tmp_path / "missing.bin")][1], OSError)


def test_pool_whitelist_and_cancel(tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"sample")
    digest = hashlib.sha256(b"sample").hexdigest()
    scan = pool.ScanPool(1)
    try:
        assert list(pool.check_files([bad], {digest}, None, whitelist={digest}, pool=scan)) == \
            [(str(bad), None, None)]
        import threading
        cancel = threading.Event()
        cancel.set()
        assert list(pool.check_files([bad], {digest}, None, cancel=cancel, pool=scan)) == []
    finally:
        scan.shutdown()


def test_core_classes_and_chooser(monkeypatch):
    classes = cpucores.core_classes()
    assert all(isinstance(c, int) for c in classes.values())
    # гибридный процессор: 0-3 производительные, 4-5 энергоэффективные
    monkeypatch.setattr(cpucores, "core_classes", lambda: {0: 1, 1: 1, 2: 1, 3: 1, 4: 0, 5: 0})
    assert cpucores.performance_cpus() == [0, 1, 2, 3]
    assert cpucores.efficiency_cpus() == [4, 5]
    chooser = cpucores.CoreChooser()
    loads = iter([[90, 90, 90, 90, 10, 10]] * 3 + [[5, 5, 5, 5, 5, 5]])
    monkeypatch.setattr(cpucores.psutil, "cpu_percent", lambda percpu=True: next(loads))
    assert not chooser.update([])           # один замер — ещё не решение
    assert chooser.update([])               # нагрузка держится: на E-ядра
    assert chooser.mode == cpucores.MODE_EFFICIENT and chooser.cpus() == [4, 5]
    assert not chooser.update([])
    assert chooser.update([])               # P-ядра освободились
    assert chooser.cpus() is None


def test_weak_match():
    def m(rule, namespace="1_x", **meta):
        return SimpleNamespace(rule=rule, namespace=namespace, meta=meta)
    assert relations.weak_match(m("WinDivert_Driver", "2056_gen_pua", score=40))
    assert relations.weak_match(m("HKTL_Mimikatz", score=80))
    assert not relations.weak_match(m("Win32_Ransomware_Lockbit", score=90))
    assert not relations.weak_match(m("Windows_Trojan_Emotet", threat_name="Windows.Trojan.Emotet"))


def test_signed_partner(tmp_path, monkeypatch):
    lib = tmp_path / "Helper.dll"
    lib.write_bytes(b"MZ" + "driver: MyDrv64.sys".encode("utf-16-le"))
    (tmp_path / "MyDrv64.sys").write_bytes(b"MZ driver")
    (tmp_path / "Other.dll").write_bytes(b"MZ other")
    signed = {"MyDrv64.sys"}
    monkeypatch.setattr(relations, "_is_signed", lambda p: p.name in signed)
    assert relations.signed_partner(lib) == ("MyDrv64.sys", "ссылается на MyDrv64.sys")
    signed.clear()
    assert relations.signed_partner(lib) is None
    # обратная связь: подписанная программа упоминает библиотеку
    (tmp_path / "app.exe").write_bytes(b"MZ ... LoadLibrary helper.dll")
    signed.add("app.exe")
    assert relations.signed_partner(lib) == ("app.exe", "app.exe ссылается на этот файл")


def test_engine_uses_partner_only_for_weak_hits(tmp_path, monkeypatch):
    from scanner import engine
    from scanner.signature import SignatureInfo
    target = tmp_path / "lib.dll"
    target.write_bytes(b"MZ")
    weak = SimpleNamespace(rule="X_PUA", namespace="1_gen_pua", meta={"score": 40})
    strong = SimpleNamespace(rule="Trojan_X", namespace="1_mal", meta={"score": 90})
    monkeypatch.setattr(engine, "inspect_signature", lambda p: SignatureInfo("unsigned"))
    monkeypatch.setattr(engine, "signed_partner", lambda p: ("app.exe", "app.exe импортирует этот файл"))
    monkeypatch.setattr(engine, "match_details", lambda rules, p: [weak])
    assert engine.analyze(target, object(), heuristics=False) is None
    monkeypatch.setattr(engine, "match_details", lambda rules, p: [weak, strong])
    assert engine.analyze(target, object(), heuristics=False) == "YARA: X_PUA, Trojan_X"


@pytest.mark.parametrize("value", [b"", b"abc" * 1000])
def test_frames_roundtrip(value):
    import io
    from scanner.worker import read_frame, write_frame
    stream = io.BytesIO()
    write_frame(stream, (1, "hash", value, {}))
    stream.seek(0)
    assert read_frame(stream) == (1, "hash", value, {})
    assert read_frame(stream) is None
