"""AMSI: разбор сообщений провайдера, проверка содержимого и сквозной путь
«провайдер (native/amsi, самопроверка) → канал → AmsiServer» без регистрации в Windows."""
import os
import subprocess
import sys
import uuid

import pytest

from scanner import amsi

# Образец обхода AMSI собирается только в памяти и НИКОГДА не пишется на диск: Defender
# находит его в файле (Trojan:PowerShell/BypassAMSI) и убирает в карантин — 12.11.2026 так и
# случилось. Сквозной путь проверяется безобидной меткой, угроза — по её хэшу в базе.
BYPASS = ("[Ref].Assembly.GetType('System.Management.Automation." + amsi.BYPASS_PARTS[1]
          + "').GetField('" + amsi.BYPASS_PARTS[0] + "','NonPublic,Static')")
MARKER = "Write-Host SBIT-AMSI-SELFTEST"
SELFTEST = amsi.BIN_DIR / "amsi_selftest64.exe"


def _request(content: bytes, app: str = "PowerShell_C:\\x\\powershell.exe_10.0",
             name: str = "a.ps1") -> bytes:
    a, n = app.encode("utf-16-le"), name.encode("utf-16-le")
    head = b"".join(x.to_bytes(4, "little") for x in
                    (amsi.MAGIC_REQUEST, 1234, 1, len(a), len(n), len(content)))
    return head + len(content).to_bytes(8, "little") + a + n + content


def test_parse_request_roundtrip():
    pid, flags, app, name, content, full = amsi.parse_request(_request(b"Get-Date"))
    assert (pid, flags, name, content, full) == (1234, 1, "a.ps1", b"Get-Date", 8)
    assert app.startswith("PowerShell")
    assert amsi.parse_request(_request(b"x")[:-1]) is None           # длина не сходится
    assert amsi.parse_request(b"\0" * 40) is None                    # не то магическое число
    assert amsi.reply(True)[4:] == b"\x01\0\0\0"


def test_bypass_is_threat_in_utf16_and_utf8():
    for data in (BYPASS.encode("utf-16-le"), BYPASS.encode()):
        v = amsi.scan_content(data)
        assert v.level == "threat" and "AMSI" in v.reason
    assert amsi.scan_content("Get-ChildItem C:\\".encode("utf-16-le")).level == "clean"
    assert amsi.scan_content(b"").level == "clean"


def test_hash_and_yara(tmp_path):
    import hashlib

    import yara
    data = "Write-Host EvilMarker42".encode("utf-16-le")
    assert amsi.scan_content(data, signatures={hashlib.sha256(data).hexdigest()}).level == "threat"
    rules = yara.compile(source=(
        'rule Evil_Marker { strings: $a = "EvilMarker42" condition: $a }\n'
        'rule PUA_Marker { meta: category = "PUA" strings: $a = "PuaMarker" condition: $a }'))
    v = amsi.scan_content(data, rules=rules)  # строка в ASCII — находится через текст UTF-8
    assert v.level == "threat" and "Evil_Marker" in v.reason
    assert amsi.scan_content(b"PuaMarker", rules=rules).level == "suspicious"


@pytest.mark.skipif(not SELFTEST.is_file() or sys.platform != "win32",
                    reason="нет native/amsi/bin/amsi_selftest64.exe (python native/amsi/build.py --selftest)")
@pytest.mark.parametrize("mode", ["address", "read"])
def test_provider_end_to_end(tmp_path, mode):
    import hashlib
    pipe = rf"\\.\pipe\sbit-amsi-test-{uuid.uuid4().hex[:8]}"
    events = []
    server = amsi.AmsiServer(events.append, pipe_name=pipe, skip_own=False)
    marker = MARKER.encode("utf-16-le")
    server._bases = ({hashlib.sha256(marker).hexdigest()}, None)  # метка — «угроза» по хэшу
    assert server.start(), server.error
    me = os.path.abspath(sys.executable)
    content = tmp_path / "content.bin"

    def run(text: str, allowed: str = me) -> int:
        content.write_bytes(text.encode("utf-16-le"))
        return subprocess.run([str(SELFTEST), pipe, allowed, str(content),
                               "PowerShell_selftest", mode], capture_output=True,
                              timeout=30).returncode

    try:
        assert run(MARKER) == 2                       # угроза: DETECTED
        assert events and events[-1]["blocked"] and events[-1]["app"] == "PowerShell_selftest"
        assert MARKER in events[-1]["excerpt"] and "хэш" in events[-1]["reason"]
        assert run("Get-Process | Select -First 3") == 0
        scanned = server.scanned
        # сервер — не та программа, что разрешена: содержимое не отправляется, ответ «чисто»
        assert run(MARKER, allowed=r"C:\nowhere\other.exe") == 0
        assert server.scanned == scanned
    finally:
        server.stop()
    # программа не запущена (канала нет) — «чисто», без зависания
    assert run(MARKER) == 0


def test_second_server_on_same_pipe_refused():
    if sys.platform != "win32":
        pytest.skip("Windows")
    pipe = rf"\\.\pipe\sbit-amsi-test-{uuid.uuid4().hex[:8]}"
    first = amsi.AmsiServer(pipe_name=pipe)
    assert first.start()
    try:
        second = amsi.AmsiServer(pipe_name=pipe)
        assert not second.start() and "канал" in second.error
    finally:
        first.stop()


def test_bypass_split_by_concatenation_is_threat():
    """Обход, разрезанный склейкой строк и обратными кавычками, — тоже угроза."""
    name = amsi.BYPASS_PARTS[0]
    pieces = "'" + name[:2] + "'+'" + name[2:6] + "'" + " + '" + name[6:8] + "`" + name[8:] + "'"
    v = amsi.scan_content(("$x = " + pieces).encode("utf-16-le"))
    assert v.level == "threat"
    assert amsi.squash("'Get' + '-Date'") == "Get-Date"
    assert amsi.scan_content("'Get' + '-ChildItem'".encode("utf-16-le")).level == "clean"


def test_trimmed_flag_reported():
    events = []
    server = amsi.AmsiServer(events.append, skip_own=False)
    server._bases = (None, None)
    head = amsi.BYPASS_PARTS[0].encode()
    msg = bytearray(_request(head))
    msg[8:12] = (2).to_bytes(4, "little")  # отправлены только начало и конец
    assert server._handle(bytes(msg), 4321) is True
    assert events[-1]["trimmed"] and events[-1]["pid"] == 4321


def test_sddl_without_admin_grants_own_account(monkeypatch):
    monkeypatch.setattr(amsi, "_user_sid", lambda: "S-1-5-21-1-2-3-1001")
    assert amsi.pipe_sddl(True) == amsi.PIPE_SDDL
    assert amsi.pipe_sddl(False).endswith("(A;;GA;;;S-1-5-21-1-2-3-1001)")
    if sys.platform == "win32":
        monkeypatch.undo()
        assert amsi._user_sid().startswith("S-1-5-")


def test_planted_library_is_replaced(tmp_path):
    src = tmp_path / "src.dll"
    src.write_bytes(b"MZ genuine provider")
    folder = tmp_path / "amsi"
    folder.mkdir()
    import hashlib
    name = f"sbit_amsi64-{hashlib.sha256(src.read_bytes()).hexdigest()[:12]}.dll"
    (folder / name).write_bytes(b"MZ planted")             # подложили заранее под тем же именем
    placed = amsi.place(folder, {64: src})
    assert (folder / name).read_bytes() == b"MZ genuine provider"
    assert placed == {64: str(folder / name)}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows")
def test_idle_clients_do_not_stall_server(monkeypatch):
    """Подключения без данных закрываются через READ_TIMEOUT, лишние от одного процесса —
    сразу: сервер продолжает отвечать (раньше четыре таких подключения его «усыпляли»)."""
    import ctypes
    import time
    from ctypes import wintypes
    monkeypatch.setattr(amsi, "READ_TIMEOUT", 0.5)
    pipe = rf"\\.\pipe\sbit-amsi-test-{uuid.uuid4().hex[:8]}"
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                              ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    access = 0x80000000 | 0x2 | 0x100      # как у провайдера: GENERIC_READ | запись данных
    server = amsi.AmsiServer(pipe_name=pipe, skip_own=False)
    server._bases = (None, None)
    assert server.start(), server.error
    held = []
    try:
        for _ in range(amsi.WORKERS + 2):
            h = k.CreateFileW(pipe, access, 0, None, 3, 0, None)
            if h and h != amsi.INVALID_HANDLE:
                held.append(h)
        assert held, f"провайдер не открыл канал: ошибка {ctypes.get_last_error()}"
        time.sleep(1.5)
        assert server.dropped >= len(held)  # лишние — сразу, молчащие — по таймауту
        h = k.CreateFileW(pipe, access, 0, None, 3, 0, None)
        assert h and h != amsi.INVALID_HANDLE, "сервер не освободил экземпляры канала"
        k.CloseHandle(h)
    finally:
        for h in held:
            k.CloseHandle(h)
        server.stop()

