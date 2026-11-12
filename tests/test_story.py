"""Сводка по процессу: кто запустил → что запустил → что создал → куда подключался."""
from processmanager import story
from processmanager.story import Story, render


def _filled() -> Story:
    s = Story()
    s.sources |= {"launch", "files", "net"}
    s.known(100, 0, "explorer.exe")                       # шёл до нас
    s.started(200, 100, r"C:\Users\u\Downloads\invoice.exe", ["invoice.exe", "/q"], when=10)
    s.started(300, 200, r"C:\Windows\System32\cmd.exe", "cmd /c drop.bat", when=11)
    s.file_written(200, r"C:\Users\u\AppData\Roaming\upd.exe", when=12)
    s.file_written(200, r"C:\Users\u\AppData\Roaming\upd.exe", when=13)
    s.file_written(200, r"C:\Users\u\AppData\Roaming\notes.txt", when=13)  # не программа
    s.contacted(200, "evil.example", "dns", "203.0.113.5", when=14)
    s.contacted(200, "203.0.113.5:443", "tcp", "evil.example", when=15)
    s.contacted(200, "203.0.113.5:443", "tcp", when=16)
    return s


def test_records_and_chain():
    s = _filled()
    rec = s.record(200)
    assert rec.name == "invoice.exe" and rec.ppid == 100 and rec.children == [300]
    assert list(rec.files) == [r"C:\Users\u\AppData\Roaming\upd.exe"]   # .txt не запоминается
    assert rec.files[r"C:\Users\u\AppData\Roaming\upd.exe"] == (12, 2)
    assert rec.targets["203.0.113.5:443"].count == 2
    assert s.chain(300) == [(200, "invoice.exe"), (100, "explorer.exe")]
    # родитель известен только из снимка процессов
    assert s.chain(100, live={100: (50, "explorer.exe"), 50: (0, "userinit.exe")}) == \
        [(50, "userinit.exe")]


def test_pid_reuse_replaces_record():
    s = _filled()
    s.started(200, 7, r"C:\Windows\notepad.exe", when=20)
    rec = s.record(200)
    assert rec.name == "notepad.exe" and not rec.files and not rec.targets


def test_identify_fills_late_details():
    s = Story()
    s.started(5, 1, "", "", name="x.exe")
    s.identify(5, r"C:\x\x.exe", ["x.exe", "-a"])
    rec = s.record(5)
    assert rec.exe == r"C:\x\x.exe" and rec.cmdline == "x.exe -a"


def test_render_sections():
    text = render(200, _filled(), live={}, live_conns=[])
    assert "invoice.exe (PID 200)" in text
    assert "Кто запустил: explorer.exe (PID 100)" in text
    assert "cmd.exe (PID 300)" in text and "drop.bat" in text
    assert r"upd.exe (×2) — файла уже нет" in text
    assert "DNS evil.example (203.0.113.5)" in text and "TCP 203.0.113.5:443" in text


def test_render_explains_disabled_sources():
    s = Story()
    text = render(42, s, live={42: (1, "a.exe")}, live_conns=["198.51.100.1:80"])
    assert "контроль запуска выключен" in text
    assert "защита от стилеров с правами администратора" in text
    assert "Открыто сейчас: 198.51.100.1:80" in text


def test_limits():
    s = Story()
    s.sources.add("files")
    for i in range(story.MAX_FILES + 50):
        s.file_written(1, rf"C:\t\f{i}.exe")
    assert len(s.record(1).files) == story.MAX_FILES


def test_stealerguard_feeds_created_files(monkeypatch):
    """Событие Kernel-File Create: тип открытия — старший байт байтов 20–23, имя с 32-го."""
    from toolbox import stealerguard
    s = Story()
    monkeypatch.setattr(story, "STORY", s)
    monkeypatch.setattr("processmanager.etw.kernel_path", lambda p: p.replace(
        r"\Device\HarddiskVolume3", "C:"))
    guard = stealerguard.StealerGuard(lambda info: None)

    def event(disposition: int, name: str) -> bytes:
        head = bytearray(32)
        head[20:24] = (disposition << 24).to_bytes(4, "little")
        return bytes(head) + (name + "\0").encode("utf-16-le")

    guard._on_etw(12, 900, event(2, r"\Device\HarddiskVolume3\Temp\a.exe"))     # создан
    guard._on_etw(12, 900, event(1, r"\Device\HarddiskVolume3\Temp\b.exe"))     # открыт
    guard._on_etw(12, 900, event(5, r"\Device\HarddiskVolume3\Temp\c.txt"))     # не программа
    guard._on_etw(12, 900, event(5, r"\Device\HarddiskVolume3\Temp\d.ps1"))     # перезаписан
    assert sorted(s.record(900).files) == [r"C:\Temp\a.exe", r"C:\Temp\d.ps1"]
