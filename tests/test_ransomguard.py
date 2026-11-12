"""Шифровальщик по поведению (toolbox/ransomguard.py)."""
import os

from toolbox import ransomguard as rg

NOISE = os.urandom(8192)


def test_looks_encrypted_by_magic_and_entropy(tmp_path):
    good = tmp_path / "report.docx"
    good.write_bytes(b"PK\x03\x04" + NOISE)          # сжатый документ: шум, но формат цел
    broken = tmp_path / "photo.jpg"
    broken.write_bytes(NOISE)                        # начало не FF D8 и шум
    text = tmp_path / "notes.txt"
    text.write_bytes(b"plain text line\r\n" * 600)
    locked = tmp_path / "plan.xlsx.locked"
    locked.write_bytes(NOISE)                        # документ с дописанным расширением
    renamed = tmp_path / "plan.pdf.bak"
    renamed.write_bytes(b"%PDF-1.7" + NOISE)         # просто переименован: содержимое цело
    assert not rg.looks_encrypted(good)
    assert rg.looks_encrypted(broken)
    assert not rg.looks_encrypted(text)
    assert rg.looks_encrypted(locked)
    assert not rg.looks_encrypted(renamed)
    assert not rg.looks_encrypted(tmp_path / "tool.exe", NOISE)   # не документ
    assert not rg.looks_encrypted(tmp_path / "tiny.jpg", NOISE[:100])


def test_burst_needs_many_files_in_window():
    det = rg.BurstDetector(threshold=4, window=60)
    assert det.feed("a.jpg", 0, NOISE) == []
    assert det.feed("a.jpg", 1, NOISE) == []          # тот же файл не считается дважды
    assert det.feed("b.jpg", 2, NOISE) == []
    assert det.feed("ok.docx", 3, b"PK\x03\x04" + NOISE) == []
    assert det.feed("c.jpg", 100, NOISE) == []        # первые два уже вне окна
    assert det.feed("d.pdf", 101, NOISE) == []
    assert det.feed("e.png", 102, NOISE) == []
    found = det.feed("f.docx", 103, NOISE)
    assert len(found) == 4 and all(isinstance(p, str) for p in found)
    # после тревоги — пауза: сразу второй раз не срабатывает
    for i in range(6):
        assert det.feed(f"g{i}.jpg", 104 + i, NOISE) == []


def test_monitor_reports_burst(tmp_path, monkeypatch):
    import monitor
    events = []
    mon = monitor.RealtimeMonitor.__new__(monitor.RealtimeMonitor)
    mon.folders = [tmp_path]
    mon.on_event = lambda kind, text: events.append((kind, text))
    mon._ransom = rg.BurstDetector(threshold=3)
    for i in range(3):
        f = tmp_path / f"doc{i}.pdf"
        f.write_bytes(NOISE)
        mon._watch_ransom(f)
    assert events and events[-1][0] == "ransom" and len(events[-1][1].split("\n")) == 3
    outside = tmp_path.parent / "elsewhere.pdf"
    mon._watch_ransom(outside)                        # не папка пользователя — не считаем
