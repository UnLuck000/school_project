"""Распознавание видео и аудио по содержимому (scanner/media.py) и проверка без YARA."""
import os
import struct

import pytest

from scanner import engine, media

PE = (b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x80) + b"\0" * (0x80 - 0x40)
      + b"PE\0\0" + b"\0" * 64)


def box(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", 8 + len(body)) + kind + body


def mp4(payload: int = 4096) -> bytes:
    return (box(b"ftyp", b"isom\0\0\2\0isomiso2") + box(b"moov", b"\0" * 64)
            + box(b"mdat", os.urandom(payload)))


def riff(form: bytes, payload: int = 4096) -> bytes:
    body = form + os.urandom(payload)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def write(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_real_media_recognized(tmp_path):
    assert media.plain_media(write(tmp_path, "a.mp4", mp4())) == "iso"
    assert media.plain_media(write(tmp_path, "a.wav", riff(b"WAVE"))) == "riff"
    assert media.plain_media(write(tmp_path, "a.mkv", b"\x1a\x45\xdf\xa3" + os.urandom(999))) == "mkv"
    assert media.plain_media(write(tmp_path, "a.mp3", b"ID3\x04" + os.urandom(999))) == "mp3"
    # расширение не важно: видео без расширения — тоже видео
    assert media.plain_media(write(tmp_path, "noext", mp4())) == "iso"


def test_disguised_executables_are_not_media(tmp_path):
    assert media.plain_media(write(tmp_path, "film.mp4", PE + os.urandom(999))) == ""  # exe под видео
    assert media.plain_media(write(tmp_path, "film2.mp4", mp4() + PE)) == ""  # дописан в конец
    inside = box(b"ftyp", b"isom") + box(b"mdat", os.urandom(512) + PE + os.urandom(512))
    assert media.plain_media(write(tmp_path, "film3.mp4", inside)) == ""     # спрятан внутри
    assert media.plain_media(write(tmp_path, "song.mp3", b"ID3\x04" + os.urandom(99) + PE)) == ""
    assert media.plain_media(write(tmp_path, "film.exe", mp4())) == ""        # имя исполняемого
    assert media.plain_media(write(tmp_path, "cut.wav", riff(b"WAVE") + b"tail")) == ""


def test_big_media_skips_reading(tmp_path, monkeypatch):
    path = write(tmp_path, "big.mp4", mp4())
    monkeypatch.setattr(media, "MEDIA_HASH_LIMIT", 100)  # «крупный» файл

    def no_hash(_path):
        raise AssertionError("крупное видео не должно читаться целиком")

    monkeypatch.setattr(engine, "file_hashes", no_hash)
    monkeypatch.setattr(engine, "analyze", lambda *a, **k: pytest.fail("YARA для видео"))
    assert engine.check_file(path, set(), rules=object(), use_cache=False) is None


def test_small_media_hash_only(tmp_path, monkeypatch):
    path = write(tmp_path, "clip.mp4", mp4())
    digest, _ = engine.file_hashes(path)
    monkeypatch.setattr(engine, "analyze", lambda *a, **k: pytest.fail("YARA для видео"))
    assert engine.check_file(path, {digest}, rules=object(), use_cache=False) == "hash match"
    assert engine.check_file(path, set(), rules=object(), use_cache=False) is None
