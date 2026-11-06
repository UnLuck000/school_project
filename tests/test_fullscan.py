"""Полная проверка: пропуск игр и ресурсов, обход без ссылок; размеры папок анализатора."""
import threading

from analyzer import fileops
from scanner import fullscan


def _tree(tmp_path):
    game = tmp_path / "Games" / "SomeGame"
    (game / "SomeGame_Data").mkdir(parents=True)
    (game / "SomeGame.exe").write_bytes(b"MZ" + b"\0" * 100)
    (game / "UnityPlayer.dll").write_bytes(b"MZ" + b"\0" * 100)
    (game / "SomeGame_Data" / "data.unity3d").write_bytes(b"\0" * 1000)
    (game / "SomeGame_Data" / "level0").write_bytes(b"\0" * 1000)
    steam = tmp_path / "Steam" / "steamapps" / "common" / "Shooter"
    steam.mkdir(parents=True)
    (steam / "pak01_000.vpk").write_bytes(b"\0" * 1000)
    (steam / "shooter.exe").write_bytes(b"MZ")
    docs = tmp_path / "Docs"
    docs.mkdir()
    (docs / "report.txt").write_text("text")
    (docs / "textures.pak").write_bytes(b"\0" * 10)            # ресурс вне игры: пропуск
    (docs / "fake.pak").write_bytes(b"MZ" + b"\0" * 10)        # программа под чужим расширением
    return game, steam, docs


def test_walk_skips_game_assets(tmp_path):
    game, steam, docs = _tree(tmp_path)
    stats = fullscan.Stats()
    found = set(fullscan.walk(str(tmp_path), stats, threading.Event()))
    assert found == {str(game / "SomeGame.exe"), str(game / "UnityPlayer.dll"),
                     str(steam / "shooter.exe"), str(docs / "report.txt"),
                     str(docs / "fake.pak")}
    assert stats.files == 9 and stats.skipped == 4
    assert set(stats.game_dirs) == {str(game), str(steam)}


def test_states_and_reasons():
    assert fullscan.child_state("", "steamapps") == "library"
    assert fullscan.child_state("library", "common") == "library"
    assert fullscan.child_state("library", "cs2") == "game"
    assert fullscan.child_state("game", "anything") == "game"
    assert fullscan.child_state("", "documents") == ""
    assert fullscan.skip_reason("a.dll", 1, True) is None          # программы — всегда
    assert fullscan.skip_reason("a.png", 1, True) == "данные игры"
    assert fullscan.skip_reason("a.vpk", 1, False) == "ресурсы игры"
    assert fullscan.skip_reason("a.bin", fullscan.DATA_LIMIT, False) == "крупный файл данных"
    assert fullscan.skip_reason("a.bin", 10, False) is None


def test_walk_cancel(tmp_path):
    _tree(tmp_path)
    cancel = threading.Event()
    cancel.set()
    assert list(fullscan.walk(str(tmp_path), fullscan.Stats(), cancel)) == []


def test_folder_files_limit(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.bin").write_bytes(b"x" * 600)
    (tmp_path / "sub" / "b.bin").write_bytes(b"x" * 600)
    files, size, count, opened = fileops.folder_files(str(tmp_path), 2000)
    assert opened and size == 1200 and count == 2 and len(files) == 2
    files, size, count, opened = fileops.folder_files(str(tmp_path), 1000)
    assert files is None and size == 1200 and count == 2  # размер считается и у крупной
    assert not fileops.folder_files(str(tmp_path / "missing"), 1000)[3]
