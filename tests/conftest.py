"""Общие настройки тестов."""
import pytest


@pytest.fixture(autouse=True)
def _separate_release_overrides(tmp_path_factory, monkeypatch):
    """Тесты идут как тестовая версия, а она пишет исключения в signatures/
    release_overrides.json (он в Git и в релизе) — тесты его не трогают."""
    from scanner import overrides
    folder = tmp_path_factory.mktemp("release_overrides")
    monkeypatch.setattr(overrides, "RELEASE_FILE", folder / "release_overrides.json")
    monkeypatch.setattr(overrides, "_cache", None)
