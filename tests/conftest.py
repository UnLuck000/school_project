"""Общие настройки тестов."""
import os
import tempfile

import pytest

# Конфигурация пользователя (настройки, журнал, белый список, профили VPN — userdata.py) —
# во временной папке: тесты не трогают настоящую %APPDATA%\StretchBitConfiguration.
# Задаётся до импорта модулей программы: пути вычисляются при импорте.
os.environ["STRETCHBIT_CONFIG_DIR"] = tempfile.mkdtemp(prefix="sbit-config-")
# защищённые копии списков доверия и ключ кэша (trustseal.py) — тоже во временной папке,
# не в настоящей %ProgramData%\StretchBIT
os.environ["STRETCHBIT_SEAL_DIR"] = tempfile.mkdtemp(prefix="sbit-seal-")

# технический журнал logs/app.log: «import gui» в тесте включает его (diag_log.setup), и
# дальше туда писали бы все тесты — в настоящий журнал проекта. Во временную папку.
from pathlib import Path  # noqa: E402

from diag import log as _diag_log  # noqa: E402

_diag_log.LOG_DIR = Path(tempfile.mkdtemp(prefix="sbit-logs-"))
_diag_log.LOG_FILE = _diag_log.LOG_DIR / "app.log"


@pytest.fixture(autouse=True)
def _separate_release_overrides(tmp_path_factory, monkeypatch):
    """Тесты идут как тестовая версия, а она пишет исключения в signatures/
    release_overrides.json (он в Git и в релизе) — тесты его не трогают."""
    from scanner import overrides
    folder = tmp_path_factory.mktemp("release_overrides")
    monkeypatch.setattr(overrides, "RELEASE_FILE", folder / "release_overrides.json")
    monkeypatch.setattr(overrides, "_cache", None)
    # отчёт о работе (reports/activity/events.jsonl) — тоже не настоящий
    from recovery import activity
    activity_dir = tmp_path_factory.mktemp("activity")
    monkeypatch.setattr(activity, "ACTIVITY_DIR", activity_dir)
    monkeypatch.setattr(activity, "EVENTS_FILE", activity_dir / "events.jsonl")
    from scanner import whitelist
    whitelist.forget_trusted()  # доверенные хэши помнятся 2 с: тесты друг другу не мешают
