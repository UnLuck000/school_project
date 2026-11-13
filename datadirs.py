r"""Куда программа пишет журналы, кэш и отчёты.

Раньше — всегда в папку программы (app\logs, app\cache, app\reports), а установщик открывал
эти папки на запись всем пользователям: программа без прав (отказ в окне UAC) тоже должна
куда-то писать. Но та же программа с правами администратора создавала, удаляла и чистила там
файлы, и любой процесс без прав мог подменить вложенную папку ссылкой (junction) на, например,
C:\Windows\System32: запись конфигурации VPN или очистка папки шли бы уже туда — с правами
администратора.

Теперь:
  * с правами администратора — папка программы (установщик закрывает её от записи целиком);
  * без прав — %LOCALAPPDATA%\StretchBIT[-test] (своя папка пользователя: там программа
    без прав не может навредить больше, чем любая другая программа пользователя);
  * из исходников (python gui.py, тесты) — папка проекта, как раньше.
"""
import os
import sys
from pathlib import Path

import userdata


def _admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def root() -> Path:
    if not getattr(sys, "frozen", False) or _admin():
        return Path(userdata.APP_DIR)
    from diag import edition
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return base / ("StretchBIT-test" if edition.is_test() else "StretchBIT")


ROOT = root()
CACHE = ROOT / "cache"
LOGS = ROOT / "logs"
REPORTS = ROOT / "reports"
# метку «не перезапускать» ставят установщик и удаление (с правами) — в папке программы
APP_CACHE = Path(userdata.APP_DIR) / "cache"
