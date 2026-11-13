"""Разработка: python -m service --console — ядро службы в консоли (данные в
cache/service-dev). Интерфейс из исходников подключается к нему при
STRETCHBIT_SERVICE_DEV=1. Остальные ключи — как у StretchBIT.exe (service/main.py)."""
import os
import sys
from pathlib import Path

os.chdir(Path(__file__).resolve().parent.parent)  # пути баз относительные: корень проекта
from service.main import entry  # noqa: E402

args = sys.argv[1:]
if "--console" in args:
    args.append("--service-console")
sys.exit(entry(args or ["--service-console"]))
