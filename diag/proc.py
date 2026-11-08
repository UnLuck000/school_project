"""Внешние команды: каждый subprocess.run и запуск subprocess.Popen — в журнал.

run: команда (PowerShell-скрипт — первые строки), код выхода, длительность, при ошибке —
конец stderr/stdout. Popen: команда и PID (долгие процессы — ядра VPN, рабочие процессы
проверки; их завершение пишут сами модули). Значения из переменных окружения не пишутся:
по соглашению проекта данные передаются в PowerShell через них.

Обёртка ставится один раз на модуль subprocess (install) и не меняет поведение вызовов.
"""
import subprocess
import threading
import time

from diag.log import get

log = get("proc")
SLOW_SEC = 10.0
_installed = False
_inside_run = threading.local()  # Popen внутри run уже описан строкой run


def _command(args) -> str:
    if isinstance(args, (list, tuple)):
        parts = [str(a) for a in args]
    else:
        parts = [str(args)]
    if parts and parts[0].lower().endswith(("powershell", "powershell.exe", "pwsh.exe")):
        script = parts[-1].replace("\r", " ").replace("\n", " ")
        return f"PowerShell: {script[:300]}{'…' if len(script) > 300 else ''}"
    text = " ".join(parts)
    return text[:400] + ("…" if len(text) > 400 else "")


def _tail(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = str(value).strip()
    return value[-600:]


def install() -> None:
    global _installed
    if _installed:
        return
    _installed = True
    original_run = subprocess.run
    original_init = subprocess.Popen.__init__

    def run(*args, **kwargs):
        cmd = _command(args[0] if args else kwargs.get("args"))
        start = time.monotonic()
        _inside_run.on = True
        try:
            result = original_run(*args, **kwargs)
        except subprocess.TimeoutExpired:
            log.warning("Команда не уложилась в %s с: %s", kwargs.get("timeout"), cmd)
            raise
        except OSError as e:
            log.error("Команда не запустилась (%s): %s", e, cmd)
            raise
        finally:
            _inside_run.on = False
        took = time.monotonic() - start
        if result.returncode:
            log.warning("Код %s за %.2f с: %s\n%s", result.returncode, took, cmd,
                        _tail(result.stderr) or _tail(result.stdout))
        elif took > SLOW_SEC:
            log.info("Долгая команда %.1f с: %s", took, cmd)
        else:
            log.debug("Код 0 за %.2f с: %s", took, cmd)
        return result

    def popen_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        if getattr(_inside_run, "on", False):
            return
        try:
            cmd = _command(args[0] if args else kwargs.get("args"))
            if "--scan-worker" in cmd or "scanner.worker" in cmd:
                log.debug("Рабочий процесс проверки PID %s", self.pid)
            elif not cmd.startswith("PowerShell"):
                log.info("Запущен процесс PID %s: %s", self.pid, cmd)
        except Exception:
            pass

    subprocess.run = run
    subprocess.Popen.__init__ = popen_init
