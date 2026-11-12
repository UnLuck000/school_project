"""Внешние команды: каждый subprocess.run и запуск subprocess.Popen — в журнал.

run: команда (PowerShell-скрипт — первые строки), код выхода, длительность, при ошибке —
конец stderr/stdout. Popen: команда и PID (долгие процессы — ядра VPN, рабочие процессы
проверки; их завершение пишут сами модули). Значения из переменных окружения не пишутся:
по соглашению проекта данные передаются в PowerShell через них.

Обёртка ставится один раз на модуль subprocess (install). Единственное изменение вызова —
имя системной программы без пути заменяется полным путём (syscmd.resolve).
"""
import os
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


def _text(value, limit: int = 4000) -> str:
    """Вывод программы для разбора: UTF-8, а netsh и консольный PowerShell — в OEM (cp866)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value[-limit:]
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("oem" if os.name == "nt" else "latin-1", "replace")
    return str(value)[-limit:]


def _check(argv, cmd: str, error: BaseException | None = None, result=None) -> None:
    """Сбой системной программы с узнаваемой причиной — предупреждение (diag/systool)."""
    try:
        from diag import systool
        failure = systool.diagnose(
            argv, error=error, returncode=getattr(result, "returncode", None),
            output=(_text(result.stderr) + "\n" + _text(result.stdout)) if result else "",
            command=cmd)
        if failure is not None:
            systool.report(failure)
    except Exception:  # noqa: BLE001 — разбор сбоя не должен ломать сам вызов
        from diag.log import swallowed
        swallowed("proc: разбор сбоя")


def _full_path(args: tuple, kwargs: dict) -> tuple[tuple, dict]:
    """Имя системной программы без пути → полный путь (syscmd.resolve): Windows иначе ищет
    её сначала в папке самой программы, куда файл можно подложить."""
    import syscmd
    if args:
        return (syscmd.resolve(args[0]), *args[1:]), kwargs
    if "args" in kwargs:
        return args, {**kwargs, "args": syscmd.resolve(kwargs["args"])}
    return args, kwargs


def install() -> None:
    global _installed
    if _installed:
        return
    _installed = True
    original_run = subprocess.run
    original_init = subprocess.Popen.__init__

    def run(*args, **kwargs):
        args, kwargs = _full_path(args, kwargs)
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
            _check(args[0] if args else kwargs.get("args"), cmd, error=e)
            raise
        finally:
            _inside_run.on = False
        took = time.monotonic() - start
        if result.returncode:
            log.warning("Код %s за %.2f с: %s\n%s", result.returncode, took, cmd,
                        _tail(result.stderr) or _tail(result.stdout))
            _check(args[0] if args else kwargs.get("args"), cmd, result=result)
        elif took > SLOW_SEC:
            log.info("Долгая команда %.1f с: %s", took, cmd)
        else:
            log.debug("Код 0 за %.2f с: %s", took, cmd)
        return result

    def popen_init(self, *args, **kwargs):
        args, kwargs = _full_path(args, kwargs)
        try:
            original_init(self, *args, **kwargs)
        except OSError as e:
            if not getattr(_inside_run, "on", False):  # у run — своя запись
                _check(args[0] if args else kwargs.get("args"), _command(
                    args[0] if args else kwargs.get("args")), error=e)
            raise
        if getattr(_inside_run, "on", False):
            return
        try:
            cmd = _command(args[0] if args else kwargs.get("args"))
            if "--scan-worker" in cmd or "scanner.worker" in cmd:
                log.debug("Рабочий процесс проверки PID %s", self.pid)
            elif not cmd.startswith("PowerShell"):
                log.info("Запущен процесс PID %s: %s", self.pid, cmd)
        except Exception:  # noqa: S110 — запись о запуске не должна мешать запуску процесса
            pass

    subprocess.run = run
    subprocess.Popen.__init__ = popen_init
