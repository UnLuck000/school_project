r"""Шаг 7 service/DESIGN.md: инструменты, меняющие систему, — отдельным процессом с правами
через окно UAC, а не операциями канала службы.

Почему не через службу: всё, что окно без прав может попросить у службы, может попросить и
вредонос в сеансе пользователя (он внедряется в процесс окна — тот без прав). Для защиты
это терпимо (операции узкие, ослабляющие — под запретом lock_protection), а центр
восстановления, сканер автозапуска и драйверы — это удаление ключей реестра, служб и файлов
по выбору пользователя: такой канал был бы готовым повышением прав. Окно UAC на каждое
открытие инструмента подтверждает сам пользователь (обойти его без прав нельзя).

    StretchBIT.exe --tool <recovery|autoruns|drivers> [--tab N]  — окно инструмента
    StretchBIT.exe --undo <id записи журнала>                     — отмена с правами

Процесс с правами — та же программа той же учётной записи: журнал действий, настройки — те
же (%APPDATA%), карантин, журнал защиты и белый список — у службы (подключается к ней сам).
"""
import ctypes
import os
import sys
from ctypes import wintypes

TOOLS = ("recovery", "autoruns", "drivers")
ERROR_CANCELLED = 1223
SEE_MASK_NOCLOSEPROCESS = 0x40
SW_SHOWNORMAL = 1
STILL_ACTIVE = 259


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


def wanted(name: str) -> bool:
    """Открывать ли инструмент процессом с правами: окно без прав и служба работает (без
    службы окно и так запускается с правами — прежний порядок)."""
    from service import remote
    from trustseal import is_admin
    return name in TOOLS and remote.REMOTE is not None and not is_admin()


def command(args: list[str]) -> tuple[str, str]:
    """(программа, параметры): собранная — StretchBIT.exe, из исходников — python gui.py."""
    import subprocess
    if getattr(sys, "frozen", False):
        return sys.executable, subprocess.list2cmdline(args)
    gui = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gui.py")
    return sys.executable, subprocess.list2cmdline([gui, *args])


def start(args: list[str]):
    """Запуск с правами. Дескриптор процесса или None (окно UAC закрыли «Нет»)."""
    if sys.platform != "win32":
        return None
    exe, params = command(args)
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb, info.lpFile, info.lpParameters = "runas", exe, params
    info.lpDirectory = os.getcwd()
    info.nShow = SW_SHOWNORMAL
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error()
        if err == ERROR_CANCELLED:
            return None
        raise OSError(err, f"не удалось запустить с правами администратора ({err})")
    return info.hProcess


def exit_code(handle) -> int | None:
    """Код завершения процесса или None, пока он работает."""
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    code = wintypes.DWORD()
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    if not k32.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == STILL_ACTIVE:
        return None
    k32.CloseHandle(handle)
    return code.value


def open_tool(name: str, tab: int = 0) -> bool:
    """True — инструмент открыт процессом с правами; False — пользователь отказался."""
    args = ["--tool", name] + (["--tab", str(int(tab))] if tab else [])
    handle = start(args)
    if handle is None:
        return False
    ctypes.WinDLL("kernel32").CloseHandle(handle)
    return True


# ---------- процесс с правами ----------
def _connect_service() -> None:
    from service import client, remote
    svc = client.connect()
    if svc is not None:
        remote.install(svc)


def run_tool(argv: list[str]) -> int:
    """--tool: одно окно инструмента; программа завершается, когда его закрыли."""
    name = argv[argv.index("--tool") + 1] if argv.index("--tool") + 1 < len(argv) else ""
    if name not in TOOLS:
        return 2
    tab = 0
    if "--tab" in argv:
        try:
            tab = int(argv[argv.index("--tab") + 1])
        except (ValueError, IndexError):
            tab = 0
    from PySide6.QtWidgets import QApplication

    from ui import settings as cfg
    from ui import theme
    app = QApplication.instance() or QApplication(sys.argv)
    theme.apply_theme(app, cfg.get("general/theme"))
    _connect_service()
    from diag.log import get
    get("service").info("Инструмент с правами: %s", name)
    if name == "recovery":
        from recovery.window import RecoveryWindow
        window = RecoveryWindow()
        window.show_tab(tab)
    elif name == "autoruns":
        from autoruns.window import AutorunsWindow
        window = AutorunsWindow()
    else:
        from toolbox.driverswindow import DriversWindow
        window = DriversWindow()
    window.setWindowTitle(window.windowTitle() + " — с правами администратора")
    window.show()
    return app.exec()


def needs_admin(error: BaseException) -> bool:
    """Отмена не удалась из-за прав (окно без прав администратора)."""
    text = str(error)
    return isinstance(error, PermissionError) or getattr(error, "winerror", 0) == 5 or any(
        s in text for s in ("Access is denied", "Отказано в доступе", "0x80070005",
                            "прав администратора", "Нет прав"))


def run_undo(argv: list[str]) -> int:
    """--undo id [id...]: отменить записи журнала действий с правами и показать итог."""
    ids = [a for a in argv[argv.index("--undo") + 1:] if not a.startswith("--")]
    from PySide6.QtWidgets import QApplication, QMessageBox

    from ui import settings as cfg
    from ui import theme
    app = QApplication.instance() or QApplication(sys.argv)
    theme.apply_theme(app, cfg.get("general/theme"))
    _connect_service()
    import recovery.journal_page  # noqa: F401 — регистрирует откаты всех разделов
    from recovery import journal
    messages, errors = [], []
    for record_id in ids:
        try:
            try:
                messages.append(journal.undo(record_id))
            except journal.UnsignedRecord as unsigned:
                if QMessageBox.question(None, "Запись без подписи",
                                        "Запись журнала не подписана. Отменить её?\n\n" +
                                        str(unsigned)) != QMessageBox.StandardButton.Yes:
                    continue
                messages.append(journal.undo(record_id, unsigned_ok=True))
        except (ValueError, OSError) as e:
            errors.append(str(e))
    if errors:
        QMessageBox.warning(None, "Отмена действия", f"Отменено: {len(messages)}. Не удалось: "
                            f"{len(errors)}\n\n" + "\n".join(errors[:10]))
        return 1
    QMessageBox.information(None, "Отмена действия",
                            messages[0] if len(messages) == 1 else
                            f"Отменено действий: {len(messages)}")
    return 0
