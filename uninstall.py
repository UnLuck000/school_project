r"""Удаление программы: StretchBIT.exe --uninstall.

Запускается из «Параметры → Приложения» (запись в реестре делает установщик), из ярлыка
«Удалить StretchBIT» в меню «Пуск» или вручную. Нужны права администратора (gui.py
перезапускает с UAC). Порядок:
1. закрыть работающую программу из этой папки (её ядра VPN закроются вместе с ней —
   vpn/procguard);
2. вернуть то, что программа меняла в системе: прокси, kill switch, DNS (vpn/*.recover),
   правила брандмауэра групп «SBIT» и «SBIT-killswitch» (и прежних «myav»), сеансы ETW, ловушки для
   шифровальщиков;
3. убрать задание автозапуска и пункт «Проверить в ...» Проводника — только если они
   указывают на эту папку (у тестовой, релизной и запуска из исходников они общие), ярлыки,
   запись «Приложения»; по галочке (по умолчанию да) — настройки программы, регистрацию
   уведомлений и правила брандмауэра (блокировки со страницы «Сеть»);
4. удалить папку программы целиком (с карантином и журналами) — отдельной командой после
   выхода: запущенный .exe Windows удалить не даёт.
По той же галочке удаляется и папка конфигурации %APPDATA%\StretchBitConfiguration[-test]
(userdata.py: настройки, журнал действий, белый список, исключения, профили VPN).
Каждый шаг независим: ошибка одного не останавливает остальные, итог показывается.

Деинсталлятор Inno Setup (installer.iss) вызывает StretchBIT.exe --uninstall --silent
[--wipe]: те же шаги 1–3 без окон, а ярлыки, запись «Приложения» и папку программы
удаляет сам Inno Setup.
"""
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import appinfo
import syscmd

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
ETW_SESSIONS = ("sbit-dns", "sbit-proc", "sbit-files", "myav-dns", "myav-proc", "myav-files")
KILLSWITCH_GROUPS = ("SBIT-killswitch", "myav-killswitch")
FIREWALL_GROUPS = ("SBIT", "myav") + KILLSWITCH_GROUPS  # и прежние названия


def install_dir() -> Path:
    return Path(sys.executable).resolve().parent


def key_name(test: bool) -> str:
    return f"{appinfo.APP_NAME}-test" if test else appinfo.APP_NAME


def link_names(test: bool) -> list[str]:
    suffix = " (тест)" if test else ""
    return [f"{appinfo.APP_NAME}{suffix}.lnk", f"Удалить {appinfo.APP_NAME}{suffix}.lnk"]


def _powershell(script: str, env: dict | None = None) -> None:
    subprocess.run(syscmd.PS_ARGS + [script],
                   env={**os.environ, **(env or {})}, capture_output=True, timeout=120,
                   creationflags=CREATE_NO_WINDOW)


def _other_installed(test: bool) -> bool:
    """Другая версия установлена: прежним установщиком или Inno Setup (ключ <AppId>_is1)."""
    import winreg
    for name in (key_name(not test), key_name(not test) + "_is1"):
        for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(root, UNINSTALL_KEY + "\\" + name):
                    return True
            except OSError:
                continue
    return False


def close_running(folder: Path) -> int:
    """Закрыть другие экземпляры StretchBIT.exe из этой папки."""
    import selfguard
    selfguard.forbid_restart()  # иначе сторож вернул бы закрытую программу
    import psutil
    me, count = os.getpid(), 0
    target = os.path.normcase(str(folder))
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            exe = p.info.get("exe") or ""
            if p.info["pid"] != me and os.path.normcase(os.path.dirname(exe)) == target:
                p.kill()
                count += 1
        except (psutil.Error, OSError):
            pass
    return count


def steps(folder: Path, test: bool, wipe: bool = True,
          silent: bool = False) -> list[tuple[str, Callable[[], object]]]:
    """silent — вызов из деинсталлятора Inno Setup: ярлыки и запись «Приложения» он
    удаляет сам."""
    from ui import settings as cfg

    def vpn_restore():
        from vpn import dnsguard, killswitch, procguard, xray
        procguard.kill_orphans()
        xray.recover_proxy()
        killswitch.recover()
        dnsguard.recover()

    def firewall():
        groups = FIREWALL_GROUPS if wipe else KILLSWITCH_GROUPS  # kill switch — всегда
        _powershell("foreach ($g in ($env:FW_GROUPS -split ',')) { "
                    "Remove-NetFirewallRule -Group $g -ErrorAction SilentlyContinue }",
                    {"FW_GROUPS": ",".join(groups)})

    def etw():
        for name in ETW_SESSIONS:
            subprocess.run(["logman", "stop", name, "-ets"], capture_output=True,
                           creationflags=CREATE_NO_WINDOW)

    def amsi_provider():
        from scanner import amsi
        if amsi.registered():
            amsi.uninstall()  # иначе Windows грузила бы библиотеку и после удаления

    def decoys():
        from toolbox import decoys as d
        d.remove_all()

    def autostart():
        if cfg.autostart_current():  # задание запускает именно эту копию
            cfg.set_autostart(False)

    def explorer():
        if cfg.explorer_current():
            cfg.set_explorer_menu(False)

    def registry():
        import winreg
        from ui import notify
        keys = [] if silent else [UNINSTALL_KEY + "\\" + key_name(test)]
        if wipe and not _other_installed(test):  # регистрация уведомлений общая у обеих
            # прежнее место настроек (до папки конфигурации) — тоже общее
            keys += [notify.KEY, *notify.LEGACY_KEYS, rf"Software\{cfg.ORG}\{cfg.APP}",
                     cfg.LEGACY_EXPLORER_KEY]
        for key in keys:
            _delete_tree(winreg.HKEY_CURRENT_USER, key)

    def config():
        import shutil

        import userdata
        if wipe and userdata.CONFIG_DIR.exists():
            shutil.rmtree(userdata.CONFIG_DIR)

    def shortcuts():
        import ctypes
        for csidl in (0x10, 0x02):  # рабочий стол, «Пуск → Программы»
            buf = ctypes.create_unicode_buffer(260)
            ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
            for name in link_names(test):
                try:
                    (Path(buf.value) / name).unlink()
                except OSError:
                    pass

    return [("Закрыть запущенную программу", lambda: close_running(folder)),
            ("Вернуть настройки сети после VPN", vpn_restore),
            ("Удалить правила брандмауэра программы", firewall),
            ("Остановить сеансы ETW", etw),
            ("Снять провайдер проверки скриптов (AMSI)", amsi_provider),
            ("Удалить ловушки для шифровальщиков", decoys),
            ("Убрать автозапуск", autostart),
            ("Убрать пункт меню Проводника", explorer),
            ("Удалить записи в реестре", registry),
            ("Удалить настройки пользователя (папку конфигурации)", config)] + \
        ([] if silent else [("Удалить ярлыки", shortcuts)])


def _delete_tree(root, path: str) -> None:
    import winreg
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_ALL_ACCESS) as key:
            while True:
                try:
                    child = winreg.EnumKey(key, 0)
                except OSError:
                    break
                _delete_tree(root, path + "\\" + child)
        winreg.DeleteKey(root, path)
    except OSError:
        pass


def remove_folder_later(folder: Path) -> None:
    """Папку удаляет отдельный cmd через 3 с после выхода программы."""
    env = {**os.environ, "SB_DIR": str(folder)}
    subprocess.Popen(["cmd", "/c", 'ping -n 4 127.0.0.1 >nul & rmdir /s /q "%SB_DIR%"'],
                     cwd=tempfile.gettempdir(), env=env,
                     creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS)


def run_silent(wipe: bool) -> int:
    """Вызов из деинсталлятора Inno Setup: шаги без окон и без удаления папки (её удалит
    Inno Setup после выхода). Код возврата — число неудавшихся шагов."""
    from diag import edition
    from diag.log import get
    log = get("uninstall")
    folder, test = install_dir(), edition.is_test()
    log.info("Удаление (Inno Setup) из %s (настройки пользователя: %s)", folder,
             "удалить" if wipe else "оставить")
    failed = 0
    for title, action in steps(folder, test, wipe, silent=True):
        try:
            action()
            log.info("Удаление: %s — готово", title)
        except Exception as e:  # noqa: BLE001 — шаги независимы
            failed += 1
            log.error("Удаление: %s — ошибка: %s", title, e)
    return failed


def run() -> bool:
    """Диалог, шаги удаления, итог. True — удалено (папка удалится после выхода)."""
    from PySide6.QtWidgets import QMessageBox

    from diag import edition
    from diag.log import get
    log = get("uninstall")
    folder, test = install_dir(), edition.is_test()
    if not getattr(sys, "frozen", False):
        QMessageBox.information(None, "Удаление", "Удаление работает только у установленной "
                                "программы (StretchBIT.exe), не из исходников.")
        return False
    from PySide6.QtWidgets import QCheckBox
    box = QMessageBox(QMessageBox.Icon.Question, f"Удаление {appinfo.APP_NAME}",
                      f"Удалить {appinfo.APP_NAME} {appinfo.VERSION}"
                      f"{' (тестовая версия)' if test else ''} из {folder}?\n\n"
                      "Программа будет закрыта, её автозапуск и пункт меню Проводника убраны, "
                      "настройки сети после VPN возвращены. Папка программы будет удалена "
                      "целиком — вместе с карантином, журналами и отчётами.",
                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    wipe_box = QCheckBox("Удалить все настройки пользователя: настройки, журнал, белый "
                         "список, исключения, профили VPN и правила брандмауэра "
                         "(блокировки со страницы «Сеть»)")
    wipe_box.setChecked(True)
    box.setCheckBox(wipe_box)
    if box.exec() != QMessageBox.StandardButton.Yes:
        log.info("Удаление отменено")
        return False
    wipe = wipe_box.isChecked()
    log.info("Удаление из %s (настройки и правила брандмауэра: %s)", folder,
             "удалить" if wipe else "оставить")
    failed = []
    for title, action in steps(folder, test, wipe):
        try:
            action()
            log.info("Удаление: %s — готово", title)
        except Exception as e:
            failed.append(f"{title}: {e}")
            log.error("Удаление: %s — ошибка: %s", title, e)
    os.chdir(tempfile.gettempdir())  # из папки, которую будем удалять
    remove_folder_later(folder)
    text = f"{appinfo.APP_NAME} удалена. Папка {folder} удалится через несколько секунд."
    if failed:
        text += "\n\nНе всё получилось:\n" + "\n".join(failed)
    QMessageBox.information(None, "Удаление", text)
    return True
