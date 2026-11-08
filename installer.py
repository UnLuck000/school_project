"""Простой установщик StretchBIT: один .exe (PyInstaller --onefile), внутри — архив сборки.

Релизную версию ставит в C:\\Utils\\SBIT, тестовую (папка архива StretchBIT-test) — в
C:\\Utils\\SBIT-test, чтобы они не перезаписывали друг друга. Распаковывает архив поверх прежней версии (журнал, карантин,
кэш, белый список и исключения в архиве не лежат и поэтому сохраняются), создаёт ярлыки на
рабочем столе и в меню «Пуск». Права администратора запрашиваются, только если в папку нельзя
писать без них. Сборка — python build_release.py --installer.
"""
import ctypes
import os
import subprocess
import sys
import threading
import tkinter as tk
import zipfile
from pathlib import Path
from tkinter import messagebox, ttk

import appinfo

TARGET = Path(r"C:\Utils\SBIT")          # тестовая — C:\Utils\SBIT-test (configure)
EXE_NAME = f"{appinfo.APP_NAME}.exe"
TEST = False
LINK_NAME = appinfo.APP_NAME
CREATE_NO_WINDOW = 0x08000000


def payload() -> Path:
    """Архив релиза: внутри собранного установщика или release/ при запуске из исходников."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "payload.zip"
    return Path(__file__).resolve().parent / "release" / f"{appinfo.APP_NAME}-{appinfo.VERSION}.zip"


def configure() -> None:
    """Версия — по имени папки в архиве: StretchBIT или StretchBIT-test."""
    global TARGET, TEST, LINK_NAME
    try:
        with zipfile.ZipFile(payload()) as z:
            top = Path(z.namelist()[0]).parts[0]
    except (OSError, zipfile.BadZipFile, IndexError):
        return
    TEST = top.endswith("-test")
    if TEST:
        TARGET = Path(r"C:\Utils\SBIT-test")
        LINK_NAME = f"{appinfo.APP_NAME} (тест)"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def can_write(folder: Path) -> bool:
    try:
        folder.mkdir(parents=True, exist_ok=True)
        probe = folder / ".sbit_write_test"
        probe.write_bytes(b"")
        probe.unlink()
        return True
    except OSError:
        return False


def relaunch_as_admin() -> bool:
    exe = sys.executable
    args = "" if getattr(sys, "frozen", False) else f'"{os.path.abspath(__file__)}"'
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1) > 32


def program_running() -> bool:
    """Запущенный .exe Windows не даёт открыть на запись."""
    exe = TARGET / EXE_NAME
    if not exe.exists():
        return False
    try:
        with open(exe, "r+b"):
            return False
    except PermissionError:
        return True
    except OSError:
        return False


def shortcut(link: Path, arguments: str = "") -> None:
    """Ярлык через WScript.Shell; значения — через переменные окружения."""
    env = {**os.environ, "SB_LINK": str(link), "SB_EXE": str(TARGET / EXE_NAME),
           "SB_DIR": str(TARGET), "SB_ARGS": arguments}
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:SB_LINK); "
                    "$s.TargetPath = $env:SB_EXE; $s.WorkingDirectory = $env:SB_DIR; "
                    "$s.Arguments = $env:SB_ARGS; "
                    "$s.IconLocation = $env:SB_EXE + ',0'; $s.Save()"],
                   env=env, capture_output=True, creationflags=CREATE_NO_WINDOW, check=False)


def register_uninstall(size_bytes: int) -> None:
    """Запись в «Параметры → Приложения» (HKCU: права администратора не нужны).
    Удаление — StretchBIT.exe --uninstall (uninstall.py)."""
    import winreg
    name = f"{appinfo.APP_NAME}-test" if TEST else appinfo.APP_NAME
    exe = str(TARGET / EXE_NAME)
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                           rf"Software\Microsoft\Windows\CurrentVersion\Uninstall\{name}")
    with key:
        values = {"DisplayName": LINK_NAME, "DisplayVersion": appinfo.VERSION,
                  "Publisher": appinfo.AUTHOR, "DisplayIcon": exe + ",0",
                  "InstallLocation": str(TARGET), "UninstallString": f'"{exe}" --uninstall',
                  "QuietUninstallString": f'"{exe}" --uninstall'}
        for k, v in values.items():
            winreg.SetValueEx(key, k, 0, winreg.REG_SZ, v)
        winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD, size_bytes // 1024)
        for k in ("NoModify", "NoRepair"):
            winreg.SetValueEx(key, k, 0, winreg.REG_DWORD, 1)


def known_folder(csidl: int) -> Path:
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
    return Path(buf.value)


class Installer:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(f"Установка {appinfo.APP_NAME} {appinfo.VERSION}"
                   + (" (тестовая версия)" if TEST else ""))
        root.resizable(False, False)
        frame = ttk.Frame(root, padding=16)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=f"{appinfo.APP_NAME} {appinfo.VERSION}"
                  + (" — тестовая версия" if TEST else ""),
                  font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(frame, text=f"Папка установки: {TARGET}").pack(anchor="w", pady=(8, 8))
        self.desktop = tk.BooleanVar(value=True)
        self.start_menu = tk.BooleanVar(value=True)
        self.run_after = tk.BooleanVar(value=True)
        for text, var in (("Ярлык на рабочем столе", self.desktop),
                          ("Ярлык в меню «Пуск»", self.start_menu),
                          ("Запустить после установки", self.run_after)):
            ttk.Checkbutton(frame, text=text, variable=var).pack(anchor="w")
        self.bar = ttk.Progressbar(frame, length=420, mode="determinate")
        self.bar.pack(fill="x", pady=(12, 4))
        self.status = ttk.Label(frame, text="")
        self.status.pack(anchor="w")
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x", pady=(12, 0))
        self.btn_cancel = ttk.Button(buttons, text="Отмена", command=root.destroy)
        self.btn_cancel.pack(side="right")
        self.btn_install = ttk.Button(buttons, text="Установить", command=self.start)
        self.btn_install.pack(side="right", padx=(0, 8))

    def start(self) -> None:
        if not payload().exists():
            messagebox.showerror("Установка", f"Не найден архив программы: {payload()}")
            return
        if program_running():
            messagebox.showwarning("Установка", f"{appinfo.APP_NAME} сейчас запущена. Закройте её "
                                   "(значок в трее → «Выход») и нажмите «Установить» ещё раз.")
            return
        self.btn_install.config(state="disabled")
        self.btn_cancel.config(state="disabled")
        threading.Thread(target=self.install, daemon=True).start()

    def _progress(self, value: float, text: str) -> None:
        self.root.after(0, lambda: (self.bar.config(value=value), self.status.config(text=text)))

    def install(self) -> None:
        try:
            with zipfile.ZipFile(payload()) as z:
                members = [m for m in z.infolist() if not m.is_dir()]
                for i, m in enumerate(members, 1):
                    rel = Path(*Path(m.filename).parts[1:])  # архив: StretchBIT/<файлы>
                    dest = TARGET / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(m) as src, open(dest, "wb") as out:
                        while chunk := src.read(1 << 20):
                            out.write(chunk)
                    if i % 20 == 0 or i == len(members):
                        self._progress(i * 95 / len(members), f"Файлы: {i} из {len(members)}")
            self._progress(97, "Ярлыки...")
            if self.desktop.get():
                shortcut(known_folder(0x10) / f"{LINK_NAME}.lnk")  # CSIDL_DESKTOPDIRECTORY
            if self.start_menu.get():
                shortcut(known_folder(0x02) / f"{LINK_NAME}.lnk")  # CSIDL_PROGRAMS
            shortcut(known_folder(0x02) / f"Удалить {LINK_NAME}.lnk", "--uninstall")
            register_uninstall(sum(m.file_size for m in members))
            self._progress(100, "Готово")
            self.root.after(0, self.done)
        except OSError as e:
            self.root.after(0, lambda: self.failed(e))

    def done(self) -> None:
        messagebox.showinfo("Установка", f"{appinfo.APP_NAME} установлена в {TARGET}.")
        if self.run_after.get():
            os.startfile(TARGET / EXE_NAME)
        self.root.destroy()

    def failed(self, error: OSError) -> None:
        messagebox.showerror("Установка", f"Не удалось установить: {error}")
        self.btn_install.config(state="normal")
        self.btn_cancel.config(state="normal")


def main() -> None:
    configure()
    if not can_write(TARGET) and not is_admin():
        if relaunch_as_admin():
            return
        ctypes.windll.user32.MessageBoxW(None, f"Без прав администратора нельзя писать в {TARGET}.",
                                         "Установка", 0x10)
        return
    root = tk.Tk()
    Installer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
