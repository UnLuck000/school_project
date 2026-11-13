"""Сборка: python build_release.py [--zip] [--installer] [--sign] [--windivert]

1. PyInstaller по StretchBIT.spec → dist/StretchBIT: StretchBIT.exe и папка app со всем остальным.
2. Рядом кладутся ядра VPN (vpn/bin), инструменты декомпилятора (tools/bin) и из signatures —
   только файлы из Git (release_exclusions.json, release_overrides.json). Скачанных баз в
   сборке нет: первый запуск сразу их обновляет (db/last_update = 0). Файлов этого
   компьютера (белый список, исключения, своя база хэшей, ключ abuse.ch) — тоже нет.
3. Две версии (diag/edition.py): dist/StretchBIT — релизная, dist/StretchBIT-test — тестовая
   (кнопки «✓ Исправно», «✎ Комментарий», страница «Тестирование», подробный журнал).
   Отличаются только файлом app/edition.txt.
4. Эталон исправных функций diag/baseline.json входит в обе. Перед сборкой в него
   добавляются отметки из установленной тестовой версии (Program Files\\StretchBIT-test), если там новее,
   а в signatures/release_overrides.json и release_exclusions.json — её исключения.
5. --zip — архивы release/StretchBIT-<версия>.zip и StretchBIT-test-<версия>.zip;
   --installer — установщики Inno Setup 6 (installer.iss, ISCC.exe): release/StretchBIT-
   <версия>-setup.exe ставит в C:\\Program Files\\StretchBIT, StretchBIT-test-...-setup.exe —
   в ...\\StretchBIT-test (прежнее C:\\Utils\\SBIT переносится); LZMA2, при удалении — флажок
   «Удалить все настройки пользователя».

6. --windivert — WinDivert (native/windivert: WinDivert.dll и WinDivert64.sys, официальный
   выпуск) в app/native/windivert: TLS на вкладке «Сеть» работает без zapret, из папки,
   закрытой от записи. По умолчанию НЕ кладётся: Microsoft Defender считает официальный
   архив WinDivert угрозой (Misleading:Win32/Malgent) и у пользователя мог бы остановить
   установщик целиком. Без него вкладка TLS предлагает указать папку WinDivert.
7. release/SHA256SUMS — хэши архивов и установщиков (по ним проверяет обновление
   updatecheck.py; файл выкладывается в выпуск GitHub вместе с ними).
8. --sign — подпись Authenticode (signtool из Windows SDK) StretchBIT.exe, библиотек AMSI и
   установщиков: сертификат — SBIT_SIGN_PFX (+ SBIT_SIGN_PASSWORD) или отпечаток в хранилище
   SBIT_SIGN_THUMBPRINT; метка времени — SBIT_SIGN_TIMESTAMP (по умолчанию DigiCert).

Журналы, карантин, кэш в сборку не попадают; настройки, журнал действий, профили VPN и пароль
администратора — в %APPDATA%\\StretchBitConfiguration[-test] (userdata.py), не в папке программы.
"""
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import appinfo

ROOT = Path(__file__).resolve().parent
NAME = appinfo.APP_NAME
DIST = ROOT / "dist" / NAME
EDITIONS = {"release": NAME, "test": f"{NAME}-test"}   # версия → папка в dist
def _installed_test() -> Path:
    """Установленная тестовая версия: Program Files (с 1.0.0) или прежнее C:\\Utils."""
    new = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / f"{NAME}-test"
    return new if new.is_dir() else Path(r"C:\Utils\SBIT-test")


INSTALLED_TEST = _installed_test()
BASELINE = ROOT / "diag" / "baseline.json"
# из signatures/ в сборку — только эти файлы (они в Git); базы скачиваются при первом запуске
RELEASE_SIGNATURES = ("release_exclusions.json", "release_overrides.json")
# файлы signatures/, которые принадлежат только этому компьютеру (или секретны)
LOCAL_ONLY = {"whitelist.json", "exclusions.json", "overrides.json", "hashes.txt",
              ".abusech_key"}


def merge_test_baseline() -> None:
    """Отметки «Исправно», сделанные в установленной тестовой версии, — в эталон проекта."""
    installed = INSTALLED_TEST / "app" / "diag" / "baseline.json"
    try:
        theirs = json.loads(installed.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    try:
        ours = json.loads(BASELINE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        ours = {}
    added = [fid for fid, e in theirs.items()
             if e.get("verified_at", "") > ours.get(fid, {}).get("verified_at", "")]
    for fid in added:
        ours[fid] = theirs[fid]
    if added:
        BASELINE.write_text(json.dumps(ours, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"Эталон: добавлены отметки из {installed}: {', '.join(added)}")


def merge_test_exclusions() -> None:
    """Исключения, сделанные в установленной тестовой версии, — в файлы проекта (они в Git и
    в релизе): ложные срабатывания (release_overrides.json; старые версии писали их в
    overrides.json) и исключения release_exclusions.json (драйверы, программы, мониторинг
    сети). Только добавление: снятое в тестовой версии из проекта не убирается."""
    from diag.anon import anonymize_user
    from scanner import exclusions, overrides
    folder = INSTALLED_TEST / "app" / "signatures"
    if not folder.is_dir():
        return
    ours = overrides.read_file(overrides.RELEASE_FILE)
    import userdata  # из исходников — тестовая: её папка конфигурации общая с установленной
    theirs = overrides.merge(overrides.read_file(folder / "overrides.json"),
                             overrides.read_file(userdata.OVERRIDES_FILE),
                             overrides.read_file(folder / "release_overrides.json"))
    added = 0
    for kind in overrides.KINDS:
        for key, info in theirs[kind].items():
            if key not in ours[kind]:
                if info.get("path"):
                    info = {**info, "path": anonymize_user(info["path"])}
                ours[kind][key] = info
                added += 1
    if added:
        overrides.write_file(overrides.RELEASE_FILE, ours)
        print(f"Ложные срабатывания: добавлено из {folder}: {added}")

    try:
        their_excl = json.loads((folder / "release_exclusions.json").read_text(encoding="utf-8"))
        our_excl = json.loads(exclusions.RELEASE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    added = 0
    for category in exclusions.RELEASE_CATEGORIES | exclusions.TEST_TO_RELEASE:
        for key, item in (their_excl.get(category) or {}).items():
            if key not in our_excl.setdefault(category, {}):
                our_excl[category][key] = item
                added += 1
    if added:
        exclusions.RELEASE_FILE.write_text(json.dumps(our_excl, ensure_ascii=False, indent=2),
                                           encoding="utf-8")
        print(f"Исключения: добавлено из {folder}: {added}")


def build_amsi() -> None:
    """Провайдер AMSI (native/amsi): собрать, если библиотек ещё нет."""
    bin_dir = ROOT / "native" / "amsi" / "bin"
    if all((bin_dir / name).is_file() for name in ("sbit_amsi64.dll", "sbit_amsi32.dll")):
        return
    print("Собираю провайдер AMSI (native/amsi/build.py)...")
    subprocess.run([sys.executable, str(ROOT / "native" / "amsi" / "build.py")], check=True,
                   cwd=ROOT)


def run_pyinstaller() -> None:
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build" / "pyinstaller"),
                    str(ROOT / "StretchBIT.spec")], check=True, cwd=ROOT)


def copy_vpn_cores(app: Path) -> None:
    src = ROOT / "vpn" / "bin"
    if not (src / "xray.exe").exists():
        print("! vpn/bin без xray.exe — VPN в сборке работать не будет")
    shutil.copytree(src, app / "vpn" / "bin", dirs_exist_ok=True)


def copy_decompilers(app: Path) -> None:
    """Инструменты вкладки «Декомпилятор» (tools/bin: UPX, pycdc, CFR, sbit-dotnet)."""
    src = ROOT / "tools" / "bin"
    if not (src / "dotnet" / "sbit-dotnet.exe").exists():
        print("! tools/bin без sbit-dotnet.exe — сначала python tools/build_tools.py")
    if src.is_dir():
        shutil.copytree(src, app / "tools" / "bin", dirs_exist_ok=True)


def copy_signatures(app: Path) -> None:
    """Только файлы из Git: скачанные базы (feeds, netfeeds, rules) не входят — ~70 МБ,
    а первый запуск всё равно сразу их обновляет."""
    src, dst = ROOT / "signatures", app / "signatures"
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    for name in RELEASE_SIGNATURES:
        shutil.copy2(src / name, dst / name)
    leaked = [p for p in dst.rglob("*") if p.name in LOCAL_ONLY]
    if leaked:
        raise SystemExit(f"В сборку попали локальные файлы: {leaked}")


def copy_windivert(app: Path) -> None:
    """WinDivert для вкладки «TLS» (native/windivert, вне Git; THIRD_PARTY.md — версия и
    лицензия LGPL v3) — только с ключом --windivert."""
    src = ROOT / "native" / "windivert"
    files = ("WinDivert.dll", "WinDivert64.sys")
    dst = app / "native" / "windivert"
    if "--windivert" not in sys.argv:
        shutil.rmtree(dst, ignore_errors=True)
        print("WinDivert в сборку не кладётся (ключ --windivert): Defender считает его "
              "угрозой; вкладка TLS предложит указать папку WinDivert")
        return
    if not all((src / name).is_file() for name in files):
        print("! native/windivert без WinDivert.dll и WinDivert64.sys — TLS в сборке только "
              "с WinDivert, указанным вручную")
        return
    dst.mkdir(parents=True, exist_ok=True)
    for name in (*files, "LICENSE", "THIRD_PARTY.md"):
        if (src / name).is_file():
            shutil.copy2(src / name, dst / name)


def find_signtool() -> Path | None:
    found = shutil.which("signtool")
    if found:
        return Path(found)
    kits = os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                        "Windows Kits", "10", "bin", "*", "x64", "signtool.exe")
    candidates = sorted(glob.glob(kits))
    return Path(candidates[-1]) if candidates else None


def sign(files: list[Path]) -> None:
    """Подпись Authenticode (--sign). Без сертификата — ошибка: подписать «как-нибудь»
    нельзя, а молча пропустить — значит выпустить неподписанное."""
    if "--sign" not in sys.argv or not files:
        return
    tool = find_signtool()
    if tool is None:
        raise SystemExit("Нет signtool.exe (Windows SDK) для --sign")
    args = [str(tool), "sign", "/fd", "SHA256", "/td", "SHA256",
            "/tr", os.environ.get("SBIT_SIGN_TIMESTAMP", "http://timestamp.digicert.com")]
    if os.environ.get("SBIT_SIGN_PFX"):
        args += ["/f", os.environ["SBIT_SIGN_PFX"]]
        if os.environ.get("SBIT_SIGN_PASSWORD"):
            args += ["/p", os.environ["SBIT_SIGN_PASSWORD"]]
    elif os.environ.get("SBIT_SIGN_THUMBPRINT"):
        args += ["/sha1", os.environ["SBIT_SIGN_THUMBPRINT"]]
    else:
        raise SystemExit("--sign: задайте SBIT_SIGN_PFX или SBIT_SIGN_THUMBPRINT")
    subprocess.run(args + [str(f) for f in files], check=True)
    print("Подписано:", ", ".join(f.name for f in files))


def write_sums(files: list[Path]) -> Path:
    """release/SHA256SUMS: «хэш  имя» (как sha256sum) — для проверки обновления."""
    out = ROOT / "release" / "SHA256SUMS"
    lines = {}
    if out.is_file():  # прежние строки других файлов этой версии остаются
        for line in out.read_text(encoding="utf-8").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and (ROOT / "release" / parts[1].strip()).is_file():
                lines[parts[1].strip()] = parts[0]
    for f in files:
        lines[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    out.write_text("".join(f"{sha}  {name}\n" for name, sha in sorted(lines.items())),
                   encoding="utf-8")
    return out


def make_editions() -> dict[str, Path]:
    """dist/StretchBIT → релизная; её копия dist/StretchBIT-test → тестовая."""
    folders = {}
    for edition, folder in EDITIONS.items():
        target = ROOT / "dist" / folder
        if target != DIST:
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(DIST, target)
        (target / "app" / "edition.txt").write_text(edition, encoding="utf-8")
        folders[edition] = target
    return folders


def make_zip(folder: Path) -> Path:
    out = ROOT / "release" / f"{folder.name}-{appinfo.VERSION}"
    out.parent.mkdir(exist_ok=True)
    return Path(shutil.make_archive(str(out), "zip", folder.parent, folder.name))


def find_iscc() -> Path | None:
    """ISCC.exe Inno Setup 6: PATH, Program Files, установка winget для пользователя."""
    found = shutil.which("ISCC") or shutil.which("iscc")
    if found:
        return Path(found)
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"),
                 os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs")):
        if base and (Path(base) / "Inno Setup 6" / "ISCC.exe").is_file():
            return Path(base) / "Inno Setup 6" / "ISCC.exe"
    return None


def make_installer(folder: Path, edition: str) -> Path:
    """Установщик Inno Setup из готовой папки dist/<версия> (installer.iss)."""
    iscc = find_iscc()
    if iscc is None:
        raise SystemExit("Нет Inno Setup 6 (ISCC.exe): winget install JRSoftware.InnoSetup")
    subprocess.run([str(iscc), "/Q", f"/DEdition={edition}", f"/DAppVersion={appinfo.VERSION}",
                    f"/DSourceDir={folder}", f"/DOutputDir={ROOT / 'release'}",
                    str(ROOT / "installer.iss")], check=True, cwd=ROOT)
    return ROOT / "release" / f"{folder.name}-{appinfo.VERSION}-setup.exe"


def main() -> None:
    if "--installer" in sys.argv and find_iscc() is None:
        raise SystemExit("Нет Inno Setup 6 (ISCC.exe): winget install JRSoftware.InnoSetup")
    merge_test_baseline()
    merge_test_exclusions()
    build_amsi()
    run_pyinstaller()
    copy_vpn_cores(DIST / "app")
    copy_decompilers(DIST / "app")
    copy_signatures(DIST / "app")
    copy_windivert(DIST / "app")
    sign([DIST / f"{NAME}.exe", *sorted((DIST / "app" / "native" / "amsi" / "bin").glob("*.dll"))])
    made = []
    for edition, folder in make_editions().items():
        size = sum(p.stat().st_size for p in folder.rglob("*") if p.is_file()) / 2 ** 20
        print(f"Готово ({edition}): {folder} ({size:.0f} МБ)")
        if "--zip" in sys.argv:
            made.append(make_zip(folder))
            print("Архив:", made[-1])
        if "--installer" in sys.argv:
            installer = make_installer(folder, edition)
            sign([installer])
            made.append(installer)
            print("Установщик:", installer)
    if made:
        print("Хэши:", write_sums(made))


if __name__ == "__main__":
    main()
