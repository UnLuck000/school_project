"""Сборка: python build_release.py [--zip] [--installer]

1. PyInstaller по myav.spec → dist/StretchBIT: StretchBIT.exe и папка app со всем остальным.
2. Рядом кладутся ядра VPN (vpn/bin) и скачанные базы (signatures) — без файлов этого
   компьютера: белого списка, исключений, отключённых правил, своей базы хэшей и ключа abuse.ch.
3. Две версии (diag/edition.py): dist/StretchBIT — релизная, dist/StretchBIT-test — тестовая
   (кнопки «✓ Исправно», «✎ Комментарий», страница «Тестирование», подробный журнал).
   Отличаются только файлом app/edition.txt.
4. Эталон исправных функций diag/baseline.json входит в обе. Перед сборкой в него
   добавляются отметки из установленной тестовой версии (C:\\Utils\\SBIT-test), если там новее,
   а в signatures/release_overrides.json и release_exclusions.json — её исключения.
5. --zip — архивы release/StretchBIT-<версия>.zip и StretchBIT-test-<версия>.zip;
   --installer — ещё и установщики ...-setup.exe (installer.py: релизная ставится в
   C:\\Utils\\SBIT, тестовая — в C:\\Utils\\SBIT-test; архив — внутри установщика).

Журналы, карантин, кэш, профили VPN, настройки и пароли отладки (debug_mode/passwords.txt)
в сборку не попадают: программа создаёт их сама на новом компьютере.
"""
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
INSTALLED_TEST = Path(r"C:\Utils\SBIT-test")
BASELINE = ROOT / "diag" / "baseline.json"
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
    theirs = overrides.merge(overrides.read_file(folder / "overrides.json"),
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


def run_pyinstaller() -> None:
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
                    "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build" / "pyinstaller"),
                    str(ROOT / "myav.spec")], check=True, cwd=ROOT)


def copy_vpn_cores(app: Path) -> None:
    src = ROOT / "vpn" / "bin"
    if not (src / "xray.exe").exists():
        print("! vpn/bin без xray.exe — VPN в сборке работать не будет")
    shutil.copytree(src, app / "vpn" / "bin", dirs_exist_ok=True)


def copy_signatures(app: Path) -> None:
    src, dst = ROOT / "signatures", app / "signatures"

    def ignore(folder: str, names: list[str]) -> set[str]:
        return {n for n in names if Path(folder) == src and n in LOCAL_ONLY}

    shutil.copytree(src, dst, ignore=ignore, dirs_exist_ok=True)
    leaked = [p for p in dst.rglob("*") if p.name in LOCAL_ONLY]
    if leaked:
        raise SystemExit(f"В сборку попали локальные файлы: {leaked}")


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


def make_installer(archive: Path, folder_name: str) -> Path:
    name = f"{folder_name}-{appinfo.VERSION}-setup"
    work = ROOT / "build" / "installer" / folder_name
    payload = work / "payload.zip"  # внутри установщика — под постоянным именем
    payload.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(archive, payload)
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
                    "--windowed", "--name", name, "--icon", str(ROOT / "ui" / "assets" / "icon.ico"),
                    "--add-data", f"{payload}{os.pathsep}.",
                    "--distpath", str(ROOT / "release"), "--workpath", str(work),
                    "--specpath", str(work), str(ROOT / "installer.py")], check=True, cwd=ROOT)
    return ROOT / "release" / f"{name}.exe"


def main() -> None:
    merge_test_baseline()
    merge_test_exclusions()
    run_pyinstaller()
    copy_vpn_cores(DIST / "app")
    copy_signatures(DIST / "app")
    for edition, folder in make_editions().items():
        size = sum(p.stat().st_size for p in folder.rglob("*") if p.is_file()) / 2 ** 20
        print(f"Готово ({edition}): {folder} ({size:.0f} МБ)")
        if "--zip" in sys.argv or "--installer" in sys.argv:
            archive = make_zip(folder)
            print("Архив:", archive)
            if "--installer" in sys.argv:
                print("Установщик:", make_installer(archive, folder.name))


if __name__ == "__main__":
    main()
