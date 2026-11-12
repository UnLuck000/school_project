"""Разбор присланных архивов «Сведения о программе» (diag/bundle.py) у разработчика.

    python tools/import_reports.py <архив.zip> [ещё архивы или папки с ними] [--to ПАПКА]

Каждый архив распаковывается в
    user_reports/<Windows>/<дата_время разбора>/
        manifest.json, snapshot.txt, logs/ ...           — любая версия
        feedback/, features/                              — только тестовая
<Windows> — из manifest.json архива, например «Windows 11 Pro 26H2 (26300.9711)»;
дата и время — когда архив прислан (разобран), а не когда собран (это в manifest.json).
Папка user_reports — вне Git (в архивах журналы чужих компьютеров).
"""
import argparse
import json
import re
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "user_reports"
UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def windows_folder(manifest: dict) -> str:
    win = manifest.get("windows") or {}
    caption = re.sub(r"^(Майкрософт|Microsoft)\s+", "", str(win.get("caption") or "Windows"),
                     flags=re.I).strip()
    parts = [caption]
    if win.get("display_version"):
        parts.append(str(win["display_version"]))
    build = str(win.get("build") or "")
    if build:
        parts.append(f"({build}.{win['ubr']})" if win.get("ubr") is not None else f"({build})")
    name = UNSAFE.sub("_", " ".join(parts)).strip(" .")
    return name or "Windows (неизвестно)"


def _free(folder: Path) -> Path:
    """Два архива в одну секунду — вторая папка с суффиксом."""
    if not folder.exists():
        return folder
    n = 2
    while folder.with_name(f"{folder.name}_{n}").exists():
        n += 1
    return folder.with_name(f"{folder.name}_{n}")


def import_zip(archive: Path, dest: Path = DEST, now: float | None = None) -> Path:
    with zipfile.ZipFile(archive) as z:
        try:
            manifest = json.loads(z.read("manifest.json").decode("utf-8"))
        except KeyError:
            raise ValueError(f"{archive.name}: нет manifest.json — это не архив сведений "
                             "StretchBIT") from None
        stamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime(now))
        target = _free(dest / windows_folder(manifest) / stamp)
        target.mkdir(parents=True)
        for info in z.infolist():
            rel = PurePosixPath(info.filename.replace("\\", "/"))
            if rel.is_absolute() or ".." in rel.parts or ":" in info.filename:
                continue                        # путь за пределы папки — не распаковываем
            out = target.joinpath(*rel.parts)
            if info.is_dir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(out, "wb") as dst:
                while chunk := src.read(1 << 20):
                    dst.write(chunk)
    (target / "source.txt").write_text(
        f"Архив: {archive.name}\nРазобран: {time.strftime('%d.%m.%Y %H:%M:%S', time.localtime(now))}\n"
        f"Собран: {manifest.get('created')}\nВерсия: {manifest.get('version')} "
        f"({manifest.get('edition')})\n", encoding="utf-8")
    return target


def summary(folder: Path) -> str:
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    lines = [f"{folder}", f"  {manifest.get('app')} {manifest.get('version')} "
             f"({manifest.get('edition')}), собран {manifest.get('created')}",
             f"  файлов: {manifest.get('files')}"]
    status = folder / "features" / "status.json"
    if status.is_file():
        items = json.loads(status.read_text(encoding="utf-8"))
        bad = [i["title"] for i in items if i["state"] == "error"]
        counts = {}
        for i in items:
            counts[i["state"]] = counts.get(i["state"], 0) + 1
        lines.append(f"  функции: {counts}" + (f"; с ошибкой: {', '.join(bad)}" if bad else ""))
    comments = folder / "feedback" / "comments.jsonl"
    if comments.is_file():
        n = sum(1 for line in comments.read_text(encoding="utf-8").splitlines() if line.strip())
        lines.append(f"  комментариев: {n}")
    crash = folder / "logs" / "crash.log"
    if crash.is_file() and crash.stat().st_size:
        lines.append(f"  crash.log: {crash.stat().st_size} байт — есть аварийные записи")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", type=Path, help="архивы .zip или папки с ними")
    parser.add_argument("--to", type=Path, default=DEST, help="куда раскладывать")
    args = parser.parse_args(argv)
    archives = []
    for p in args.paths:
        archives += sorted(p.glob("*.zip")) if p.is_dir() else [p]
    failed = 0
    for archive in archives:
        try:
            print(summary(import_zip(archive, args.to)))
        except (OSError, ValueError, zipfile.BadZipFile) as e:
            print(f"! {archive}: {e}", file=sys.stderr)
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
