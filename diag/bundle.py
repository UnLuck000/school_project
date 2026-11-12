"""Сведения о программе одним .zip — для разработчика (кнопка на странице «Настройки»).

Состав архива:
    manifest.json  — программа, версия, издание (test/release), Windows, время сбора;
    snapshot.txt   — настройки, отличные от стандартных, базы, ядра VPN, мешающие программы,
                     характеристики компьютера (diag/snapshot, diag/specs);
    logs/          — всё из logs/ (app.log с ротацией, crash.log, session.json, specs.json,
                     feature_runs.json, yara_errors.log...);
  только тестовая версия (diag/edition.is_test):
    feedback/      — комментарии testpanel (comments.jsonl, .log, снимки .png);
    features/      — статусы функций: status.json и status.txt (как на странице
                     «Тестирование»), эталон «Исправно» baseline.json.

Текстовые файлы ещё раз проходят diag.anon.scrub: app.log обезличен при записи, но crash.log
(faulthandler) и старые журналы — нет. Снимки экрана (.png) — как есть.
Разбор присланного архива у разработчика — tools/import_reports.py.
"""
import json
import platform
import time
import zipfile
from pathlib import Path

import appinfo
from diag import edition, features
from diag.anon import scrub

LOGS = Path("logs")
FEEDBACK = Path("reports") / "feedback"
TEXT_EXTS = {".log", ".txt", ".json", ".jsonl", ".csv"}
MAX_FILE = 64 * 2 ** 20   # больше — обрезается до последних MAX_FILE байт (журнал разросся)


def default_name(now: float | None = None) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    return f"logs-{appinfo.SHORT_NAME}-v{appinfo.VERSION}-{stamp}.zip"


def windows_info() -> dict:
    """Версия Windows: из кэша diag/specs (без нового сбора), иначе platform."""
    from diag import specs
    data = (specs.cached() or {}).get("os") or {}
    if data.get("build"):
        return {"caption": data.get("caption", ""), "display_version": data.get("display_version", ""),
                "build": str(data.get("build", "")), "ubr": data.get("ubr"),
                "arch": data.get("arch", "")}
    ver = platform.version()            # 10.0.26100
    build = ver.rsplit(".", 1)[-1]
    caption = f"Windows {'11' if build.isdigit() and int(build) >= 22000 else platform.release()}"
    return {"caption": caption, "display_version": "", "build": build, "ubr": None,
            "arch": platform.machine()}


def feature_status() -> list[dict]:
    """Статус каждой функции: как точка на странице «Тестирование»."""
    runs, ref = features.runs(), features.baseline()
    out = []
    for f in features.FEATURES.values():
        last, base = runs.get(f.id), ref.get(f.id)
        if last and last.get("ok") is False:
            state = "error"
        elif base:
            state = "verified"
        elif last:
            state = "ran"
        else:
            state = "not_run"
        out.append({"id": f.id, "title": f.title, "area": f.area, "state": state,
                    "last_run": last, "verified": base})
    return out


STATE_TEXT = {"error": "ОШИБКА", "verified": "исправно (отмечено)",
              "ran": "запускалось, не отмечено", "not_run": "не запускалось"}


def _status_text(items: list[dict]) -> str:
    lines = []
    for it in items:
        line = f"[{STATE_TEXT[it['state']]}] {it['title']} ({it['id']}, {it['area']})"
        last = it.get("last_run")
        if last:
            when = time.strftime("%d.%m.%Y %H:%M", time.localtime(last.get("time", 0)))
            line += f"\n    последний запуск {when}, {last.get('duration')} с"
            if last.get("errors"):
                line += ": " + "; ".join(last["errors"])
        if it.get("verified"):
            v = it["verified"]
            line += f"\n    отмечено исправным {v.get('verified_at')} (версия {v.get('version')})"
        lines.append(line)
    return "\n".join(lines) + "\n"


def _read(path: Path) -> bytes:
    with open(path, "rb") as f:
        size = f.seek(0, 2)
        f.seek(max(0, size - MAX_FILE))
        return f.read()


def _add_file(z: zipfile.ZipFile, path: Path, arcname: str) -> None:
    data = _read(path)
    if path.suffix.lower() in TEXT_EXTS:
        data = scrub(data.decode("utf-8", errors="replace")).encode("utf-8")
        z.writestr(arcname, data, zipfile.ZIP_DEFLATED)
    else:
        z.writestr(arcname, data, zipfile.ZIP_STORED if path.suffix.lower() == ".png"
                   else zipfile.ZIP_DEFLATED)


def _add_folder(z: zipfile.ZipFile, folder: Path, prefix: str, progress=None) -> int:
    count = 0
    if not folder.is_dir():
        return 0
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        try:
            _add_file(z, path, f"{prefix}/{path.relative_to(folder).as_posix()}")
            count += 1
            if progress:
                progress(f"{prefix}/{path.name}")
        except OSError:
            continue  # файл занят или исчез — без него
    return count


def _snapshot() -> str:
    lines = []
    try:
        from diag import snapshot
        lines += snapshot.lines()
    except Exception as e:  # noqa: BLE001 — сбор сведений не должен падать
        lines.append(f"Снимок не собран: {e}")
    try:
        from diag import specs
        lines += ["", "Компьютер:"] + ["  " + s for s in specs.describe(specs.cached())]
    except Exception as e:  # noqa: BLE001
        lines.append(f"Характеристики не собраны: {e}")
    return scrub("\n".join(lines)) + "\n"


def collect(target: Path, progress=None) -> dict:
    """Собрать архив в target. Возвращает manifest (с числом файлов по разделам)."""
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    # что скрывать: свои адреса, профили и серверы VPN (vpn/last_profile в снимке настроек,
    # старые строки журналов, записанные до регистрации) — повторная регистрация безвредна
    from diag import anon
    anon.register_adapters()
    anon.register_vpn_profiles()
    test = edition.is_test()
    manifest = {
        "app": appinfo.APP_NAME, "version": appinfo.VERSION, "edition": edition.edition(),
        "frozen": features.is_frozen(),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "windows": windows_info(),
        "files": {},
    }
    tmp = target.with_name(target.name + ".part")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        manifest["files"]["logs"] = _add_folder(z, LOGS, "logs", progress)
        z.writestr("snapshot.txt", _snapshot())
        if test:
            manifest["files"]["feedback"] = _add_folder(z, FEEDBACK, "feedback", progress)
            items = feature_status()
            z.writestr("features/status.json", json.dumps(items, ensure_ascii=False, indent=1))
            z.writestr("features/status.txt", _status_text(items))
            if features.BASELINE_FILE.is_file():
                _add_file(z, features.BASELINE_FILE, "features/baseline.json")
            manifest["files"]["features"] = len(items)
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1))
    tmp.replace(target)
    return manifest
