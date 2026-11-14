"""Сведения о программе одним .zip (diag/bundle.py) и их разбор (tools/import_reports.py)."""
import json
import os
import zipfile

import pytest

from diag import bundle, edition, features
from tools import import_reports


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Свои logs/ и reports/feedback/ во временной папке: настоящие журналы не трогаем."""
    logs, feedback = tmp_path / "logs", tmp_path / "reports" / "feedback"
    logs.mkdir()
    feedback.mkdir(parents=True)
    user = os.environ.get("USERNAME", "someone")
    (logs / "app.log").write_text(f"старт из C:\\Users\\{user}\\Desktop\n", encoding="utf-8")
    (logs / "crash.log").write_text("Traceback ...\n", encoding="utf-8")
    (feedback / "comments.jsonl").write_text(
        json.dumps({"feature": "scan.file", "text": "не работает"}, ensure_ascii=False) + "\n",
        encoding="utf-8")
    (feedback / "20261109-120000_scan.png").write_bytes(b"\x89PNG fake")
    monkeypatch.setattr(bundle, "LOGS", logs)
    monkeypatch.setattr(bundle, "SERVICE_LOGS", tmp_path / "program" / "logs")
    monkeypatch.setattr(bundle, "FEEDBACK", feedback)
    monkeypatch.setattr(bundle, "_snapshot", lambda: "снимок\n")
    monkeypatch.setattr(bundle, "windows_info", lambda: {
        "caption": "Майкрософт Windows 11 Pro", "display_version": "26H2", "build": "26300",
        "ubr": 9711, "arch": "64-bit"})
    monkeypatch.setattr(features, "baseline", lambda: {"scan.file": {
        "verified_at": "2026-11-08 19:00", "version": "1.0.0-beta"}})
    monkeypatch.setattr(features, "runs", lambda: {"scan.file": {"ok": True, "time": 0,
                                                                  "duration": 1.5}})
    return tmp_path, user


def _names(path):
    with zipfile.ZipFile(path) as z:
        return set(z.namelist())


def test_test_edition_has_feedback_and_statuses(sandbox, monkeypatch):
    tmp, user = sandbox
    monkeypatch.setattr(edition, "_edition", edition.TEST)
    out = tmp / "out" / "info.zip"
    manifest = bundle.collect(out)
    names = _names(out)
    assert {"manifest.json", "snapshot.txt", "logs/app.log", "logs/crash.log",
            "feedback/comments.jsonl", "feedback/20261109-120000_scan.png",
            "features/status.json", "features/status.txt"} <= names
    assert manifest["edition"] == "test" and manifest["files"]["feedback"] == 2
    with zipfile.ZipFile(out) as z:
        log = z.read("logs/app.log").decode("utf-8")
        status = json.loads(z.read("features/status.json"))
    assert f"\\{user}\\" not in log and "%USERPROFILE%" in log      # обезличено
    assert next(s for s in status if s["id"] == "scan.file")["state"] == "verified"
    assert not out.with_name("info.zip.part").exists()


def test_release_edition_without_feedback(sandbox, monkeypatch):
    tmp, _ = sandbox
    monkeypatch.setattr(edition, "_edition", edition.RELEASE)
    out = tmp / "info.zip"
    bundle.collect(out)
    names = _names(out)
    assert "logs/app.log" in names
    assert not any(n.startswith(("feedback/", "features/")) for n in names)


def test_import_sorted_by_windows_and_time(sandbox, monkeypatch):
    tmp, _ = sandbox
    monkeypatch.setattr(edition, "_edition", edition.TEST)
    archive = tmp / "info.zip"
    bundle.collect(archive)
    dest = tmp / "user_reports"
    first = import_reports.import_zip(archive, dest, now=1_794_000_000)
    second = import_reports.import_zip(archive, dest, now=1_794_000_000)   # та же секунда
    assert first.parent == dest / "Windows 11 Pro 26H2 (26300.9711)"
    assert second != first and second.parent == first.parent
    assert (first / "logs" / "app.log").is_file()
    assert (first / "feedback" / "comments.jsonl").is_file()
    assert "комментариев: 1" in import_reports.summary(first)


def test_import_rejects_escape_and_foreign_zip(tmp_path):
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("manifest.json", json.dumps({"windows": {"caption": "Windows 10", "build": "19045"}}))
        z.writestr("../evil.txt", "x")
    target = import_reports.import_zip(bad, tmp_path / "dest")
    assert not (tmp_path / "dest" / "evil.txt").exists() and not (tmp_path / "evil.txt").exists()
    assert target.parent.name == "Windows 10 (19045)"
    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as z:
        z.writestr("readme.txt", "x")
    with pytest.raises(ValueError):
        import_reports.import_zip(other, tmp_path / "dest")


def test_service_logs_in_bundle(sandbox, monkeypatch):
    """Окно без прав пишет журналы в %LOCALAPPDATA%, служба — в папку программы: в архив
    сведений попадают оба (иначе причину сбоя службы не узнать)."""
    tmp, user = sandbox
    service_logs = tmp / "program" / "logs"
    service_logs.mkdir(parents=True)
    (service_logs / "service.log").write_text(f"Базы: из C:\\Users\\{user}\\x\n",
                                              encoding="utf-8")
    (service_logs / "service-stdout.log").write_text("VirusShare: ошибка\n", encoding="utf-8")
    (service_logs / "yara_errors.log").write_text("не служба\n", encoding="utf-8")
    monkeypatch.setattr(edition, "_edition", edition.RELEASE)
    out = tmp / "info.zip"
    manifest = bundle.collect(out)
    names = _names(out)
    assert {"service-logs/service.log", "service-logs/service-stdout.log"} <= names
    assert "service-logs/yara_errors.log" not in names and manifest["files"]["service-logs"] == 2
    with zipfile.ZipFile(out) as z:
        log = z.read("service-logs/service.log").decode("utf-8")
    assert f"\\{user}\\" not in log and "%USERPROFILE%" in log
