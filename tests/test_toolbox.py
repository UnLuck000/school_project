"""Отчёт о работе, USB (вирус-ярлык и восстановление), ловушки, проверка ссылок и паролей."""
import os
import subprocess
import time
from pathlib import Path

import pytest

from recovery import activity, journal


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    """Журнал, карантин и отчёт — во временной папке, не в папке программы."""
    import quarantine
    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "journal")
    monkeypatch.setattr(journal, "JOURNAL_FILE", tmp_path / "journal" / "actions.jsonl")
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", tmp_path / "quarantine")
    monkeypatch.setattr(activity, "ACTIVITY_DIR", tmp_path / "activity")
    monkeypatch.setattr(activity, "EVENTS_FILE", tmp_path / "activity" / "events.jsonl")
    monkeypatch.setattr(activity, "OUTBOX_DIR", tmp_path / "activity" / "outbox")
    return tmp_path


def test_activity_report_and_periods(sandbox, monkeypatch):
    activity.record("threat", r"C:\x\bad.exe: hash match", action="найдено")
    activity.record("scan_folder", r"C:\x: Найдено угроз: 1", found=[r"C:\x\bad.exe: Угроза"])
    activity.record("custom", "событие без раздела")
    text = activity.build_report()
    assert "Угрозы, найденные защитой файлов (1)" in text
    assert r"C:\x\bad.exe: hash match" in text  # имена файлов остаются (п. 1.3)
    assert "Сканирование папок (1)" in text and "событие без раздела" in text
    assert "== Карантин сейчас: 0 ==" in text

    day = activity.DAY
    first = 1_000_000.0
    assert activity.due_periods(first, 0, first + 2 * day) == []
    assert activity.due_periods(first, 0, first + 7 * day) == [
        (first, first + 3 * day), (first + 3 * day, first + 6 * day)]
    assert activity.due_periods(first, first + 6 * day, first + 7 * day) == []
    end = activity.prepare_outbox(time.time() - 4 * day, 0)
    assert end and len(list(activity.OUTBOX_DIR.glob("report_*.txt"))) == 1


def test_activity_anonymize(sandbox):
    env = {"USERPROFILE": r"C:\Users\Ivan", "LOCALAPPDATA": r"C:\Users\Ivan\AppData\Local",
           "APPDATA": r"C:\Users\Ivan\AppData\Roaming", "USERNAME": "Ivan",
           "COMPUTERNAME": "IVAN-PC", "PUBLIC": r"C:\Users\Public"}
    text = (r"C:\Users\ivan\Downloads\x.exe; C:\Users\Ivan\AppData\Local\Temp\a.vbs; "
            r"C:\Users\Petr\Desktop\b.exe; C:\Users\Public\c.exe; user Ivan on IVAN-PC; "
            r"Ivanov.docx")
    assert activity.anonymize(text, env) == (
        r"%USERPROFILE%\Downloads\x.exe; %LOCALAPPDATA%\Temp\a.vbs; "
        r"C:\Users\%OTHERUSER%\Desktop\b.exe; %PUBLIC%\c.exe; "
        r"user %USERNAME% on %COMPUTERNAME%; Ivanov.docx")
    activity.record("threat", os.path.join(os.environ["USERPROFILE"], "bad.exe") + ": hash")
    report = activity.build_report()
    assert os.environ["USERPROFILE"].lower() not in report.lower()
    assert r"%USERPROFILE%\bad.exe: hash" in report


def test_pwned_offline():
    from toolbox import pwned
    prefix, suffix = pwned.split_hash("password")
    assert prefix == "5BAA6" and suffix.startswith("1E4C9B93F3F0682250B6CF8331B7EE68FD8")
    response = f"0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n{suffix}:9659365\r\n"
    assert pwned.count_in_response(response, suffix) == 9659365
    assert pwned.count_in_response(response, "F" * 35) == 0


# noinspection HttpUrlsUsage
def test_link_check():
    from toolbox.linkcheck import check_url
    domains = {"evil-c2.top": "threatfox"}
    assert check_url("http://cdn.evil-c2.top/x.exe", domains, set()).level == "danger"
    assert check_url("https://github.com/a/b/releases/x.zip", domains, set()).level == "clean"
    assert check_url("http://1.2.3.4/a", domains, {"1.2.3.4"}).level == "danger"
    assert check_url("https://bank.ru@evil.example/login", domains, set()).level == "warning"


def _shortcut(path: Path, target: str, args: str) -> None:
    script = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK); "
              "$s.TargetPath = $env:TARGET; $s.Arguments = $env:ARGS; $s.Save()")
    env = dict(os.environ, LNK=str(path), TARGET=target, ARGS=args)
    subprocess.run(["powershell", "-NoProfile", "-Command", script], env=env, check=True,
                   capture_output=True, timeout=60)


def _hide(path: Path) -> None:
    from usbguard.repair import set_attributes
    from usbguard.scan import HIDDEN, SYSTEM
    set_attributes(str(path), HIDDEN | SYSTEM)


def test_usb_shortcut_virus_and_repair(sandbox):
    from usbguard import repair
    from usbguard.scan import parse_lnk, scan_drive
    drive = sandbox / "drive"
    hidden = drive / "\u00a0"                       # папка «без имени», куда вирус прячет файлы
    (hidden / "Учёба").mkdir(parents=True)
    (hidden / "Учёба" / "курсовая.docx").write_text("текст")
    (hidden / "фото.jpg").write_bytes(b"\xff\xd8")
    (hidden / "helper.vbs").write_text("WScript.Echo 1")
    _hide(hidden)
    (drive / "autorun.inf").write_text("[autorun]\nopen=wscript helper.vbs\n")
    (drive / "notes.txt").write_text("видимый файл")
    lnk = drive / "FLASH.lnk"
    _shortcut(lnk, r"C:\Windows\System32\cmd.exe",
              r'/c start wscript /e:VBScript "\u00a0\helper.vbs" & explorer "\u00a0"')
    assert parse_lnk(lnk.read_bytes()).target.lower().endswith("cmd.exe")

    report = scan_drive(str(drive))
    kinds = {(f.kind, f.level) for f in report.findings}
    assert ("shortcut", "threat") in kinds and ("autorun", "threat") in kinds
    assert ("script", "threat") in kinds and ("hidden_folder", "suspicious") in kinds
    assert report.infected and not any("notes.txt" in f.path for f in report.findings)

    done, errors = repair.apply(report.findings)
    assert not errors and done == 4
    assert (drive / "Учёба" / "курсовая.docx").exists() and (drive / "фото.jpg").exists()
    assert not lnk.exists() and not (drive / "autorun.inf").exists()
    assert not scan_drive(str(drive)).problems

    for record in reversed(journal.read_all()):  # откат возвращает всё как было
        if record["op"] in ("usb_moves", "usb_attrs"):
            journal.undo(record["id"])
    assert (hidden / "Учёба" / "курсовая.docx").exists()

    assert repair.vaccinate(str(drive)) and (drive / "autorun.inf").is_dir()
    assert not repair.vaccinate(str(drive))


def test_decoys(sandbox, monkeypatch):
    from toolbox import decoys
    monkeypatch.setattr(decoys, "MANIFEST", sandbox / "journal" / "decoys.json")
    docs = sandbox / "Documents"
    docs.mkdir()
    count = decoys.install([docs])
    assert count == len(decoys.FILES) and decoys.installed()
    assert decoys.changed_files() == []
    victim = next(iter(decoys.load_manifest()))
    Path(victim).write_bytes(b"encrypted")
    assert decoys.changed_files() == [victim]
    decoys.repair()
    assert decoys.changed_files() == []
    decoys.uninstall()
    assert not decoys.installed() and not (docs / decoys.DECOY_NAME).exists()
    journal.undo(journal.read_all()[-1]["id"])  # откат удаления — ловушки снова на месте
    assert decoys.installed() and (docs / decoys.DECOY_NAME).is_dir()


def test_decoys_auto_protected_folder(sandbox, monkeypatch):
    from toolbox import decoys
    monkeypatch.setattr(decoys, "MANIFEST", sandbox / "journal" / "decoys.json")
    monkeypatch.setattr(decoys, "default_folders", lambda: [sandbox])
    assert decoys.ensure() == len(decoys.FILES)
    folder = sandbox / decoys.DECOY_NAME
    assert decoys.is_protected(folder)                       # скрытая + системная
    files = list(decoys.load_manifest())
    assert all(not os.stat(f).st_file_attributes & 0x6 for f in files)  # файлы — обычные
    decoys.set_attributes(folder, 0)                        # папка от прежней версии
    decoys.ensure()
    assert decoys.is_protected(folder) and set(decoys.load_manifest()) == set(files)
    decoys.remove_all()
    assert not folder.exists() and not decoys.installed()


def test_usb_auto_fixes_only_for_infected():
    from usbguard.scan import DriveReport, Finding
    from usbguard.window import auto_fixes
    clean = DriveReport("E:\\", findings=[
        Finding("E:\\x.lnk", "shortcut", "info", "Ярлык"),
        Finding("E:\\run.bat", "script", "suspicious", "Скрипт", fix="quarantine"),
        Finding("E:\\\u00a0", "hidden_folder", "info", "Папка без имени", fix="restore_folder")])
    assert auto_fixes(clean) == []                          # без угроз — только уведомление
    infected = DriveReport("E:\\", findings=clean.findings + [
        Finding("E:\\FLASH.lnk", "shortcut", "threat", "Ярлык-вирус", fix="quarantine")])
    assert [f.path for f in auto_fixes(infected)] == ["E:\\\u00a0", "E:\\FLASH.lnk"]


def test_data_description_paragraphs():
    text = activity.description()
    assert "в нём нет ничего, кроме" in text                # строки абзаца склеены
    assert "\n• найденные угрозы" in text and "\n\n\n" not in text


def test_decoy_culprit_ranking(monkeypatch):
    from toolbox import decoys
    watcher = decoys.DecoyWatcher(lambda *a: None)
    watcher._history.append((0, {100: (1000, "app.exe"), 200: (0, "evil.exe"),
                                 os.getpid(): (0, "python.exe")}))
    watcher._history.append((1, {100: (1500, "app.exe"), 200: (90_000, "evil.exe"),
                                 os.getpid(): (10**9, "python.exe")}))
    monkeypatch.setattr(decoys, "_exe", lambda pid: f"C:\\x\\{pid}.exe")
    monkeypatch.setattr(decoys, "_signed", lambda exe: False)
    culprit = watcher.find_culprit()
    assert culprit["pid"] == 200 and culprit["written"] == 90_000


def test_ntsnap_written():
    from processmanager import ntsnap
    if not ntsnap.AVAILABLE:
        pytest.skip("только Windows x64")
    me = next(p for p in ntsnap.list_processes() if p.pid == os.getpid())
    assert me.written >= 0
