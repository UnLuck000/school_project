"""Перенос данных другой версии (service/transfer.py): сам — в пустую папку, по просьбе
установщика — с заменой; пути, подписи журнала, списки доверия, состояние VPN."""
import json
from pathlib import Path

import pytest

import trustseal
from recovery.journal import signature_with
from service import transfer

ROOT = Path(__file__).resolve().parent.parent
OTHER_KEY = b"k" * 32
OWN_KEY = b"o" * 32


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    src = tmp_path / "Roaming" / "StretchBitConfiguration"
    dst = tmp_path / "Roaming" / "StretchBitConfiguration-test"
    root = tmp_path / "ProgramData" / "StretchBIT"
    (src / "journal").mkdir(parents=True)
    root.mkdir(parents=True)
    (root / "cache.key").write_bytes(OTHER_KEY)
    monkeypatch.setattr(transfer, "_root_secured", lambda r: True)
    monkeypatch.setattr(transfer, "_own_key", lambda: OWN_KEY)
    saved = []
    monkeypatch.setattr(trustseal, "saved", lambda p: saved.append(Path(p).name))
    return src, dst, root, saved


def _record(src: Path, key: bytes | None, rid: str) -> dict:
    rec = {"id": rid, "time": "2026-11-14T10:00:00", "title": "t", "op": "ext_remove",
           "data": {"backup": str(src / "journal" / "ext_backup" / "a.zip")},
           "undone": False, "undone_at": ""}
    if key:
        rec["mac"] = signature_with(rec, key)
    return rec


def test_auto_into_empty_and_once(dirs):
    src, dst, root, saved = dirs
    (src / "settings.ini").write_text("[general]\ntheme=night\n", encoding="utf-8")
    (src / "whitelist.json").write_text("[]", encoding="utf-8")
    lines = transfer.transfer(src, dst, root)
    assert lines and (dst / "settings.ini").read_text(encoding="utf-8").endswith("night\n")
    assert (dst / transfer.DONE).read_text(encoding="utf-8") == "auto"
    assert saved == ["whitelist.json"]
    (src / "settings.ini").write_text("[general]\ntheme=light\n", encoding="utf-8")
    assert transfer.transfer(src, dst, root) == []           # свои данные уже есть
    assert "night" in (dst / "settings.ini").read_text(encoding="utf-8")


def test_request_replaces_and_keeps_own(dirs):
    src, dst, root, _ = dirs
    dst.mkdir(parents=True)
    (dst / "settings.ini").write_text("own", encoding="utf-8")
    (src / "settings.ini").write_text("theirs", encoding="utf-8")
    assert transfer.transfer(src, dst, root, stamp="20261114153000")
    assert (dst / "settings.ini").read_text(encoding="utf-8") == "theirs"
    assert (dst / "before-20261114153000" / "settings.ini").read_text(encoding="utf-8") == "own"
    (dst / "settings.ini").write_text("changed later", encoding="utf-8")
    assert transfer.transfer(src, dst, root, stamp="20261114153000") == []  # один раз


def test_paths_and_journal_signatures(dirs):
    src, dst, root, _ = dirs
    good, forged, plain = (_record(src, OTHER_KEY, "a"), _record(src, b"x" * 32, "b"),
                           _record(src, None, "c"))
    (src / "journal" / "actions.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in (good, forged, plain)),
        encoding="utf-8")
    threats = {"items": [{"path": str(src / "journal" / "x"),
                          "other": str(dst / "keep")}]}   # путь тестовой не задевается
    (src / "journal" / "threats.json").write_text(json.dumps(threats), encoding="utf-8")
    transfer.transfer(src, dst, root)
    recs = [json.loads(x) for x in
            (dst / "journal" / "actions.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(str(dst) in r["data"]["backup"] for r in recs)
    assert recs[0]["mac"] == signature_with(recs[0], OWN_KEY)      # переподписана своим
    assert recs[1]["mac"] == forged["mac"]                        # подделка остаётся подделкой
    assert "mac" not in recs[2]
    moved = json.loads((dst / "journal" / "threats.json").read_text(encoding="utf-8"))
    assert moved["items"][0]["path"] == str(dst / "journal" / "x")
    assert moved["items"][0]["other"] == str(dst / "keep")


def test_unverifiable_signature_is_dropped(dirs, monkeypatch):
    src, dst, root, _ = dirs
    monkeypatch.setattr(transfer, "_root_secured", lambda r: False)   # чужой корень — ключу не верим
    (src / "journal" / "actions.jsonl").write_text(
        json.dumps(_record(src, OTHER_KEY, "a")) + "\n", encoding="utf-8")
    transfer.transfer(src, dst, root)
    rec = json.loads((dst / "journal" / "actions.jsonl").read_text(encoding="utf-8"))
    assert "mac" not in rec          # отмена спросит пользователя


def test_sealed_files_from_protected_copy(dirs):
    import hashlib
    import os
    src, dst, root, _ = dirs
    (root / "trusted").mkdir()
    (root / "trusted" / ".initialized").write_text("1")
    for name, body in (("whitelist.json", '["evil"]'), ("exclusions.json", '["x"]')):
        (src / name).write_text(body, encoding="utf-8")
    tag = hashlib.sha256(os.path.normcase(str(src / "whitelist.json")).encode()).hexdigest()[:10]
    (root / "trusted" / f"whitelist.json.{tag}").write_text("[]", encoding="utf-8")
    lines = transfer.transfer(src, dst, root)
    assert (dst / "whitelist.json").read_text(encoding="utf-8") == "[]"   # защищённая копия
    assert not (dst / "exclusions.json").exists()      # у другой версии появился не из программы
    assert any("exclusions.json" in line for line in lines)


def test_vpn_recovery_state_dropped(dirs):
    src, dst, root, _ = dirs
    (src / "settings.ini").write_text(
        "[vpn]\nkillswitch_backup=x\nlast_profile=p\ndns_backup=y\n[other]\ndns_backup=keep\n",
        encoding="utf-8")
    transfer.transfer(src, dst, root)
    text = (dst / "settings.ini").read_text(encoding="utf-8")
    assert "killswitch_backup" not in text and "last_profile=p" in text
    assert text.count("dns_backup") == 1


def test_nothing_to_take(dirs):
    src, dst, root, _ = dirs
    (src / "journal").rmdir()
    assert transfer.transfer(src, dst, root, stamp="1") == []
    assert (dst / transfer.DONE).read_text(encoding="utf-8") == "1"


def test_requested_marker(tmp_path):
    assert transfer.requested(tmp_path) == ""
    (tmp_path / transfer.MARKER).write_text("20261114153000\r\n", encoding="utf-8")
    assert transfer.requested(tmp_path) == "20261114153000"
    (tmp_path / transfer.MARKER).write_text("..\\..\\x y", encoding="utf-8")
    assert transfer.requested(tmp_path) == ""


def test_only_in_frozen_build():
    assert transfer.window() == [] and transfer.service(ROOT / "nowhere") == []


def test_installer_takes_data_before_removal():
    text = (ROOT / "installer.iss").read_text(encoding="utf-8")
    body = text[text.index("function PrepareToInstall"):]
    assert body.index("DeactivateOther();") < body.index("TakeOtherData();") < \
        body.index("RemoveOther();") < body.index("RequestTransfer();")
    assert "transfer_from.txt" in text and "quarantine_data" in text
