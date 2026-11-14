"""Релизная и тестовая версии на одном ПК (service/editions.py, installer.iss): активна одна —
другую установщик удаляет или переводит её службу в ручной запуск, окно неактивной версии
своих защит не запускает."""
import sys
from pathlib import Path

import pytest

from diag import edition
from service import editions, scm

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("ed, own, other", [
    (edition.TEST, "StretchBITService-test", "StretchBITService"),
    (edition.RELEASE, "StretchBITService", "StretchBITService-test")])
def test_names(monkeypatch, ed, own, other):
    monkeypatch.setattr(edition, "_edition", ed)
    assert editions.own_name() == own and editions.other_name() == other


def test_passive_only_in_frozen_build(monkeypatch):
    monkeypatch.setattr(editions, "other_active", lambda: True)
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert not editions.passive()           # из исходников окно — всегда своё
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert editions.passive() == (sys.platform == "win32")
    monkeypatch.setattr(editions, "other_active", lambda: False)
    assert not editions.passive()


def test_other_active_by_state(monkeypatch):
    for state, active in ((scm.RUNNING, True), (scm.START_PENDING, True),
                          (scm.STOPPED, False), (None, False)):
        info = None if state is None else {"state": state, "pid": 1, "exit_code": 0}
        monkeypatch.setattr(scm, "query", lambda name, i=info: i)
        assert editions.other_active() is active


def test_activate(monkeypatch):
    monkeypatch.setattr(edition, "_edition", edition.TEST)
    calls = []
    monkeypatch.setattr(scm, "set_start_type", lambda n, t: calls.append(("type", n, t)) or True)
    monkeypatch.setattr(scm, "stop", lambda n: calls.append(("stop", n)) or True)
    monkeypatch.setattr(scm, "start", lambda n: calls.append(("start", n)))
    monkeypatch.setattr(scm, "query", lambda n: {"state": scm.RUNNING, "pid": 1, "exit_code": 0})
    assert editions.activate(log=lambda *_: None) == 0
    assert calls == [("type", "StretchBITService", scm.SERVICE_DEMAND_START),
                     ("stop", "StretchBITService"),
                     ("type", "StretchBITService-test", scm.SERVICE_AUTO_START),
                     ("start", "StretchBITService-test")]
    monkeypatch.setattr(scm, "query", lambda n: None)   # своей службы нет
    assert editions.activate(log=lambda *_: None) == 3


def test_revive_own_only_when_other_is_gone(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    activated = []
    monkeypatch.setattr(editions, "activate", lambda log=None: activated.append(1) or 0)
    states = {}
    monkeypatch.setattr(scm, "query", lambda n: None if states.get(n) is None else
                        {"state": states[n], "pid": 0, "exit_code": 0})
    own, other = editions.own_name(), editions.other_name()
    states.update({own: scm.STOPPED, other: scm.RUNNING})
    assert not editions.revive_own()                  # другая работает — свою не трогаем
    states.update({own: scm.RUNNING, other: None})
    assert not editions.revive_own()                  # своя и так работает
    states.update({own: None})
    assert not editions.revive_own()                  # своей нет (переносная из .zip)
    states.update({own: scm.STOPPED})
    assert editions.revive_own() and activated == [1]


def test_installer_handles_other_edition():
    text = (ROOT / "installer.iss").read_text(encoding="utf-8")
    assert '#define OtherService "StretchBITService"' in text          # у тестовой
    assert '#define OtherService "StretchBITService-test"' in text     # у релизной
    assert "CreateInputOptionPage" in text and "RemoveOther();" in text
    assert "config {#OtherService} start= demand" in text
    assert "stop {#OtherService}" in text
    # тихая установка другую версию не удаляет
    assert "not WizardSilent then\n  begin\n    TakeOtherData();\n    RemoveOther();" in text


def test_single_instance_name_per_edition():
    text = (ROOT / "gui.py").read_text(encoding="utf-8")
    assert 'SingleInstance("StretchBIT-test" if edition.is_test() else "StretchBIT")' in text
