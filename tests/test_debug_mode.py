import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from ui.debug_mode import DEFAULT_HINT, PasswordGate
from ui.single_instance import SingleInstance


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_single_instance(app):
    name = f"StudyAV-test-{uuid.uuid4().hex}"
    first = SingleInstance(name)
    assert first.listen()
    assert SingleInstance(name).already_running(notify=False)


def test_password_gate_set_check_remove(tmp_path):
    gate = PasswordGate(tmp_path / "passwords.txt", default=("", ""))
    assert not gate.has_password() and not gate.check("anything")
    with pytest.raises(ValueError):
        gate.set_password("123")
    gate.set_password("Secret1")
    assert gate.has_password()
    assert gate.check("SECRET1")             # регистр не важен
    assert not gate.check("abcSECRET1")      # лишние символы — уже другой пароль
    assert PasswordGate(tmp_path / "passwords.txt", default=("", "")).check("secret1")
    gate.remove_password()
    assert not gate.has_password() and not (tmp_path / "passwords.txt").exists()


def test_default_password(tmp_path):
    gate = PasswordGate(tmp_path / "passwords.txt")
    assert gate.has_default() and not gate.has_own_password()
    assert gate.check(DEFAULT_HINT) and gate.check("1QAZ2WSX3EDC")
    with pytest.raises(ValueError):  # без своего пароля убрать пароль по умолчанию нельзя
        gate.set_default_enabled(False)
    gate.set_password("my-secret")
    assert gate.check("my-secret") and gate.check(DEFAULT_HINT)


def test_default_password_can_be_removed_and_restored(tmp_path):
    path = tmp_path / "passwords.txt"
    gate = PasswordGate(path)
    gate.set_password("my-secret")
    gate.set_default_enabled(False)
    assert not gate.has_default() and not gate.check(DEFAULT_HINT) and gate.check("my-secret")
    again = PasswordGate(path)                # сохранено на диск
    assert not again.has_default() and again.check("my-secret")
    with pytest.raises(ValueError):           # иначе не останется ни одного пароля
        again.remove_password()
    again.set_password("other-secret")        # смена своего пароля не возвращает умолчание
    assert not again.has_default() and again.check("other-secret")
    again.set_default_enabled(True)
    assert again.has_default() and again.check(DEFAULT_HINT)
    again.remove_password()
    assert not path.exists() and PasswordGate(path).has_default()


def test_tool_locks(monkeypatch):
    from ui import access, settings
    values = dict(settings.DEFAULTS)
    monkeypatch.setattr(settings, "get", values.__getitem__)
    # у каждого инструмента своя галочка; по умолчанию запрещены только эти четыре
    from ui.registry import FEATURES
    locked = {"btnRestorePoint", "btnSfcDism", "btnMemoryDeep", "btnUsb"}
    assert set(access.TOOL_LOCKS) <= set(FEATURES)
    for button in access.TOOL_LOCKS:
        assert access.allowed(button) == (button not in locked), button
    assert not access.protection_locked() and not access.network_locked()
    values["lock/sfc_dism"] = False
    values["lock/autoruns"] = True
    assert access.allowed("btnSfcDism") and not access.allowed("btnRestorePoint")
    assert not access.allowed("btnAutoruns") and access.allowed("btnProcessManager")


def test_every_tool_has_lock_checkbox():
    """Галочка запрета есть у каждой кнопки страницы «Инструменты»."""
    import re
    from pathlib import Path
    from ui import access
    from ui.pages import SettingsPage
    tools = set(re.findall(r'name="(btn\w+)"', Path("ui/designer/tools_page.ui").read_text(
        encoding="utf-8"))) - {"btnRelaunchAdmin"}
    assert tools == set(access.TOOL_LOCKS)
    assert set(SettingsPage().locks) >= set(access.TOOL_LOCKS.values())
