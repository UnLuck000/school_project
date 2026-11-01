import os
import uuid

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from ui.debug_mode import DebugKeyWatcher
from ui.single_instance import SingleInstance


class FakeGate:
    def check(self, typed: str) -> bool:
        return typed.endswith("xyzzy")


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_combination_triggers_once(app):
    watcher = DebugKeyWatcher(FakeGate())
    hits = []
    watcher.triggered.connect(lambda: hits.append(1))
    for ch in "abxyzzy":  # лишние символы перед комбинацией допустимы
        watcher.feed(ch)
    assert hits == [1]
    assert watcher.buffer == ""


def test_reset_clears_partial_input(app):
    watcher = DebugKeyWatcher(FakeGate())
    hits = []
    watcher.triggered.connect(lambda: hits.append(1))
    for ch in "xyz":
        watcher.feed(ch)
    watcher.reset()  # то же, что сброс через 1,5 секунды
    for ch in "zy":
        watcher.feed(ch)
    assert hits == []


def test_without_gate_nothing_happens(app):
    assert DebugKeyWatcher(None).feed("anything") is False


def test_single_instance(app):
    name = f"StudyAV-test-{uuid.uuid4().hex}"
    first = SingleInstance(name)
    assert first.listen()
    assert SingleInstance(name).already_running(notify=False)

def test_password_gate_set_check_remove(tmp_path):
    from ui.debug_mode import PasswordGate
    gate = PasswordGate(tmp_path / "passwords.txt")
    assert not gate.has_password() and not gate.check("anything")
    with pytest.raises(ValueError):
        gate.set_password("123")
    gate.set_password("Secret1")
    assert gate.has_password()
    assert gate.check("abcSECRET1")  # регистр не важен, лишние символы перед паролем допустимы
    assert PasswordGate(tmp_path / "passwords.txt").check("secret1")  # сохранён на диск
    gate.remove_password()
    assert not gate.has_password() and not (tmp_path / "passwords.txt").exists()
