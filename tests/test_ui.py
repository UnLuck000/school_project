import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QPushButton

from ui.pages import AboutPage, DashboardPage, DebugPage, SettingsPage, ToolsPage
from ui.registry import FEATURES
from ui.exclusions_page import ExclusionsPage

from recovery.journal_page import JournalPage


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_pages_load(app):
    DashboardPage()
    SettingsPage()
    AboutPage()
    DebugPage(window=None)
    JournalPage()
    ExclusionsPage()


def test_every_feature_has_a_button(app):
    pages = (ToolsPage(window=None), DebugPage(window=None))
    for button_id in FEATURES:
        found = any(p.ui.findChild(QPushButton, button_id) is not None for p in pages)
        assert found, f"нет кнопки {button_id}"
