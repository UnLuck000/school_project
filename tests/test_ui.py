import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QPushButton

from ui.pages import AboutPage, DashboardPage, SettingsPage, ToolsPage
from ui.registry import FEATURES


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_pages_load(app):
    DashboardPage()
    SettingsPage()
    AboutPage()


def test_every_feature_has_a_button(app):
    page = ToolsPage(window=None)
    for button_id in FEATURES:
        assert page.ui.findChild(QPushButton, button_id), f"нет кнопки {button_id}"