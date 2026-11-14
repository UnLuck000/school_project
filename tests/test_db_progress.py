"""Шкала обновления баз на главной: доля готовности updater.update_all и карточка."""
import pytest
from PySide6.QtWidgets import QApplication

import updater


@pytest.fixture
def qapp():
    return QApplication.instance() or QApplication([])


def test_update_all_fraction_grows_to_one(monkeypatch):
    for name in ("update_ips", "update_domains", "update_drivers", "update_hashes",
                 "update_threatfox"):
        monkeypatch.setattr(updater, name, lambda: True)

    def rules(part=None):
        for i in range(4):
            part(i / 4)
        return True

    def virusshare(progress=None, part=None):
        for i in range(10):
            part(i / 10)
        return True
    monkeypatch.setattr(updater, "update_rules", rules)
    monkeypatch.setattr(updater, "update_virusshare", virusshare)
    values = []
    assert updater.update_all(fraction=values.append)
    assert values == sorted(values)               # шкала не прыгает назад
    assert values[0] == 0.0 and values[-1] == 1.0
    assert len(set(values)) > 15                  # внутри правил и VirusShare — по частям


def test_update_all_failing_step_still_moves(monkeypatch):
    def broken():
        raise OSError("нет сети")
    for name in ("update_ips", "update_domains", "update_drivers", "update_hashes",
                 "update_threatfox"):
        monkeypatch.setattr(updater, name, broken)
    monkeypatch.setattr(updater, "update_rules", lambda part=None: False)
    monkeypatch.setattr(updater, "update_virusshare", lambda progress=None, part=None: False)
    values = []
    assert not updater.update_all(fraction=values.append)
    assert values[-1] == 1.0


def test_dashboard_card(qapp):
    from ui.pages import DashboardPage
    page = DashboardPage()
    info = {"protection": True, "network": True, "quarantine": 0, "whitelist": 0,
            "last_scan": "", "db_updated": 0, "db_updating": True, "db_progress": 0.4,
            "events": []}
    page.refresh(info)
    label = page.labels["databases"]
    assert not page.db_bar.isHidden() and page.db_bar.value() == 400
    first = label.text()
    page._tick_db_dots()
    page._tick_db_dots()
    texts = {first, label.text()}
    assert all(t.startswith("Обновляются") for t in texts) and len(texts) == 2
    page.set_db_progress(0.75)
    assert page.db_bar.value() == 750
    page.refresh(dict(info, db_updating=False, db_updated=1_800_000_000))
    assert page.db_bar.isHidden() and not page._db_timer.isActive()
    assert label.text().startswith("обновлены")
