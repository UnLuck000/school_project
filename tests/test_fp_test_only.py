"""«Ложные срабатывания» — только в тестовой версии (diag/edition)."""
from diag import edition
from recovery import journal_page


def test_goto_false_positives_only_in_test(monkeypatch):
    monkeypatch.setattr(edition, "_edition", edition.TEST)
    assert journal_page.place_of("fp_hash_restore") == "false_positives"
    monkeypatch.setattr(edition, "_edition", edition.RELEASE)
    assert journal_page.place_of("fp_hash_restore") is None
    assert journal_page.place_of("fp_rule_enable") is None
    assert journal_page.place_of("firewall_remove") == "net_block"   # остальное — как было


def test_window_not_opened_in_release(monkeypatch):
    import gui
    monkeypatch.setattr(edition, "_edition", edition.RELEASE)

    class Fake:
        fp_window = None
    gui.MainWindow.open_false_positives(Fake(), "C:/x.exe")
    assert Fake.fp_window is None                         # окно не создавалось
