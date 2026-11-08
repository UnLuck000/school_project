"""Удаление программы (без настоящего удаления)."""
import uninstall


def test_uninstall_plan(tmp_path):
    names = [title for title, _ in uninstall.steps(tmp_path, test=True, wipe=False)]
    assert names[0] == "Закрыть запущенную программу"   # сначала закрыть, потом возвращать
    assert "Убрать автозапуск" in names and "Удалить ярлыки" in names
    assert uninstall.key_name(True) == "StretchBIT-test"
    assert uninstall.link_names(False) == ["StretchBIT.lnk", "Удалить StretchBIT.lnk"]
