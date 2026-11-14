"""Релизная и тестовая версии на одном ПК (14.11.2026): у каждой своя служба
(StretchBITService и StretchBITService-test), но часть системных имён общая — сеансы ETW
sbit-proc/sbit-files/sbit-dns, канал AMSI, правила брандмауэра «SBIT» и kill switch, пункт меню
Проводника. Две работающие службы мешали друг другу: запущенная второй забирала сеансы ETW
первой, и у той молча переставали работать контроль запуска, защита от стилеров и DNS.

Поэтому активна одна версия. Установщик (installer.iss) находит другую и предлагает её удалить;
если пользователь отказался — останавливает её службу и переводит в ручной запуск. Окно
неактивной версии (её служба не отвечает, а служба другой версии работает) — пассивное: своих
защит, мониторинга сети и VPN не запускает, автозапуск и меню Проводника не трогает, а
«Включить защиту» предлагает сделать эту версию основной (activate, с правами через UAC).

    StretchBIT.exe --service-activate   — служба этой версии — автозапуск и работает,
                                          служба другой — остановлена, ручной запуск
"""
import sys

from diag import edition


def own_name() -> str:
    from service import protocol
    return protocol.service_name()


def other_name() -> str:
    return "StretchBITService" + ("" if edition.is_test() else "-test")


def other_title() -> str:
    """Как называть другую версию пользователю."""
    return "StretchBIT (релизная)" if edition.is_test() else "StretchBIT (тест)"


def other_active() -> bool:
    """Служба другой версии работает (или запускается)."""
    from service import scm
    info = scm.query(other_name())
    return bool(info) and info["state"] in (scm.START_PENDING, scm.RUNNING)


def passive() -> bool:
    """Окно этой версии не должно запускать свои защиты: служба другой версии работает.
    Только в собранной программе: из исходников (python gui.py) окно — всегда своё
    (разработка на ПК, где стоит собранная версия)."""
    if not getattr(sys, "frozen", False) or sys.platform != "win32":
        return False
    try:
        return other_active()
    except OSError:
        return False


def revive_own() -> bool:
    """Своя служба установлена, но остановлена (её переводили в ручной запуск ради другой
    версии, а ту потом удалили), и другая не работает: вернуть свою — автозапуск и запуск.
    Нужны права администратора. True — служба запущена, окну подключаться к ней."""
    if not getattr(sys, "frozen", False) or sys.platform != "win32":
        return False
    from service import scm
    try:
        info = scm.query(own_name())
        if info is None or info["state"] != scm.STOPPED or other_active():
            return False
        return activate(log=lambda *_: None) == 0
    except OSError:
        return False


def activate(log=print) -> int:
    """Сделать эту версию основной (нужны права администратора): служба другой версии —
    остановить и в ручной запуск, своя — автозапуск и запустить. 0 — успех."""
    from service import scm
    other, own = other_name(), own_name()
    if scm.set_start_type(other, scm.SERVICE_DEMAND_START):
        scm.stop(other)
        log(f"Служба {other} остановлена и переведена в ручной запуск")
    if scm.query(own) is None:
        log(f"Служба {own} не установлена — переустановите программу установщиком")
        return 3
    scm.set_start_type(own, scm.SERVICE_AUTO_START)
    scm.start(own)
    import time
    deadline = time.monotonic() + 30  # окно после этого переподключается к службе
    while time.monotonic() < deadline:
        info = scm.query(own)
        if info and info["state"] == scm.RUNNING:
            break
        time.sleep(0.3)
    log(f"Служба {own} запущена (автозапуск)")
    return 0
