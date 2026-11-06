"""Плановая проверка: когда запускать (только расчёт, без Qt).

Настройки (ui/settings.py): schedule/enabled, schedule/kind (full | quick),
schedule/period (1w | 2w | 1m | 3m), schedule/time («ЧЧ:ММ», от 00:00 до 23:59),
schedule/last_run (секунды с 1970 года), schedule/postponed (до какого времени отложена).

Следующий запуск = последний запуск + период, в выбранное время суток. Если компьютер был
выключен в нужный момент, проверка не теряется: она начнётся при следующей возможности
(после предупреждения за WARN_SECONDS). Первая проверка после включения расписания —
в ближайшее выбранное время.
"""
import calendar
from datetime import datetime, timedelta

PERIODS = {"1w": "Каждую неделю", "2w": "Каждые 2 недели", "1m": "Каждый месяц",
           "3m": "Каждые 3 месяца"}
KINDS = {"full": "Полная проверка", "quick": "Быстрая проверка"}
WARN_SECONDS = 10 * 60  # предупреждение за 10 минут
POSTPONE_SECONDS = 3600


def add_period(moment: datetime, period: str) -> datetime:
    if period == "1w":
        return moment + timedelta(weeks=1)
    if period == "2w":
        return moment + timedelta(weeks=2)
    months = 3 if period == "3m" else 1
    month = moment.month - 1 + months
    year = moment.year + month // 12
    month = month % 12 + 1
    day = min(moment.day, calendar.monthrange(year, month)[1])  # 31 января → 28/29 февраля
    return moment.replace(year=year, month=month, day=day)


def parse_time(text: str) -> tuple[int, int]:
    try:
        hours, minutes = (int(x) for x in str(text).split(":")[:2])
    except ValueError:
        return 12, 0
    if hours == 24:  # «24:00» — это полночь
        hours = 0
    return max(0, min(23, hours)), max(0, min(59, minutes))


def next_run(last_run: float, period: str, time_text: str, now: float,
             postponed: float = 0.0) -> float:
    """Время следующей проверки (секунды с 1970 года)."""
    hours, minutes = parse_time(time_text)
    current = datetime.fromtimestamp(now)
    if last_run <= 0 or last_run > now:  # ещё не было (или часы перевели назад)
        due = current.replace(hour=hours, minute=minutes, second=0, microsecond=0)
        if due.timestamp() < now:
            due += timedelta(days=1)
    else:
        due = add_period(datetime.fromtimestamp(last_run), period).replace(
            hour=hours, minute=minutes, second=0, microsecond=0)
    result = due.timestamp()
    if postponed > result:
        result = postponed
    return result


def describe(when: float, now: float) -> str:
    moment = datetime.fromtimestamp(when)
    if when <= now:
        return "пропущена, начнётся после предупреждения"
    days = (moment.date() - datetime.fromtimestamp(now).date()).days
    day = {0: "сегодня", 1: "завтра"}.get(days, moment.strftime("%d.%m.%Y"))
    return f"{day} в {moment:%H:%M}"
