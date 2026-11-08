"""Отчёт о работе программы: что делал пользователь и что нашла программа.

События пишутся по мере работы в EVENTS_FILE (JSON Lines). Отчёт — текстовый файл: события
за период плюс снимки журнала действий, карантина, белого списка и исключений. Раз в
PERIOD_DAYS (отсчёт от первого запуска) готовый отчёт кладётся в OUTBOX_DIR; отправка
пока не реализована (send_report). Что именно собирается — DATA_DESCRIPTION, он же
показывается пользователю кнопкой на вкладке «Отладка».
"""
import json
import os
import platform
import re
import threading
import time
from datetime import datetime
from pathlib import Path

import appinfo

BASE_DIR = Path(__file__).resolve().parent.parent
ACTIVITY_DIR = BASE_DIR / "reports" / "activity"
EVENTS_FILE = ACTIVITY_DIR / "events.jsonl"
REPORT_FILE = ACTIVITY_DIR / "report.txt"      # текущий отчёт (кнопка «Открыть отчёт»)
OUTBOX_DIR = ACTIVITY_DIR / "outbox"           # отчёты, готовые к отправке
PERIOD_DAYS = 3
KEEP_DAYS = 90                                 # старые события удаляются
DAY = 86400

# вид события → раздел отчёта (порядок разделов — как здесь)
KINDS = {
    "threat": "Угрозы, найденные защитой файлов",
    "scan_folder": "Сканирование папок",
    "scan_file": "Сканирование файлов",
    "full_scan": "Полная проверка дисков",
    "usb": "USB-накопители: проверка и восстановление",
    "link": "Проверка ссылок и скачанных файлов",
    "decoy": "Ловушки для шифровальщиков",
    "launch": "Контроль запуска программ",
    "stealer": "Защита от стилеров (доступ к паролям браузеров)",
    "drivers": "Уязвимые драйверы",
    "extensions": "Расширения браузеров и уведомления сайтов",
    "schedule": "Плановая проверка",
    "vpn": "VPN",
    "password": "Проверка паролей по утечкам",
    "net_alert": "Сетевые оповещения",
    "integrity": "Проверка целостности (SFC/DISM)",
    "system_check": "Проверка системы",
    "update": "Обновление баз",
    "settings": "Изменение настроек",
    "access": "Дополнительные настройки и отладка (ввод пароля)",
    "program": "Запуск и завершение программы",
}

DATA_DESCRIPTION = f"""Какие данные собирает {appinfo.APP_NAME}

Программа ведёт отчёт о своей работе на этом компьютере. Отчёт хранится в папке
reports\\activity рядом с программой, его можно открыть и прочитать целиком: в нём нет
ничего, кроме перечисленного ниже.

Что попадает в отчёт:
• найденные угрозы и подозрительные файлы: путь к файлу и причина (хэш, правило YARA,
  эвристика); итоги сканирования папок и файлов;
• действия из журнала: карантин, восстановление, белый список, исключения, отключение
  автозапуска, блокировки брандмауэром, исправления системы — и их отмена;
• текущие списки карантина, белого списка и исключений;
• результаты проверки целостности Windows (SFC/DISM) и проверки системы (hosts, прокси,
  политики и т. п.): что найдено;
• проверка USB-накопителей и их восстановление; проверка ссылок (адрес ссылки и вердикт);
  срабатывания ловушек для шифровальщиков;
• сетевые оповещения: программа, адрес или домен, правило;
• проверка паролей по утечкам: только число найденных утечек — сам пароль и его хэш
  не сохраняются и никуда не передаются;
• изменения настроек программы, успешный и неудачный ввод пароля дополнительных настроек;
• время запуска и завершения программы, обновления баз;
• версия программы и Windows, характеристики компьютера: процессор, видеокарта, память,
  накопители, сетевые адаптеры (без IP- и MAC-адресов), антивирусы и брандмауэр;
• технический журнал logs\\app.log: нажатия кнопок, открытие окон, ошибки, внешние команды,
  время работы функций — для поиска неисправностей.

Чего в отчёте нет: содержимого ваших файлов, паролей, истории браузера, переписки,
нажатий клавиш, снимков экрана. Имя вашей учётной записи и компьютера в отчёт не
попадает: путь вида C:\\Users\\<имя> записывается как %USERPROFILE%, само имя — как
%USERNAME%, имя компьютера — как %COMPUTERNAME%, папки других пользователей —
%OTHERUSER%. IP-адреса компьютера (локальные и внешний) и MAC-адреса не записываются
(%MYIP%, %LANIP%, %MAC%); у VPN — ни адреса сервера (%VPNSERVER1%), ни имени профиля
(%PROFILE1%), только адреса сайтов, к которым шли запросы. Имена файлов остаются.

Раз в {PERIOD_DAYS} дня (отсчёт от первого запуска) программа готовит отчёт за прошедший
период для отправки автору программы — для исследования качества обнаружения и ложных
срабатываний в учебной работе. Отправка ещё не включена: сейчас отчёт только сохраняется
в папке reports\\activity\\outbox. Хранится не дольше {KEEP_DAYS} дней.
"""

_lock = threading.Lock()


def description() -> str:
    """DATA_DESCRIPTION абзацами: строки внутри абзаца и пункта списка склеиваются."""
    paragraphs, current = [], ""
    for line in DATA_DESCRIPTION.splitlines():
        text = line.strip()
        if not text or text.startswith("•"):
            if current:
                paragraphs.append(current)
            current = text
            if not text:
                paragraphs.append("")
        else:
            current = f"{current} {text}" if current else text
    if current:
        paragraphs.append(current)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(paragraphs)).strip()


def record(kind: str, text: str, **details) -> None:
    """Добавляет событие. Ошибки записи не мешают работе программы."""
    item = {"time": time.time(), "kind": kind, "text": text}
    if details:
        item["details"] = details
    try:
        from diag.log import get
        get("activity").info("[%s] %s%s", kind, text,
                             f" {json.dumps(details, ensure_ascii=False, default=str)}"
                             if details else "")
    except Exception:
        pass
    try:
        with _lock:
            ACTIVITY_DIR.mkdir(parents=True, exist_ok=True)
            with EVENTS_FILE.open("a", encoding="utf-8") as f:
                f.write(json.dumps(item, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def read_events(since: float = 0.0, until: float | None = None) -> list[dict]:
    try:
        lines = EVENTS_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events = []
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("time", 0) >= since and (until is None or item["time"] < until):
            events.append(item)
    return events


def trim(now: float | None = None) -> None:
    """Удаляет события старше KEEP_DAYS дней."""
    border = (now or time.time()) - KEEP_DAYS * DAY
    with _lock:
        events = read_events(border)
        try:
            tmp = EVENTS_FILE.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps(e, ensure_ascii=False, default=str) + "\n"
                                   for e in events), encoding="utf-8")
            tmp.replace(EVENTS_FILE)
        except OSError:
            pass


def _when(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%d.%m.%Y %H:%M:%S")


def _iso_to_ts(text: str) -> float:
    try:
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _detail_lines(details: dict) -> list[str]:
    lines = []
    for key, value in details.items():
        if isinstance(value, (list, tuple)):
            lines += [f"      - {v}" for v in value[:200]]
            if len(value) > 200:
                lines.append(f"      ... ещё {len(value) - 200}")
        else:
            lines.append(f"      {key}: {value}")
    return lines


def anonymize(text: str, env: dict | None = None) -> str:
    """Имя учётной записи, компьютера и папки профиля (diag.anon.anonymize_user)."""
    from diag import anon
    return anon.anonymize_user(text, env)


def build_report(since: float = 0.0, until: float | None = None) -> str:
    """Текст отчёта без имени пользователя и компьютера, без IP-адресов компьютера и
    адресов VPN-серверов, имена профилей VPN — %PROFILEn% (diag.anon.scrub). Имена файлов
    остаются как есть."""
    from diag import anon
    anon.register_vpn_profiles()
    return anon.scrub(_build_report(since, until))


def _build_report(since: float, until: float | None) -> str:
    """Текст отчёта за период [since, until). Снимки списков — на момент построения."""
    from quarantine import list_quarantine
    from recovery import journal
    from scanner import exclusions
    from scanner.whitelist import load_whitelist

    shown_until = until or time.time()  # без until — все события, даже этой миллисекунды
    from diag import edition, specs
    out = [f"Отчёт {appinfo.APP_NAME} {appinfo.VERSION} ({edition.title()} версия)",
           f"Windows: {platform.platform()}",
           f"Период: {_when(since) if since else 'с начала'} — {_when(shown_until)}",
           f"Составлен: {_when(time.time())}"]
    cached = specs.cached()
    out += ["", "== Компьютер =="] + (specs.describe(cached) if cached else
                                      ["характеристики ещё не собраны"]) + [""]

    events = read_events(since, until)
    groups: dict[str, list[dict]] = {}
    for e in events:
        groups.setdefault(e.get("kind", ""), []).append(e)
    out.append(f"== События: {len(events)} ==")
    for kind, title in list(KINDS.items()) + [(k, k) for k in groups if k not in KINDS]:
        items = groups.get(kind)
        if not items:
            continue
        out.append(f"\n--- {title} ({len(items)}) ---")
        for e in items:
            out.append(f"  [{_when(e['time'])}] {e.get('text', '')}")
            out += _detail_lines(e.get("details") or {})

    actions = [r for r in journal.read_all() if since <= _iso_to_ts(r.get("time")) < (until or float("inf"))]
    out.append(f"\n== Журнал действий за период: {len(actions)} ==")
    for r in actions:
        undone = f" (отменено {r['undone_at']})" if r.get("undone") else ""
        out.append(f"  [{r.get('time', '')}] {r.get('title', '')}{undone}")

    items = list_quarantine()
    out.append(f"\n== Карантин сейчас: {len(items)} ==")
    for m in items:
        out.append(f"  [{m.get('quarantined_at', '')}] {m.get('original_path', '')} — "
                   f"{m.get('reason', '')}")

    white = load_whitelist()
    out.append(f"\n== Белый список сейчас: {len(white)} ==")
    for sha, item in white.items():
        out.append(f"  [{item.get('added_at', '')}] {item.get('path', '')} ({sha[:16]}...)")

    excl = exclusions.items()
    out.append(f"\n== Исключения сейчас: {len(excl)} ==")
    for e in excl:
        out.append(f"  [{e['added']}] {e['category']}: {e['title']}"
                   + (f" — {e['detail']}" if e["detail"] else ""))
    return "\n".join(out) + "\n"


def write_report(path: Path = REPORT_FILE, since: float = 0.0,
                 until: float | None = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_report(since, until), encoding="utf-8-sig")  # BOM: Блокнот
    return path


def due_periods(first_run: float, last_end: float, now: float) -> list[tuple[float, float]]:
    """Завершённые периоды по PERIOD_DAYS дней от first_run, ещё не попавшие в отчёт."""
    length = PERIOD_DAYS * DAY
    start = max(first_run, last_end)
    periods = []
    while start + length <= now:
        end = first_run + ((start - first_run) // length + 1) * length
        periods.append((start, end))
        start = end
    return periods


def prepare_outbox(first_run: float, last_end: float, now: float | None = None) -> float:
    """Готовит отчёты за завершённые периоды в OUTBOX_DIR. Возвращает конец последнего."""
    now = now or time.time()
    for start, end in due_periods(first_run, last_end, now):
        name = datetime.fromtimestamp(end).strftime("report_%Y-%m-%d_%H%M.txt")
        write_report(OUTBOX_DIR / name, start, end)
        send_report(OUTBOX_DIR / name)
        last_end = end
    return last_end


def send_report(path: Path) -> bool:
    """Отправка автору. Способ ещё не выбран: отчёт остаётся в OUTBOX_DIR."""
    return False
