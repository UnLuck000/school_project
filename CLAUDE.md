# myav — учебный антивирус-мультитул (Python 3.12, Windows 11, PySide6)

Тема работы: «Разработка и исследование системы обнаружения вредоносного ПО для обеспечения
кибербезопасности». Это учебный проект: ответы и комментарии в коде на русском.

## Как запускать
- Вход один: `python gui.py` (рабочая папка сверху файла переключается в корень проекта:
  в проекте много относительных путей, `quarantine.py` вычисляет путь при импорте).
- Тесты: `pytest` (pytest.ini задаёт pythonpath). Часть тестов работает с реестром Windows
  во временных ветках HKCU\Software\StudyAVTest.
- Нативный модуль (энтропия на C++): `python setup.py build_ext --inplace`; без него
  работает запасной вариант на Python (`scanner/features.py`).

## Структура
- scanner/: hashing, engine (check_file: белый список → хэш → YARA → эвристика PE), yara_engine,
  heuristics, signature (WinVerifyTrust, каталоги, издатель), whitelist, exclusions
- processmanager/: диспетчер процессов (отдельное окно), colors, origin, memscan (YARA по памяти),
  enrich (фоновая проверка подписей с кэшем на диске), ntsnap (снимок процессов одним вызовом
  NtQuerySystemInformation; psutil.process_iter не использовать: O(n²) и держит GIL, интерфейс лагает)
- networkmonitor/: мониторинг соединений; monitor.py (корень): мониторинг папок (watchdog)
- autoruns/: сканер автозапуска (вкладки Всё, Реестр{Run,RunOnce,Winlogon}, Папка автозагрузки,
  Планировщик, Службы), действия с откатом
- recovery/: journal (общий журнал и откат через @undo_op), checks (hosts, прокси, WinHTTP,
  обновления, брандмауэр, BCD), policies (ограничения реестра), actions, panels, window,
  journal_page, assoc + assoc_panel (файловые ассоциации: снимки в journal/assoc_snapshots,
  сравнение, восстановление с резервной копией разделов через reg export, проверка критичных
  расширений на перехват в HKCU)
- analyzer/: анализатор файла (report, code, codeview, window); disasm (дизассемблер разделов PE
  с именами импортов, hex по страницам 64 КБ), strings + stringsview (весь файл до 256 МБ через
  mmap, категории, фильтры, экспорт CSV/TXT, таблица на QAbstractTableModel)
- ui/: боковая навигация (shell), страницы из Qt Designer (ui/designer/*.ui, загружаются
  QUiLoader), settings, theme, tray, single_instance, registry+handlers (кнопки-заглушки)
- debug_mode/ — скрытый режим отладки, в .gitignore (проверка пароля и хэши комбинаций)

## Соглашения
- Каждое изменяющее систему действие пишется в журнал (`recovery/journal.log_action`) вместе с
  данными для отмены; откат регистрируется декоратором `@undo_op`.
- Действия без возможности отката (завершение процесса, включение защиты) в журнал не пишутся.
- Значения для PowerShell передаются через переменные окружения, не подставляются в скрипт.
- Кнопки-заглушки: добавить имя в `ui/registry.py` FEATURES, функцию с `@implements("btnИмя")`
  в `ui/handlers.py`.
- Кнопки и поля из .ui нельзя переименовывать (имена используются в коде); `pytest` проверяет XML.
- Проверки Microsoft Defender из программы убраны намеренно (у части пользователей он вырезан).
- Не хранить в Git: signatures/whitelist.json, signatures/exclusions.json, signatures/feeds/,
  signatures/rules/community/, signatures/.abusech_key, journal/, cache/, logs/, debug_mode/.

## Состояние
Готово: хэши + YARA + эвристика PE + подписи, мониторинг папок и сети, карантин и белый список,
диспетчер процессов, сканер автозапуска, центр восстановления (точки, SFC/DISM, проверки,
разблокировка политик, файловые ассоциации), анализатор файла (вкладки «Код» и «Строки»
расширены), трей, один экземпляр, исключения, журнал.

## Дальше
1. Исследовательский стенд (метрики TPR/FPR по слоям), скрыт за режимом отладки.

## Осторожно
Часть кода (реестр, WinAPI через ctypes, PowerShell, Qt) писалась без запуска на Windows:
проверять тестами и вручную, любые падения смотреть в logs/gui.log.