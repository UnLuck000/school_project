"""Какие изменения файлов присылает watchdog на Windows.

watchdog подписывается на ReadDirectoryChangesW со всеми флагами, в том числе
FILE_NOTIFY_CHANGE_LAST_ACCESS, ATTRIBUTES и SECURITY. В Windows 11 обновление времени
последнего доступа включено (fsutil behavior query disablelastaccess = 2), поэтому любое
ЧТЕНИЕ файла — запуск программы, загрузка библиотеки, индексатор, чужой антивирус —
приходило событием «изменён». Защита файлов проверяла давно не менявшиеся файлы, а
журнал защиты заполнялся «OK» на одни и те же библиотеки.

Оставляем только то, что меняет содержимое или имя: создание, переименование, удаление,
запись и размер. Флаги читаются при каждом вызове ReadDirectoryChangesW, поэтому
use_content_flags() достаточно вызвать до запуска наблюдателя.
"""
import os

FILE_NOTIFY_CHANGE_FILE_NAME = 0x01
FILE_NOTIFY_CHANGE_DIR_NAME = 0x02
FILE_NOTIFY_CHANGE_SIZE = 0x08
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x10
FILE_NOTIFY_CHANGE_CREATION = 0x40

CONTENT_FLAGS = (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME
                 | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE
                 | FILE_NOTIFY_CHANGE_CREATION)


def use_content_flags() -> bool:
    """Наблюдатели watchdog больше не получают события от чтения файлов."""
    if os.name != "nt":
        return False
    try:
        from watchdog.observers import winapi
    except ImportError:
        return False
    winapi.WATCHDOG_FILE_NOTIFY_FLAGS = CONTENT_FLAGS
    return True
