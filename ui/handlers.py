from ui.registry import implements


@implements("btnProcessManager")
def open_process_manager(window):
    window.open_process_manager()


@implements("btnAutoruns")
def open_autoruns(window):
    window.open_autoruns()


@implements("btnUndoJournal")
def open_journal(window):
    window.open_autoruns(journal=True)

# Чтобы оживить кнопку-заглушку, добавьте функцию с её именем из ui/registry.py.
# Кнопка сама потеряет пометку «скоро». Пример:
#
# @implements("btnAutoruns")
# def scan_autoruns(window):
#     ...  # window - главное окно программы