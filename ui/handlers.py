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


@implements("btnMemoryDeep")
def memory_deep(window):
    window.open_process_manager()
    window.proc_window.find_injections()


@implements("btnFileAnalyzer")
def open_analyzer(window):
    window.open_analyzer()


@implements("btnRestorePoint")
def restore_point(window):
    window.open_recovery(0, "create")


@implements("btnSfcDism")
def integrity_check(window):
    window.open_recovery(1)


@implements("btnSystemChecks")
def system_checks(window):
    window.open_recovery(2, "check")





# Чтобы оживить кнопку-заглушку, добавьте функцию с её именем из ui/registry.py.
# Кнопка сама потеряет пометку «скоро». Пример:
#
# @implements("btnAutoruns")
# def scan_autoruns(window):
#     ...  # window - главное окно программы