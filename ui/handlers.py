from ui.registry import implements


@implements("btnProcessManager")
def open_process_manager(window):
    window.open_process_manager()


# Чтобы оживить кнопку-заглушку, добавьте функцию с её именем из ui/registry.py.
# Кнопка сама потеряет пометку «скоро». Пример:
#
# @implements("btnAutoruns")
# def scan_autoruns(window):
#     ...  # window - главное окно программы