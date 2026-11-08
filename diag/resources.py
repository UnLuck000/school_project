"""Ресурсы программы раз в 5 минут: память и ЦП своего процесса и дочерних (рабочие процессы
проверки, ядра VPN), число потоков."""
import os
import threading
import time

from diag.log import get

log = get("res")
INTERVAL = 300


def start() -> None:
    threading.Thread(target=_loop, name="diag-resources", daemon=True).start()


def _loop() -> None:
    try:
        import psutil
    except ImportError:
        return
    me = psutil.Process(os.getpid())
    me.cpu_percent(None)
    while True:
        time.sleep(INTERVAL)
        try:
            kids = me.children(recursive=True)
            kid_rss = 0
            names = {}
            for k in kids:
                try:
                    kid_rss += k.memory_info().rss
                    names[k.name()] = names.get(k.name(), 0) + 1
                except psutil.Error:
                    pass
            log.info("Ресурсы: ЦП %.1f%%, память %.0f МБ, потоков %d; дочерних %d (%.0f МБ): %s",
                     me.cpu_percent(None) / (psutil.cpu_count() or 1), me.memory_info().rss / 2 ** 20,
                     me.num_threads(), len(kids), kid_rss / 2 ** 20,
                     ", ".join(f"{n}×{c}" for n, c in names.items()) or "нет")
        except Exception:
            log.debug("Замер ресурсов не удался", exc_info=True)
