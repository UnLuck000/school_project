"""Дополнительные этапы быстрой и полной проверки (fullscan.run).

• Быстрая: весь автозапуск — реестр, папки автозагрузки, службы, планировщик, WMI (как
  сканер автозапуска: файлы записей — через scanner.pool, подписи и признаки — assess).
• Полная: автозапуск, проверка системы (hosts, прокси, WinHTTP, обновления, брандмауэр, BCD,
  ограничения реестра — recovery.checks) и память запущенных процессов (YARA по приватной
  памяти, как «Сканировать память» в диспетчере процессов: системные неизменившиеся процессы
  берутся из memcache, совпадение у подписанной программы — «проверить», не угроза).

Каждый этап сообщает найденное через on_found(path, level, text): path — файл (можно
поместить в карантин) или пустая строка (запись системы, процесс без файла). Записи
из исключений (автозапуск, проверка системы) не показываются, как и в их окнах.
"""
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExtraStats:
    autoruns: int = 0       # записей автозапуска проверено
    checks: int = 0         # проверок системы выполнено
    processes: int = 0      # процессов, чья память проверена


AUTORUN_LEVELS = {"threat": "threat", "suspicious": "suspicious"}  # «проверить» — не находка
CHECK_LEVELS = {"bad": "threat", "warning": "suspicious"}


def scan_autoruns(signatures, rules, whitelist, on_found, cancel: threading.Event,
                  say=lambda text: None) -> int:
    """Все записи автозапуска; найденное — on_found. Возвращает число записей."""
    from autoruns.scanner import Context, assess, collect_all
    from scanner import exclusions, pool as scan_pool
    say("Автозапуск: читаю записи...")
    entries, _ = collect_all()
    data = exclusions.load()
    entries = [e for e in entries
               if not exclusions.matches(data, "autoruns", exclusions.entry_key(e),
                                         exclusions.fingerprint(e.exe))]
    ctx = Context(signatures, rules, whitelist)
    exes = sorted({e.exe for e in entries if e.exe and os.path.isfile(e.exe)})
    say(f"Автозапуск: проверяю файлы ({len(exes)})...")
    for path, reason, error in scan_pool.check_files(exes, signatures, rules, whitelist,
                                                     cancel=cancel):
        ctx.verdicts[path] = "" if error is not None else reason or ""
    for e in entries:
        if cancel.is_set():
            break
        try:
            assess(e, ctx)
        except Exception:
            continue
        level = AUTORUN_LEVELS.get(e.level)
        if level:
            text = f"автозапуск ({e.location}: {e.name}) — " + "; ".join(e.flags)
            on_found(e.exe if e.exe and os.path.isfile(e.exe) else "", level, text)
    return len(entries)


def scan_system(on_found, cancel: threading.Event, say=lambda text: None) -> int:
    """Проверка системы (как в центре восстановления); число выполненных проверок."""
    from recovery import checks
    from scanner import exclusions
    say("Проверка системы: hosts, прокси, обновления, брандмауэр, BCD, политики...")
    results = checks.run_all()
    data = exclusions.load()
    for findings in results.findings.values():
        for f in findings:
            level = CHECK_LEVELS.get(f.level)
            if level and not exclusions.matches(data, "checks", exclusions.finding_key(f)):
                on_found("", level, f"Проверка системы: {f.title} — {f.status}")
    for hit in results.hits:
        if not exclusions.matches(data, "checks", exclusions.hit_key(hit)):
            on_found("", "suspicious", f"Ограничение в реестре: {hit.title} ({hit.path})")
    return len(results.findings) + (0 if cancel.is_set() else 1)


@dataclass
class _Proc:  # то, что нужно memcache: pid, время запуска, файл
    pid: int
    ppid: int
    name: str
    exe: str
    created: float


def scan_memory(on_found, cancel: threading.Event, say=lambda text: None,
                workers: int | None = None) -> int:
    """Память всех процессов правилами «memory»; число проверенных процессов."""
    from processmanager import memcache, ntsnap
    from processmanager.memscan import get_rules, kernel_process, scan_process
    from scanner.signature import VALID, inspect_signature
    from scanner.yara_engine import rules_version
    from ui import settings as cfg
    say("Память процессов: загружаю правила...")
    rules = get_rules("memory")
    if rules is None:
        return 0
    rules_key = f"memory|False|{rules_version(rules) or id(rules)}"
    me = os.getpid()
    procs = []
    for raw in ntsnap.list_processes():
        if raw.pid == me:
            continue
        exe = ntsnap._exe_by_kernel(raw.pid)
        if kernel_process(raw.pid, raw.ppid, exe):
            continue
        procs.append(_Proc(raw.pid, raw.ppid, raw.name, exe, raw.created))

    def work(p: _Proc):
        if cancel.is_set():
            return p, None
        cached, fp = memcache.lookup(p, rules_key)
        if cached is not None:
            return p, cached
        res = scan_process(rules, p.pid)
        memcache.store(p, rules_key, fp, res)
        if res.status == "match" and p.exe:
            try:
                if inspect_signature(Path(p.exe)).status == VALID:
                    res.status = "signed"  # подписанная программа: проверить, не угроза
            except OSError:
                pass
        return p, res

    done = 0
    workers = workers or int(cfg.get("scan/workers"))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(work, p) for p in procs]
        for future in as_completed(futures):
            p, res = future.result()
            if res is None:
                continue
            done += 1
            if done % 20 == 0:
                say(f"Память процессов: {done}/{len(procs)}")
            if res.status in ("match", "signed"):
                level = "threat" if res.status == "match" else "suspicious"
                on_found(p.exe or "", level,
                         f"память процесса {p.name} (PID {p.pid}): {res.text()}")
    return done
