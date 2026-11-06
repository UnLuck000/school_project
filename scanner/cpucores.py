"""Производительные (P) и энергоэффективные (E) ядра гибридных процессоров Intel (12-е
поколение и новее) и выбор ядер для проверки.

Тип ядра сообщает Windows: GetLogicalProcessorInformationEx(RelationProcessorCore) даёт
для каждого физического ядра EfficiencyClass (чем больше, тем производительнее) и маску
его логических процессоров. На обычных процессорах класс у всех ядер одинаковый.

Выбор: если производительные ядра заняты другими программами (игра, сборка проекта),
рабочие процессы проверки переносятся на энергоэффективные ядра и получают режим EcoQoS,
чтобы не отнимать производительность у пользователя. Если производительные ядра свободны,
проверка идёт на всех ядрах. Нагрузка самой проверки из замера вычитается, иначе она
сама себя выгоняла бы с P-ядер.
"""
import ctypes
import sys
import threading
import time

import psutil

RELATION_PROCESSOR_CORE = 0
BUSY_ENTER = 60.0   # % чужой нагрузки на P-ядрах (среднее по их логическим процессорам): на E-ядра
BUSY_LEAVE = 40.0   # % ниже этого: обратно на все ядра (запас против «дребезга»)

BUSY_SAMPLES = 2    # столько замеров подряд (по 2 с) нагрузка должна быть выше BUSY_ENTER

MODE_ALL, MODE_EFFICIENT = "all", "efficient"
MODE_TEXT = {MODE_ALL: "все ядра", MODE_EFFICIENT: "энергоэффективные ядра"}

_classes: dict[int, int] | None = None
_lock = threading.Lock()
_efficient_only = False  # настройка «Только E-ядра»


def set_efficient_only(on: bool) -> None:
    global _efficient_only
    _efficient_only = bool(on)


def efficient_only() -> bool:
    """Включена ли настройка «Только E-ядра» (и есть ли такие ядра вообще)."""
    return _efficient_only and bool(efficiency_cpus())


def _query_classes() -> dict[int, int]:
    """Номер логического процессора -> класс эффективности его ядра."""
    if sys.platform != "win32":
        return {}
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    size = ctypes.c_uint32(0)
    kernel32.GetLogicalProcessorInformationEx(RELATION_PROCESSOR_CORE, None, ctypes.byref(size))
    if not size.value:
        return {}
    buf = ctypes.create_string_buffer(size.value)
    if not kernel32.GetLogicalProcessorInformationEx(RELATION_PROCESSOR_CORE, buf,
                                                     ctypes.byref(size)):
        return {}
    raw = buf.raw
    result: dict[int, int] = {}
    offset = 0
    while offset < size.value:
        # SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX: Relationship(4) Size(4), далее
        # PROCESSOR_RELATIONSHIP: Flags(1) EfficiencyClass(1) Reserved(20) GroupCount(2)
        # GROUP_AFFINITY[GroupCount]: Mask(8) Group(2) Reserved(6)
        item_size = int.from_bytes(raw[offset + 4:offset + 8], "little")
        if item_size == 0:
            break
        efficiency = raw[offset + 9]
        group_count = int.from_bytes(raw[offset + 30:offset + 32], "little")
        for g in range(group_count):
            base = offset + 32 + g * 16
            mask = int.from_bytes(raw[base:base + 8], "little")
            group = int.from_bytes(raw[base + 8:base + 10], "little")
            for bit in range(64):
                if mask >> bit & 1:
                    result[group * 64 + bit] = efficiency
        offset += item_size
    return result


def core_classes() -> dict[int, int]:
    global _classes
    with _lock:
        if _classes is None:
            try:
                _classes = _query_classes()
            except (OSError, ValueError, AttributeError):
                _classes = {}
        return _classes


def is_hybrid() -> bool:
    return len(set(core_classes().values())) > 1


def performance_cpus() -> list[int]:
    classes = core_classes()
    if not classes:
        return []
    top = max(classes.values())
    return sorted(cpu for cpu, c in classes.items() if c == top)


def efficiency_cpus() -> list[int]:
    classes = core_classes()
    if not is_hybrid():
        return []
    top = max(classes.values())
    return sorted(cpu for cpu, c in classes.items() if c != top)


def describe() -> str:
    """Короткое описание процессора для интерфейса."""
    if not is_hybrid():
        return f"обычный процессор, логических ядер {psutil.cpu_count() or 1}"
    return (f"гибридный процессор: производительных логических ядер {len(performance_cpus())}, "
            f"энергоэффективных {len(efficiency_cpus())}")


class CoreChooser:
    """Следит за нагрузкой и решает, на каких ядрах работать проверке.
    update(own_pids) вызывается раз в 1-3 секунды."""

    def __init__(self):
        self.mode = MODE_ALL
        self.foreign_load = 0.0   # чужая нагрузка на P-ядрах, % (среднее по ним)
        self._busy = 0            # сколько замеров подряд P-ядра заняты
        self._procs: dict[int, psutil.Process] = {}
        psutil.cpu_percent(percpu=True)  # первый вызов задаёт точку отсчёта

    def cpus(self) -> list[int] | None:
        """Список ядер для рабочих процессов; None — все ядра."""
        if self.mode == MODE_EFFICIENT or efficient_only():
            return efficiency_cpus() or None
        return None

    def text(self) -> str:
        if not is_hybrid():
            return "все ядра (процессор не гибридный)"
        if efficient_only():
            return "только энергоэффективные ядра (так задано в настройках)"
        if self.mode == MODE_EFFICIENT:
            return (f"энергоэффективные ядра: производительные заняты другими программами "
                    f"({self.foreign_load:.0f}%)")
        return f"все ядра: производительные свободны ({self.foreign_load:.0f}%)"

    def _own_load(self, pids: list[int]) -> float | None:
        """Сколько процессорного времени заняли наши процессы, в «процентах одного ядра».
        None: среди них есть новые, для них замера ещё нет (первый вызов psutil даёт 0)."""
        total = 0.0
        fresh = False
        alive = {}
        for pid in pids:
            proc = self._procs.get(pid)
            try:
                if proc is None:
                    proc = psutil.Process(pid)
                    proc.cpu_percent(None)  # точка отсчёта
                    fresh = True
                else:
                    total += proc.cpu_percent(None)
                alive[pid] = proc
            except psutil.Error:
                continue
        self._procs = alive
        return None if fresh else total

    def update(self, own_pids: list[int]) -> bool:
        """Пересчитывает режим. True, если режим сменился."""
        per_cpu = psutil.cpu_percent(percpu=True)
        own = self._own_load(own_pids)
        p_cpus = [c for c in performance_cpus() if c < len(per_cpu)]
        if not is_hybrid() or not p_cpus or own is None:
            return False  # своя нагрузка неизвестна: чужую не отличить, решение откладываем
        # на каком ядре работали наши потоки, Windows не сообщает, поэтому считается
        # вся чужая нагрузка (общая минус своя, она известна точно), и считается, что
        # чужие программы сидят на производительных ядрах: Windows ставит туда активные
        # программы в первую очередь
        foreign = max(0.0, sum(per_cpu) - own)
        self.foreign_load = min(foreign, 100.0 * len(p_cpus)) / len(p_cpus)
        new = self.mode
        if self.mode == MODE_ALL and self.foreign_load > BUSY_ENTER:
            # разовый всплеск (запуск процессов, проверка файла другим антивирусом) не в счёт:
            # нагрузка должна держаться несколько замеров подряд
            self._busy += 1
            if self._busy >= BUSY_SAMPLES:
                new = MODE_EFFICIENT
        else:
            self._busy = 0
        if self.mode == MODE_EFFICIENT and self.foreign_load < BUSY_LEAVE:
            new = MODE_ALL
        changed = new != self.mode
        self.mode = new
        return changed


def choose_now(seconds: float = 0.5) -> CoreChooser:
    """Разовый выбор ядер (замер нагрузки за seconds) для проверки внутри своего процесса."""
    chooser = CoreChooser()
    time.sleep(seconds)
    chooser.update([])
    return chooser


# ---------- применение к процессу и потоку ----------
PROCESS_SET_INFORMATION = 0x0200
PROCESS_POWER_THROTTLING = 4  # ProcessPowerThrottling в SetProcessInformation
POWER_THROTTLING_EXECUTION_SPEED = 0x1


class _PowerThrottling(ctypes.Structure):
    _fields_ = [("Version", ctypes.c_uint32), ("ControlMask", ctypes.c_uint32),
                ("StateMask", ctypes.c_uint32)]


def set_eco(pid: int, on: bool) -> bool:
    """EcoQoS: Windows держит такой процесс на экономичных ядрах и низкой частоте."""
    if sys.platform != "win32":
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    handle = kernel32.OpenProcess(PROCESS_SET_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        state = _PowerThrottling(1, POWER_THROTTLING_EXECUTION_SPEED,
                                 POWER_THROTTLING_EXECUTION_SPEED if on else 0)
        return bool(kernel32.SetProcessInformation(
            ctypes.c_void_p(handle), PROCESS_POWER_THROTTLING, ctypes.byref(state),
            ctypes.sizeof(state)))
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def apply(pid: int, cpus: list[int] | None) -> None:
    """Привязывает процесс к ядрам (None — ко всем) и включает EcoQoS на E-ядрах."""
    try:
        proc = psutil.Process(pid)
        proc.cpu_affinity(cpus or list(range(psutil.cpu_count() or 1)))
    except (psutil.Error, ValueError, OSError):
        pass
    set_eco(pid, cpus is not None)


THREAD_PRIORITY_BELOW_NORMAL = -1


def pin_current_thread(cpus: list[int] | None) -> None:
    """Для потоков проверки внутри своего процесса (память процессов): пониженный приоритет
    и, если производительные ядра заняты, только энергоэффективные ядра."""
    if sys.platform != "win32":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentThread.restype = ctypes.c_void_p
    kernel32.SetThreadAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    kernel32.SetThreadAffinityMask.restype = ctypes.c_size_t
    kernel32.SetThreadPriority.argtypes = [ctypes.c_void_p, ctypes.c_int]
    thread = kernel32.GetCurrentThread()
    kernel32.SetThreadPriority(thread, THREAD_PRIORITY_BELOW_NORMAL)
    if cpus:
        mask = 0
        for cpu in cpus:
            if cpu < 64:
                mask |= 1 << cpu
        kernel32.SetThreadAffinityMask(thread, mask)
