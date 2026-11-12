"""Общий сеанс ETW реального времени для одного провайдера (без драйвера).

Используется контролем запуска (Microsoft-Windows-Kernel-Process: запуск процессов) и
защитой от стилеров (Microsoft-Windows-Kernel-File: открытие файлов). Структуры —
из networkmonitor/dns_etw.py. Открыть сеанс может только администратор: без прав
start() возвращает код ошибки, и вызывающий переходит на запасной вариант (опрос).

trace = EtwTrace("sbit-proc", GUID, keywords, on_record); trace.start() → 0 или ошибка;
on_record(event_id, pid, user_data: bytes) вызывается из потока трассировки.
"""
import ctypes
import sys
import threading
from ctypes import wintypes

from networkmonitor.dns_etw import (
    ERROR_ALREADY_EXISTS, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD_CALLBACK,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, GUID, INVALID_PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, TRACE_LEVEL_VERBOSE,
    WNODE_FLAG_TRACED_GUID, _PropertiesBuffer,
)

KERNEL_PROCESS = GUID.parse("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
KERNEL_FILE = GUID.parse("{EDD08927-9CC4-4E65-B970-C2560FB5C289}")
ERROR_ACCESS_DENIED = 5
EVENT_TRACE_CONTROL_FLUSH = 3


def _properties() -> _PropertiesBuffer:
    buf = _PropertiesBuffer()
    buf.props.Wnode.BufferSize = ctypes.sizeof(buf)
    buf.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
    buf.props.Wnode.ClientContext = 1
    buf.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
    buf.props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    return buf


class EtwTrace:
    def __init__(self, name: str, provider: GUID, keywords: int, on_record,
                 event_ids: set[int] | None = None, flush: float = 0.0):
        self.name = name
        self.provider = provider
        self.keywords = keywords
        self.on_record = on_record
        self.event_ids = event_ids  # None — все события провайдера
        # ETW отдаёт события, когда заполнится буфер или раз в секунду; flush > 0 —
        # выгружать буферы чаще (запуск процесса нужно увидеть, пока процесс жив)
        self.flush = flush
        self._stopped = threading.Event()
        self._handle = ctypes.c_uint64(0)
        self._thread: threading.Thread | None = None
        self._callback = EVENT_RECORD_CALLBACK(self._on_event)  # ссылка: иначе GC

    def start(self) -> int:
        """Открывает сеанс и запускает поток чтения. 0 — успех, иначе код ошибки Win32."""
        if sys.platform != "win32":
            return 1
        advapi = ctypes.WinDLL("advapi32")
        props = _properties()
        err = advapi.StartTraceW(ctypes.byref(self._handle), self.name, ctypes.byref(props))
        if err == ERROR_ALREADY_EXISTS:  # остался от прошлого запуска (программа упала)
            self._stop_session()
            props = _properties()
            err = advapi.StartTraceW(ctypes.byref(self._handle), self.name, ctypes.byref(props))
        if err:
            return err
        advapi.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(GUID), wintypes.ULONG,
                                          ctypes.c_ubyte, ctypes.c_uint64, ctypes.c_uint64,
                                          wintypes.ULONG, ctypes.c_void_p]
        err = advapi.EnableTraceEx2(self._handle.value, ctypes.byref(self.provider),
                                    EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                                    self.keywords, 0, 0, None)
        if err:
            self._stop_session()
            return err
        self._stopped.clear()
        self._thread = threading.Thread(target=self._process, daemon=True, name=self.name)
        self._thread.start()
        if self.flush:
            threading.Thread(target=self._flusher, daemon=True, name=self.name + "-flush").start()
        return 0

    def _flusher(self) -> None:
        advapi = ctypes.WinDLL("advapi32")
        while not self._stopped.wait(self.flush):
            props = _properties()
            advapi.ControlTraceW(ctypes.c_uint64(0), self.name, ctypes.byref(props),
                                 EVENT_TRACE_CONTROL_FLUSH)

    def stop(self) -> None:
        self._stopped.set()
        self._stop_session()  # ProcessTrace вернётся сам
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _process(self) -> None:
        advapi = ctypes.WinDLL("advapi32")
        advapi.OpenTraceW.restype = ctypes.c_uint64
        advapi.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), wintypes.ULONG,
                                        ctypes.c_void_p, ctypes.c_void_p]
        advapi.CloseTrace.argtypes = [ctypes.c_uint64]
        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.name
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.EventRecordCallback = self._callback
        trace = advapi.OpenTraceW(ctypes.byref(logfile))
        if trace == INVALID_PROCESSTRACE_HANDLE:
            return
        handle = ctypes.c_uint64(trace)
        advapi.ProcessTrace(ctypes.byref(handle), 1, None, None)  # до остановки сеанса
        advapi.CloseTrace(trace)

    def _on_event(self, record_ptr) -> None:
        try:
            record = record_ptr.contents
            header = record.EventHeader
            event_id = header.EventDescriptor.Id
            if self.event_ids is not None and event_id not in self.event_ids:
                return
            if not record.UserData:
                return
            data = ctypes.string_at(record.UserData, record.UserDataLength)
            self.on_record(event_id, header.ProcessId, data)
        except Exception:  # noqa: S110 — исключение в обратном вызове ETW уронило бы трассировку
            pass

    def _stop_session(self) -> None:
        if sys.platform != "win32":
            return
        advapi = ctypes.WinDLL("advapi32")
        props = _properties()
        advapi.ControlTraceW(ctypes.c_uint64(0), self.name, ctypes.byref(props),
                             EVENT_TRACE_CONTROL_STOP)


def wstring(data: bytes, offset: int) -> tuple[str, int]:
    """Строка UTF-16 с нулём на конце, выровненная по 2 байтам: (строка, смещение после)."""
    end = offset
    while end + 1 < len(data) and data[end:end + 2] != b"\0\0":
        end += 2
    return data[offset:end].decode("utf-16-le", "replace"), end + 2


def kernel_path(path: str) -> str:
    r"""\Device\HarddiskVolume3\Users\x → C:\Users\x (если том известен)."""
    from processmanager import ntsnap
    if not path.startswith("\\Device\\") or not ntsnap.AVAILABLE:
        return path.removeprefix("\\??\\")
    lower = path.lower()
    for device, letter in ntsnap._device_map().items():
        if lower.startswith(device + "\\"):
            return letter + path[len(device):]
    return path
