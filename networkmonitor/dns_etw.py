"""DNS-запросы программ через ETW (Event Tracing for Windows), без драйвера.

Провайдер Microsoft-Windows-DNS-Client пишет событие на каждый запрос имени: 3006 — запрос
начат, 3008 — получен ответ (с адресами). Событие создаётся в процессе, который спрашивает,
поэтому в заголовке есть его PID. Сеанс трассировки реального времени может открыть только
администратор; без прав работает запасной вариант — опрос кэша DNS Windows (имена есть,
процессов нет).

DnsWatcher(on_query).start(): on_query(DnsQuery) вызывается из потока трассировки.
"""
import ctypes
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass

SESSION_NAME = "sbit-dns"
EVENT_QUERY = 3006
EVENT_RESULT = 3008
POLL_SECONDS = 5  # запасной вариант: как часто читать кэш DNS


@dataclass(frozen=True)
class DnsQuery:
    time: float
    pid: int            # 0 — неизвестен (запасной вариант)
    name: str
    results: tuple[str, ...] = ()   # адреса из ответа (только у EVENT_RESULT)
    status: int = 0
    final: bool = True              # False — начало запроса (3006), ответа ещё нет


# ---------- структуры ETW (x64) ----------
class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, text: str) -> "GUID":
        h = text.strip("{}").replace("-", "")
        return cls(int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16),
                   (ctypes.c_ubyte * 8)(*bytes.fromhex(h[16:32])))


DNS_CLIENT = GUID.parse("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", wintypes.ULONG), ("ProviderId", wintypes.ULONG),
                ("HistoricalContext", ctypes.c_uint64), ("TimeStamp", ctypes.c_int64),
                ("Guid", GUID), ("ClientContext", wintypes.ULONG), ("Flags", wintypes.ULONG)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", wintypes.ULONG),
                ("MinimumBuffers", wintypes.ULONG), ("MaximumBuffers", wintypes.ULONG),
                ("MaximumFileSize", wintypes.ULONG), ("LogFileMode", wintypes.ULONG),
                ("FlushTimer", wintypes.ULONG), ("EnableFlags", wintypes.ULONG),
                ("AgeLimit", wintypes.LONG), ("NumberOfBuffers", wintypes.ULONG),
                ("FreeBuffers", wintypes.ULONG), ("EventsLost", wintypes.ULONG),
                ("BuffersWritten", wintypes.ULONG), ("LogBuffersLost", wintypes.ULONG),
                ("RealTimeBuffersLost", wintypes.ULONG), ("LoggerThreadId", wintypes.HANDLE),
                ("LogFileNameOffset", wintypes.ULONG), ("LoggerNameOffset", wintypes.ULONG)]


class _PropertiesBuffer(ctypes.Structure):
    """EVENT_TRACE_PROPERTIES и место под имя сеанса сразу за ней (так требует API)."""
    _fields_ = [("props", EVENT_TRACE_PROPERTIES), ("name", ctypes.c_wchar * 1024)]


class EVENT_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Id", wintypes.USHORT), ("Version", ctypes.c_ubyte),
                ("Channel", ctypes.c_ubyte), ("Level", ctypes.c_ubyte),
                ("Opcode", ctypes.c_ubyte), ("Task", wintypes.USHORT),
                ("Keyword", ctypes.c_uint64)]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [("Size", wintypes.USHORT), ("HeaderType", wintypes.USHORT),
                ("Flags", wintypes.USHORT), ("EventProperty", wintypes.USHORT),
                ("ThreadId", wintypes.ULONG), ("ProcessId", wintypes.ULONG),
                ("TimeStamp", ctypes.c_int64), ("ProviderId", GUID),
                ("EventDescriptor", EVENT_DESCRIPTOR), ("ProcessorTime", ctypes.c_uint64),
                ("ActivityId", GUID)]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [("EventHeader", EVENT_HEADER), ("BufferContext", wintypes.ULONG),
                ("ExtendedDataCount", wintypes.USHORT), ("UserDataLength", wintypes.USHORT),
                ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p),
                ("UserContext", ctypes.c_void_p)]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [("Size", wintypes.USHORT), ("FieldTypeFlags", wintypes.USHORT),
                ("Version", wintypes.ULONG), ("ThreadId", wintypes.ULONG),
                ("ProcessId", wintypes.ULONG), ("TimeStamp", ctypes.c_int64),
                ("Guid", GUID), ("ProcessorTime", ctypes.c_uint64)]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", wintypes.ULONG),
                ("ParentInstanceId", wintypes.ULONG), ("ParentGuid", GUID),
                ("MofData", ctypes.c_void_p), ("MofLength", wintypes.ULONG),
                ("ClientContext", wintypes.ULONG)]


class SYSTEMTIME(ctypes.Structure):
    _fields_ = [(n, wintypes.WORD) for n in ("wYear", "wMonth", "wDayOfWeek", "wDay", "wHour",
                                             "wMinute", "wSecond", "wMilliseconds")]


class TIME_ZONE_INFORMATION(ctypes.Structure):
    _fields_ = [("Bias", wintypes.LONG), ("StandardName", ctypes.c_wchar * 32),
                ("StandardDate", SYSTEMTIME), ("StandardBias", wintypes.LONG),
                ("DaylightName", ctypes.c_wchar * 32), ("DaylightDate", SYSTEMTIME),
                ("DaylightBias", wintypes.LONG)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", wintypes.ULONG), ("Version", wintypes.ULONG),
                ("ProviderVersion", wintypes.ULONG), ("NumberOfProcessors", wintypes.ULONG),
                ("EndTime", ctypes.c_int64), ("TimerResolution", wintypes.ULONG),
                ("MaximumFileSize", wintypes.ULONG), ("LogFileMode", wintypes.ULONG),
                ("BuffersWritten", wintypes.ULONG), ("LogInstanceGuid", GUID),
                ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p),
                ("TimeZone", TIME_ZONE_INFORMATION), ("BootTime", ctypes.c_int64),
                ("PerfFreq", ctypes.c_int64), ("StartTime", ctypes.c_int64),
                ("ReservedFlags", wintypes.ULONG), ("BuffersLost", wintypes.ULONG)]


EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [("LogFileName", ctypes.c_wchar_p), ("LoggerName", ctypes.c_wchar_p),
                ("CurrentTime", ctypes.c_int64), ("BuffersRead", wintypes.ULONG),
                ("ProcessTraceMode", wintypes.ULONG), ("CurrentEvent", EVENT_TRACE),
                ("LogfileHeader", TRACE_LOGFILE_HEADER), ("BufferCallback", ctypes.c_void_p),
                ("BufferSize", wintypes.ULONG), ("Filled", wintypes.ULONG),
                ("EventsLost", wintypes.ULONG), ("EventRecordCallback", EVENT_RECORD_CALLBACK),
                ("IsKernelTrace", wintypes.ULONG), ("Context", ctypes.c_void_p)]


WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_CONTROL_STOP = 1
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
TRACE_LEVEL_VERBOSE = 5
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF
ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5


# ---------- разбор событий ----------
def _wstring(data: bytes, offset: int) -> tuple[str, int]:
    """Строка UTF-16 с нулём на конце: (строка, смещение после неё)."""
    end = offset
    while end + 1 < len(data) and data[end:end + 2] != b"\0\0":
        end += 2
    return data[offset:end].decode("utf-16-le", "replace"), end + 2


def parse_results(text: str) -> tuple[str, ...]:
    """«type: 5 cdn.example;::ffff:1.2.3.4;» -> ('1.2.3.4',). Только адреса."""
    out = []
    for part in text.split(";"):
        part = part.strip()
        if not part or part.startswith("type:"):
            continue
        if part.startswith("::ffff:"):
            part = part[7:]
        if part.count(".") == 3 and all(x.isdigit() for x in part.split(".")) or ":" in part:
            out.append(part)
    return tuple(out)


def parse_event(event_id: int, pid: int, data: bytes) -> DnsQuery | None:
    """Пользовательские данные события DNS-Client -> DnsQuery.
    3006: QueryName, QueryType(4), QueryOptions(8), ...
    3008: QueryName, QueryType(4), QueryOptions(8), QueryStatus(4), QueryResults."""
    if event_id not in (EVENT_QUERY, EVENT_RESULT) or len(data) < 4:
        return None
    name, offset = _wstring(data, 0)
    if not name:
        return None
    if event_id == EVENT_QUERY:
        return DnsQuery(time.time(), pid, name.lower(), final=False)
    offset += 4 + 8
    status = int.from_bytes(data[offset:offset + 4], "little") if offset + 4 <= len(data) else 0
    results, _ = _wstring(data, offset + 4) if offset + 4 < len(data) else ("", 0)
    return DnsQuery(time.time(), pid, name.lower(), parse_results(results), status)


# ---------- наблюдатель ----------
class DnsWatcher:
    def __init__(self, on_query, on_status=None):
        self.on_query = on_query
        self.on_status = on_status or (lambda text: None)
        self.mode = ""          # etw | cache | ""
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._handle = ctypes.c_uint64(0)
        self._trace = INVALID_PROCESSTRACE_HANDLE
        self._callback = EVENT_RECORD_CALLBACK(self._on_event)  # держим ссылку: иначе GC

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="dns-watch")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.mode == "etw":
            self._stop_session()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        if sys.platform != "win32":
            return
        error = self._start_session()
        if error == 0:
            self.mode = "etw"
            self.on_status("DNS: запросы программ видны через ETW (с процессами)")
            self._process()
            return
        self.mode = "cache"
        why = "нет прав администратора" if error == ERROR_ACCESS_DENIED else f"ошибка {error}"
        self.on_status(f"DNS: ETW недоступен ({why}), читается кэш DNS без привязки к процессам")
        self._poll_cache()

    # ----- ETW -----
    def _properties(self) -> _PropertiesBuffer:
        buf = _PropertiesBuffer()
        buf.props.Wnode.BufferSize = ctypes.sizeof(buf)
        buf.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        buf.props.Wnode.ClientContext = 1  # время в QueryPerformanceCounter
        buf.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        buf.props.LoggerNameOffset = EVENT_TRACE_PROPERTIES.__basicsize__ \
            if hasattr(EVENT_TRACE_PROPERTIES, "__basicsize__") else ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        buf.props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        return buf

    def _start_session(self) -> int:
        advapi = ctypes.WinDLL("advapi32")
        props = self._properties()
        err = advapi.StartTraceW(ctypes.byref(self._handle), SESSION_NAME, ctypes.byref(props))
        if err == ERROR_ALREADY_EXISTS:  # остался от прошлого запуска (программа упала)
            stop = self._properties()
            advapi.ControlTraceW(ctypes.c_uint64(0), SESSION_NAME, ctypes.byref(stop),
                                 EVENT_TRACE_CONTROL_STOP)
            props = self._properties()
            err = advapi.StartTraceW(ctypes.byref(self._handle), SESSION_NAME, ctypes.byref(props))
        if err:
            return err
        advapi.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(GUID), wintypes.ULONG,
                                          ctypes.c_ubyte, ctypes.c_uint64, ctypes.c_uint64,
                                          wintypes.ULONG, ctypes.c_void_p]
        err = advapi.EnableTraceEx2(self._handle.value, ctypes.byref(DNS_CLIENT),
                                    EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
                                    0, 0, 0, None)
        if err:
            self._stop_session()
        return err

    def _process(self) -> None:
        advapi = ctypes.WinDLL("advapi32")
        advapi.OpenTraceW.restype = ctypes.c_uint64
        advapi.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), wintypes.ULONG,
                                        ctypes.c_void_p, ctypes.c_void_p]
        advapi.CloseTrace.argtypes = [ctypes.c_uint64]
        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = SESSION_NAME
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
        logfile.EventRecordCallback = self._callback
        self._trace = advapi.OpenTraceW(ctypes.byref(logfile))
        if self._trace == INVALID_PROCESSTRACE_HANDLE:
            self.on_status("DNS: не удалось открыть трассировку")
            return
        handle = ctypes.c_uint64(self._trace)
        advapi.ProcessTrace(ctypes.byref(handle), 1, None, None)  # блокирует до остановки
        advapi.CloseTrace(self._trace)

    def _on_event(self, record_ptr) -> None:
        try:
            record = record_ptr.contents
            header = record.EventHeader
            event_id = header.EventDescriptor.Id
            if event_id not in (EVENT_QUERY, EVENT_RESULT) or not record.UserData:
                return
            data = ctypes.string_at(record.UserData, record.UserDataLength)
            query = parse_event(event_id, header.ProcessId, data)
            if query is not None:
                self.on_query(query)
        except Exception:  # noqa: S110 — исключение в обратном вызове ETW уронило бы трассировку
            pass

    def _stop_session(self) -> None:
        advapi = ctypes.WinDLL("advapi32")
        props = self._properties()
        advapi.ControlTraceW(ctypes.c_uint64(0), SESSION_NAME, ctypes.byref(props),
                             EVENT_TRACE_CONTROL_STOP)

    # ----- запасной вариант: кэш DNS -----
    def _poll_cache(self) -> None:
        seen: set[str] = set()
        while not self._stop.is_set():
            for name in read_dns_cache():
                if name not in seen:
                    seen.add(name)
                    self.on_query(DnsQuery(time.time(), 0, name))
            if len(seen) > 20000:
                seen.clear()
            self._stop.wait(POLL_SECONDS)


class DNS_CACHE_ENTRY(ctypes.Structure):
    pass


DNS_CACHE_ENTRY._fields_ = [("pNext", ctypes.POINTER(DNS_CACHE_ENTRY)),
                            ("pszName", ctypes.c_wchar_p), ("wType", wintypes.WORD),
                            ("wDataLength", wintypes.WORD), ("dwFlags", wintypes.DWORD)]


def read_dns_cache() -> list[str]:
    """Имена из кэша DNS Windows (как ipconfig /displaydns). Права администратора не нужны."""
    if sys.platform != "win32":
        return []
    dnsapi = ctypes.WinDLL("dnsapi")
    dnsapi.DnsFree.argtypes = [ctypes.c_void_p, ctypes.c_int]
    dnsapi.DnsFree.restype = None
    head = ctypes.POINTER(DNS_CACHE_ENTRY)()
    if not dnsapi.DnsGetCacheDataTable(ctypes.byref(head)):
        return []
    names = []
    entry = head
    while entry:
        item = entry.contents
        if item.pszName:
            names.append(item.pszName.lower())
        nxt = item.pNext
        # имя и запись выделены отдельно: освобождаются обе (DnsFreeFlat = 0)
        name_ptr = ctypes.cast(entry, ctypes.POINTER(ctypes.c_void_p))[1]
        if name_ptr:
            dnsapi.DnsFree(name_ptr, 0)
        dnsapi.DnsFree(ctypes.cast(entry, ctypes.c_void_p), 0)
        entry = nxt
    return sorted(set(names))
