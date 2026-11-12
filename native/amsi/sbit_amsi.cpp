// Провайдер AMSI StretchBIT: Windows загружает эту библиотеку в процессы, которые проверяют
// содержимое через AMSI (PowerShell, Windows Script Host — VBScript/JScript, макросы Office,
// загрузка сборок .NET 4.8), и вызывает Scan() для каждого скрипта или блока перед
// выполнением — уже после расшифровки (-enc, склейка строк, Invoke-Expression).
//
// Сама библиотека ничего не проверяет: содержимое уходит по именованному каналу
// \\.\pipe\sbit-amsi программе StretchBIT (scanner/amsi.py), там — хэши, YARA и признаки
// отключения AMSI. Ответ «угроза» → AMSI_RESULT_DETECTED: PowerShell пишет «This script
// contains malicious content and has been blocked by your antivirus software».
//
// Безопасность:
// • содержимое скриптов отдаётся только своему серверу: процесс-сервер канала
//   (GetNamedPipeServerProcessId) должен быть одной из программ из
//   HKLM\SOFTWARE\StretchBIT\AMSI, значение Servers (REG_MULTI_SZ, пишет только администратор
//   при регистрации) — чужая программа, создавшая канал с тем же именем, ничего не получит;
// • программа не запущена или не отвечает → «не обнаружено» за ~0,2 с (канала нет — сразу),
//   ответ ждём не дольше REPLY_TIMEOUT_MS: зависший антивирус не должен вешать PowerShell;
// • больше MAX_CONTENT байт не отправляется (начало скрипта).
//
// Сборка — build_amsi.py (cl.exe, x64 и x86: 32-битные Office и PowerShell грузят свою).
// Регистрация в реестре — из Python (scanner/amsi.py install), не через regsvr32.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <new>
#include <string>
#include <vector>

// {946D2B07-6D1A-49DF-AE1B-C626C27B2DF1} — то же в scanner/amsi.py CLSID
static const CLSID CLSID_SbitProvider = {
    0x946d2b07, 0x6d1a, 0x49df, {0xae, 0x1b, 0xc6, 0x26, 0xc2, 0x7b, 0x2d, 0xf1}};

#ifdef SBIT_AMSI_SELFTEST
// самопроверка (selftest.cpp): свой канал и разрешённый сервер — без записи в HKLM;
// в рабочую библиотеку это не попадает
extern std::wstring g_test_pipe, g_test_server;
#define PIPE_NAME (g_test_pipe.c_str())
#else
static const wchar_t PIPE_NAME[] = L"\\\\.\\pipe\\sbit-amsi";
#endif
static const wchar_t SERVERS_KEY[] = L"SOFTWARE\\StretchBIT\\AMSI";
static const DWORD MAGIC_REQUEST = 0x31414253;   // "SBA1"
static const DWORD MAGIC_REPLY = 0x52414253;     // "SBAR"
static const DWORD REPLY_TIMEOUT_MS = 3000;
static const DWORD CONNECT_WAIT_MS = 200;
static const ULONGLONG MAX_CONTENT = 2 * 1024 * 1024;

static LONG g_objects = 0;
static LONG g_locks = 0;

#pragma pack(push, 1)
struct Request {
    DWORD magic;
    DWORD pid;
    DWORD flags;         // 1 — процесс 32-битный
    DWORD app_bytes;     // имя приложения (UTF-16LE), затем имя содержимого, затем содержимое
    DWORD name_bytes;
    DWORD content_bytes;
    ULONGLONG content_size;  // полный размер (если отправлено только начало)
};
struct Reply {
    DWORD magic;
    DWORD result;        // 0 — чисто, 1 — угроза (блокировать)
};
#pragma pack(pop)

static std::wstring lower(std::wstring s) {
    for (auto &c : s) c = static_cast<wchar_t>(towlower(c));
    return s;
}

// Сервер канала — разрешённая программа?
static bool trusted_server(HANDLE pipe) {
    ULONG server_pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &server_pid) || !server_pid) return false;
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_pid);
    if (!proc) return false;
    wchar_t image[MAX_PATH * 2];
    DWORD size = ARRAYSIZE(image);
    BOOL ok = QueryFullProcessImageNameW(proc, 0, image, &size);
    CloseHandle(proc);
    if (!ok) return false;
#ifdef SBIT_AMSI_SELFTEST
    return lower(image) == lower(g_test_server);
#else
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SERVERS_KEY, 0, KEY_READ | KEY_WOW64_64KEY, &key))
        return false;
    DWORD type = 0, bytes = 0;
    bool found = false;
    if (!RegQueryValueExW(key, L"Servers", nullptr, &type, nullptr, &bytes) &&
        type == REG_MULTI_SZ && bytes > 2 && bytes < 64 * 1024) {
        std::vector<wchar_t> list(bytes / sizeof(wchar_t) + 2, 0);
        if (!RegQueryValueExW(key, L"Servers", nullptr, nullptr,
                              reinterpret_cast<BYTE *>(list.data()), &bytes)) {
            std::wstring want = lower(image);
            for (const wchar_t *p = list.data(); *p; p += wcslen(p) + 1)
                if (lower(p) == want) { found = true; break; }
        }
    }
    RegCloseKey(key);
    return found;
#endif
}

// Ввод-вывод с ограничением по времени (канал открыт с FILE_FLAG_OVERLAPPED).
static bool io(HANDLE pipe, bool write, void *buf, DWORD len, DWORD *done, DWORD timeout) {
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return false;
    BOOL ok = write ? WriteFile(pipe, buf, len, nullptr, &ov) : ReadFile(pipe, buf, len, nullptr, &ov);
    bool result = false;
    if (ok || GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(ov.hEvent, timeout) == WAIT_OBJECT_0)
            result = GetOverlappedResult(pipe, &ov, done, FALSE) != FALSE;
        else {
            CancelIoEx(pipe, &ov);
            GetOverlappedResult(pipe, &ov, done, TRUE);
        }
    }
    CloseHandle(ov.hEvent);
    return result;
}

static std::wstring string_attribute(IAmsiStream *stream, AMSI_ATTRIBUTE attr) {
    ULONG need = 0;
    HRESULT hr = stream->GetAttribute(attr, 0, nullptr, &need);
    if (hr != E_NOT_SUFFICIENT_BUFFER || need == 0 || need > 64 * 1024) return L"";
    std::vector<BYTE> buf(need + 2, 0);
    if (FAILED(stream->GetAttribute(attr, need, buf.data(), &need))) return L"";
    return std::wstring(reinterpret_cast<wchar_t *>(buf.data()));
}

// Отправить содержимое программе; true — угроза.
static bool ask_server(const std::wstring &app, const std::wstring &name, const BYTE *data,
                       DWORD len, ULONGLONG full_size) {
    HANDLE pipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (pipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY &&
        WaitNamedPipeW(PIPE_NAME, CONNECT_WAIT_MS))
        pipe = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OVERLAPPED, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return false;  // программа не запущена
    bool detected = false;
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr) && trusted_server(pipe)) {
        BOOL wow = FALSE;
        IsWow64Process(GetCurrentProcess(), &wow);
        Request head = {MAGIC_REQUEST, GetCurrentProcessId(), wow ? 1u : 0u,
                        static_cast<DWORD>(app.size() * sizeof(wchar_t)),
                        static_cast<DWORD>(name.size() * sizeof(wchar_t)), len, full_size};
        std::vector<BYTE> msg(sizeof(head) + head.app_bytes + head.name_bytes + len);
        BYTE *p = msg.data();
        memcpy(p, &head, sizeof(head)); p += sizeof(head);
        memcpy(p, app.data(), head.app_bytes); p += head.app_bytes;
        memcpy(p, name.data(), head.name_bytes); p += head.name_bytes;
        if (len) memcpy(p, data, len);
        DWORD done = 0;
        Reply reply = {};
        if (io(pipe, true, msg.data(), static_cast<DWORD>(msg.size()), &done, REPLY_TIMEOUT_MS) &&
            done == msg.size() &&
            io(pipe, false, &reply, sizeof(reply), &done, REPLY_TIMEOUT_MS) &&
            done == sizeof(reply) && reply.magic == MAGIC_REPLY)
            detected = reply.result == 1;
    }
    CloseHandle(pipe);
    return detected;
}

class Provider final : public IAntimalwareProvider {
    LONG refs_ = 1;

public:
    Provider() { InterlockedIncrement(&g_objects); }
    ~Provider() { InterlockedDecrement(&g_objects); }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void **out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider)) {
            *out = static_cast<IAntimalwareProvider *>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&refs_); }
    STDMETHODIMP_(ULONG) Release() override {
        LONG n = InterlockedDecrement(&refs_);
        if (!n) delete this;
        return n;
    }

    // IAntimalwareProvider
    STDMETHODIMP Scan(IAmsiStream *stream, AMSI_RESULT *result) override {
        if (!stream || !result) return E_INVALIDARG;
        *result = AMSI_RESULT_NOT_DETECTED;
        ULONGLONG size = 0;
        ULONG got = 0;
        if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(size),
                                        reinterpret_cast<BYTE *>(&size), &got)) || !size)
            return S_OK;
        DWORD len = static_cast<DWORD>(size < MAX_CONTENT ? size : MAX_CONTENT);
        PBYTE address = nullptr;
        std::vector<BYTE> copy;
        if (FAILED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(address),
                                        reinterpret_cast<BYTE *>(&address), &got)) || !address) {
            copy.resize(len);  // содержимого нет в памяти — читаем через Read
            ULONG read = 0;
            if (FAILED(stream->Read(0, len, copy.data(), &read))) return S_OK;
            len = read;
            address = copy.data();
        }
        std::wstring app = string_attribute(stream, AMSI_ATTRIBUTE_APP_NAME);
        std::wstring name = string_attribute(stream, AMSI_ATTRIBUTE_CONTENT_NAME);
        try {
            if (ask_server(app, name, address, len, size)) *result = AMSI_RESULT_DETECTED;
        } catch (...) {  // нехватка памяти и т. п.: не мешаем процессу работать
        }
        return S_OK;
    }
    STDMETHODIMP_(void) CloseSession(ULONGLONG) override {}
    STDMETHODIMP DisplayName(LPWSTR *name) override {
        if (!name) return E_POINTER;
        static const wchar_t text[] = L"StretchBIT AMSI Provider";
        *name = static_cast<LPWSTR>(CoTaskMemAlloc(sizeof(text)));
        if (!*name) return E_OUTOFMEMORY;
        memcpy(*name, text, sizeof(text));
        return S_OK;
    }
};

class Factory final : public IClassFactory {
public:
    STDMETHODIMP QueryInterface(REFIID riid, void **out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *out = static_cast<IClassFactory *>(this);
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return 2; }   // статический объект
    STDMETHODIMP_(ULONG) Release() override { return 1; }
    STDMETHODIMP CreateInstance(IUnknown *outer, REFIID riid, void **out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        Provider *p = new (std::nothrow) Provider();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, out);
        p->Release();
        return hr;
    }
    STDMETHODIMP LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&g_locks); else InterlockedDecrement(&g_locks);
        return S_OK;
    }
};

static Factory g_factory;

extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID clsid, REFIID riid, void **out) {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (clsid != CLSID_SbitProvider) return CLASS_E_CLASSNOTAVAILABLE;
    return g_factory.QueryInterface(riid, out);
}

extern "C" HRESULT __stdcall DllCanUnloadNow() {
    return (g_objects == 0 && g_locks == 0) ? S_OK : S_FALSE;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(module);
    return TRUE;
}
