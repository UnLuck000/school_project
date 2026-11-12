// Самопроверка провайдера AMSI без регистрации в Windows: тот же код sbit_amsi.cpp, но канал
// и разрешённый сервер задаются аргументами. Провайдер создаётся через DllGetClassObject,
// Scan() получает поддельный IAmsiStream с содержимым файла — как от PowerShell.
//
//   amsi_selftest64.exe <канал> <путь сервера> <файл с содержимым> <имя приложения> [address|read]
//
// Вывод: DETECTED или CLEAN; код возврата 2 — угроза, 0 — чисто, 1 — ошибка.
// Используется tests/test_amsi.py (сервер — scanner.amsi.AmsiServer в процессе pytest).
#define SBIT_AMSI_SELFTEST
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

std::wstring g_test_pipe, g_test_server;

#include "sbit_amsi.cpp"

class Stream final : public IAmsiStream {
    std::vector<BYTE> data_;
    std::wstring app_, name_;
    bool give_address_;

    static HRESULT put(const void *src, ULONG size, ULONG cap, PUCHAR out, PULONG ret) {
        *ret = size;
        if (cap < size) return E_NOT_SUFFICIENT_BUFFER;
        memcpy(out, src, size);
        return S_OK;
    }

public:
    Stream(std::vector<BYTE> data, std::wstring app, std::wstring name, bool address)
        : data_(std::move(data)), app_(std::move(app)), name_(std::move(name)),
          give_address_(address) {}
    STDMETHODIMP QueryInterface(REFIID riid, void **out) override {
        if (riid == IID_IUnknown || riid == __uuidof(IAmsiStream)) { *out = this; return S_OK; }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return 1; }
    STDMETHODIMP_(ULONG) Release() override { return 1; }
    STDMETHODIMP GetAttribute(AMSI_ATTRIBUTE attr, ULONG size, PUCHAR out, PULONG ret) override {
        switch (attr) {
        case AMSI_ATTRIBUTE_APP_NAME:
            return put(app_.c_str(), static_cast<ULONG>((app_.size() + 1) * 2), size, out, ret);
        case AMSI_ATTRIBUTE_CONTENT_NAME:
            return put(name_.c_str(), static_cast<ULONG>((name_.size() + 1) * 2), size, out, ret);
        case AMSI_ATTRIBUTE_CONTENT_SIZE: {
            ULONGLONG n = data_.size();
            return put(&n, sizeof(n), size, out, ret);
        }
        case AMSI_ATTRIBUTE_CONTENT_ADDRESS: {
            if (!give_address_) return E_NOTIMPL;
            const BYTE *p = data_.data();
            return put(&p, sizeof(p), size, out, ret);
        }
        default:
            return E_NOTIMPL;
        }
    }
    STDMETHODIMP Read(ULONGLONG pos, ULONG size, PUCHAR out, PULONG read) override {
        if (pos >= data_.size()) { *read = 0; return S_OK; }
        ULONGLONG left = data_.size() - pos;
        ULONG n = static_cast<ULONG>(size < left ? size : left);
        memcpy(out, data_.data() + pos, n);
        *read = n;
        return S_OK;
    }
};

int wmain(int argc, wchar_t **argv) {
    if (argc < 5) {
        fwprintf(stderr, L"usage: amsi_selftest <pipe> <server exe> <file> <app> [address|read]\n");
        return 1;
    }
    g_test_pipe = argv[1];
    g_test_server = argv[2];
    std::ifstream f(argv[3], std::ios::binary);
    std::vector<BYTE> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    bool address = argc < 6 || std::wstring(argv[5]) != L"read";

    IClassFactory *factory = nullptr;
    if (FAILED(DllGetClassObject(CLSID_SbitProvider, IID_IClassFactory,
                                 reinterpret_cast<void **>(&factory)))) return 1;
    IAntimalwareProvider *provider = nullptr;
    if (FAILED(factory->CreateInstance(nullptr, __uuidof(IAntimalwareProvider),
                                       reinterpret_cast<void **>(&provider)))) return 1;
    LPWSTR display = nullptr;
    if (SUCCEEDED(provider->DisplayName(&display))) {
        fwprintf(stderr, L"%ls\n", display);
        CoTaskMemFree(display);
    }
    Stream stream(std::move(data), argv[4], L"selftest.ps1", address);
    AMSI_RESULT result = AMSI_RESULT_CLEAN;
    HRESULT hr = provider->Scan(&stream, &result);
    provider->Release();
    if (FAILED(hr)) return 1;
    bool detected = AmsiResultIsMalware(result);
    wprintf(L"%ls\n", detected ? L"DETECTED" : L"CLEAN");
    return detected ? 2 : 0;
}
