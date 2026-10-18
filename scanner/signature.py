import ctypes
import sys
from pathlib import Path

VALID = "valid"              # подпись действительна и доверенная
UNSIGNED = "unsigned"        # подписи нет
INVALID = "invalid"          # подпись есть, но файл изменён или издатель не доверенный
UNAVAILABLE = "unavailable"  # проверка не удалась (не Windows, ошибка вызова)

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000  # без обращений в сеть

# TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN
UNSIGNED_CODES = {0x800B0100, 0x800B0001, 0x800B0003}

if sys.platform == "win32":
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                    ("dwStateAction", wintypes.DWORD),
                    ("hWVTStateData", wintypes.HANDLE),
                    ("pwszURLReference", wintypes.LPCWSTR),
                    ("dwProvFlags", wintypes.DWORD),
                    ("dwUIContext", wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    _ACTION = GUID(0x00AAC56B, 0xCD44, 0x11D0,
                   (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    _wintrust = ctypes.WinDLL("wintrust")
    _wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    _wintrust.WinVerifyTrust.restype = ctypes.c_long


def verify_signature(path: Path) -> str:
    """Проверяет встроенную подпись Authenticode. Возвращает одну из констант выше."""
    if sys.platform != "win32":
        return UNAVAILABLE
    try:
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None)
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL

        hwnd = wintypes.HWND(-1)  # INVALID_HANDLE_VALUE: без окон и диалогов
        status = _wintrust.WinVerifyTrust(hwnd, ctypes.byref(_ACTION), ctypes.byref(data))
        status &= 0xFFFFFFFF

        data.dwStateAction = WTD_STATEACTION_CLOSE  # освобождаем ресурсы проверки
        _wintrust.WinVerifyTrust(hwnd, ctypes.byref(_ACTION), ctypes.byref(data))
    except (OSError, ValueError, ctypes.ArgumentError):
        return UNAVAILABLE

    if status == 0:
        return VALID
    if status in UNSIGNED_CODES:
        return UNSIGNED
    return INVALID