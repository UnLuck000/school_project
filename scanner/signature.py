import ctypes
import sys
from dataclasses import dataclass
from pathlib import Path

VALID = "valid"              # подпись действительна
UNSIGNED = "unsigned"        # подписи нет
INVALID = "invalid"          # подпись есть, но файл изменён или издатель не доверенный
UNAVAILABLE = "unavailable"  # проверка не удалась (не Windows, ошибка вызова)

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000  # без обращений в сеть

# TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN
UNSIGNED_CODES = {0x800B0100, 0x800B0001, 0x800B0003}

CERT_QUERY_OBJECT_FILE = 1
CERT_QUERY_CONTENT_FLAGS = 0x400 | 0x100  # PKCS7_SIGNED_EMBED | PKCS7_SIGNED
CERT_QUERY_FORMAT_FLAG_BINARY = 2
CMSG_SIGNER_INFO_PARAM = 6
CERT_FIND_SUBJECT_CERT = 0x000B0007
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4


@dataclass(frozen=True)
class SignatureInfo:
    status: str
    publisher: str | None = None
    source: str | None = None  # "embedded" | "catalog"


def describe(info: SignatureInfo) -> str:
    """Короткий текст для интерфейса. Для неизвестного состояния пустая строка."""
    label = {VALID: "Действительна", UNSIGNED: "Нет подписи",
             INVALID: "Недействительна"}.get(info.status)
    if label is None:
        return ""
    if info.publisher:
        label += f" ({info.publisher})"
    if info.source == "catalog":
        label += ", каталог"
    return label


if sys.platform == "win32":
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    class ALGORITHM_ID(ctypes.Structure):
        _fields_ = [("pszObjId", ctypes.c_char_p), ("Parameters", DATA_BLOB)]

    # начало CMSG_SIGNER_INFO: нам нужны только издатель и серийный номер
    class SIGNER_INFO_HEAD(ctypes.Structure):
        _fields_ = [("dwVersion", wintypes.DWORD), ("Issuer", DATA_BLOB),
                    ("SerialNumber", DATA_BLOB)]

    # начало CERT_INFO: для поиска сертификата используются Issuer и SerialNumber
    class CERT_INFO_HEAD(ctypes.Structure):
        _fields_ = [("dwVersion", wintypes.DWORD), ("SerialNumber", DATA_BLOB),
                    ("SignatureAlgorithm", ALGORITHM_ID), ("Issuer", DATA_BLOB)]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pcwszFilePath", wintypes.LPCWSTR),
                    ("hFile", wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class WINTRUST_CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("dwCatalogVersion", wintypes.DWORD),
                    ("pcwszCatalogFilePath", wintypes.LPCWSTR),
                    ("pcwszMemberTag", wintypes.LPCWSTR),
                    ("pcwszMemberFilePath", wintypes.LPCWSTR),
                    ("hMemberFile", wintypes.HANDLE),
                    ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
                    ("cbCalculatedFileHash", wintypes.DWORD),
                    ("pcCatalogContext", ctypes.c_void_p),
                    ("hCatAdmin", ctypes.c_void_p)]

    class CATALOG_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("wszCatalogFile", ctypes.c_wchar * 260)]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", wintypes.DWORD),
                    ("fdwRevocationChecks", wintypes.DWORD),
                    ("dwUnionChoice", wintypes.DWORD),
                    ("pUnion", ctypes.c_void_p),  # указатель на FILE_INFO или CATALOG_INFO
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
    _crypt32 = ctypes.WinDLL("crypt32")
    _kernel32 = ctypes.WinDLL("kernel32")

    _wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    _wintrust.WinVerifyTrust.restype = ctypes.c_long
    _wintrust.CryptCATAdminAcquireContext2.argtypes = [
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.LPCWSTR,
        ctypes.c_void_p, wintypes.DWORD]
    _wintrust.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
    _wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p, wintypes.DWORD]
    _wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
    _wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p)]
    _wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    _wintrust.CryptCATCatalogInfoFromContext.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
    _wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
    _wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    _wintrust.CryptCATAdminReleaseCatalogContext.restype = wintypes.BOOL
    _wintrust.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _wintrust.CryptCATAdminReleaseContext.restype = wintypes.BOOL

    _crypt32.CryptQueryObject.argtypes = [
        wintypes.DWORD, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    _crypt32.CryptQueryObject.restype = wintypes.BOOL
    _crypt32.CryptMsgGetParam.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD)]
    _crypt32.CryptMsgGetParam.restype = wintypes.BOOL
    _crypt32.CryptMsgClose.argtypes = [ctypes.c_void_p]
    _crypt32.CryptMsgClose.restype = wintypes.BOOL
    _crypt32.CertFindCertificateInStore.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p]
    _crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    _crypt32.CertGetNameStringW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.LPWSTR, wintypes.DWORD]
    _crypt32.CertGetNameStringW.restype = wintypes.DWORD
    _crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    _crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
    _crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    _crypt32.CertCloseStore.restype = wintypes.BOOL

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    _kernel32.CreateFileW.restype = ctypes.c_void_p
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    _INVALID_HANDLE = ctypes.c_void_p(-1).value

    def _win_verify(choice: int, info_struct) -> int:
        """Вызывает WinVerifyTrust для файла или каталога, возвращает код результата."""
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = choice
        data.pUnion = ctypes.addressof(info_struct)
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL

        hwnd = wintypes.HWND(-1)  # INVALID_HANDLE_VALUE: без окон и диалогов
        status = _wintrust.WinVerifyTrust(hwnd, ctypes.byref(_ACTION), ctypes.byref(data))
        data.dwStateAction = WTD_STATEACTION_CLOSE  # освобождаем ресурсы проверки
        _wintrust.WinVerifyTrust(hwnd, ctypes.byref(_ACTION), ctypes.byref(data))
        return status & 0xFFFFFFFF

    def _verify_embedded(path: Path) -> int:
        info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None)
        return _win_verify(WTD_CHOICE_FILE, info)

    def _catalog_lookup(path: Path):
        """Ищет файл в каталогах Windows по хэшу.
        Возвращает (код проверки, путь к .cat) или None, если файла нет ни в одном."""
        handle = _kernel32.CreateFileW(str(path), 0x80000000, 0x3, None, 3, 0x80, None)
        if handle in (None, _INVALID_HANDLE):
            return None
        try:
            for algorithm in ("SHA256", "SHA1"):
                admin = ctypes.c_void_p()
                if not _wintrust.CryptCATAdminAcquireContext2(
                        ctypes.byref(admin), None, algorithm, None, 0):
                    continue
                try:
                    size = wintypes.DWORD(0)
                    # первый вызов только сообщает нужный размер хэша
                    _wintrust.CryptCATAdminCalcHashFromFileHandle2(
                        admin, handle, ctypes.byref(size), None, 0)
                    if size.value == 0:
                        continue
                    digest = (ctypes.c_ubyte * size.value)()
                    if not _wintrust.CryptCATAdminCalcHashFromFileHandle2(
                            admin, handle, ctypes.byref(size), digest, 0):
                        continue
                    cat = _wintrust.CryptCATAdminEnumCatalogFromHash(
                        admin, digest, size.value, 0, None)
                    if not cat:
                        continue
                    try:
                        cat_info = CATALOG_INFO()
                        cat_info.cbStruct = ctypes.sizeof(CATALOG_INFO)
                        if not _wintrust.CryptCATCatalogInfoFromContext(
                                cat, ctypes.byref(cat_info), 0):
                            continue
                        member = WINTRUST_CATALOG_INFO()
                        member.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
                        member.pcwszCatalogFilePath = cat_info.wszCatalogFile
                        member.pcwszMemberTag = "".join(f"{b:02X}" for b in digest)
                        member.pcwszMemberFilePath = str(path)
                        member.pbCalculatedFileHash = ctypes.cast(
                            digest, ctypes.POINTER(ctypes.c_ubyte))
                        member.cbCalculatedFileHash = size.value
                        member.hCatAdmin = admin
                        status = _win_verify(WTD_CHOICE_CATALOG, member)
                        return status, cat_info.wszCatalogFile
                    finally:
                        _wintrust.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
                finally:
                    _wintrust.CryptCATAdminReleaseContext(admin, 0)
        finally:
            _kernel32.CloseHandle(handle)
        return None

    def get_publisher(path: Path) -> str | None:
        """Имя издателя из сертификата подписанта (для файла или .cat-каталога)."""
        encoding = wintypes.DWORD()
        content = wintypes.DWORD()
        fmt = wintypes.DWORD()
        store = ctypes.c_void_p()
        msg = ctypes.c_void_p()
        if not _crypt32.CryptQueryObject(
                CERT_QUERY_OBJECT_FILE, str(path), CERT_QUERY_CONTENT_FLAGS,
                CERT_QUERY_FORMAT_FLAG_BINARY, 0, ctypes.byref(encoding),
                ctypes.byref(content), ctypes.byref(fmt), ctypes.byref(store),
                ctypes.byref(msg), None):
            return None
        cert = None
        try:
            size = wintypes.DWORD(0)
            if not _crypt32.CryptMsgGetParam(
                    msg, CMSG_SIGNER_INFO_PARAM, 0, None, ctypes.byref(size)):
                return None
            buf = ctypes.create_string_buffer(size.value)
            if not _crypt32.CryptMsgGetParam(
                    msg, CMSG_SIGNER_INFO_PARAM, 0, buf, ctypes.byref(size)):
                return None
            signer = ctypes.cast(buf, ctypes.POINTER(SIGNER_INFO_HEAD)).contents

            probe = CERT_INFO_HEAD()
            probe.SerialNumber = signer.SerialNumber
            probe.Issuer = signer.Issuer
            cert = _crypt32.CertFindCertificateInStore(
                store, encoding.value, 0, CERT_FIND_SUBJECT_CERT,
                ctypes.addressof(probe), None)
            if not cert:
                return None
            name = ctypes.create_unicode_buffer(256)
            if _crypt32.CertGetNameStringW(
                    cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, name, 256) <= 1:
                return None
            return name.value
        finally:
            if cert:
                _crypt32.CertFreeCertificateContext(cert)
            if store.value:
                _crypt32.CertCloseStore(store, 0)
            if msg.value:
                _crypt32.CryptMsgClose(msg)


def inspect_signature(path: Path) -> SignatureInfo:
    """Проверяет подпись: сначала встроенную, затем по каталогам Windows."""
    if sys.platform != "win32":
        return SignatureInfo(UNAVAILABLE)
    try:
        status = _verify_embedded(path)
        if status == 0:
            return SignatureInfo(VALID, get_publisher(path), "embedded")
        if status in UNSIGNED_CODES:
            found = _catalog_lookup(path)
            if found is None:
                return SignatureInfo(UNSIGNED)
            cat_status, cat_path = found
            publisher = get_publisher(Path(cat_path))
            return SignatureInfo(VALID if cat_status == 0 else INVALID, publisher, "catalog")
        return SignatureInfo(INVALID, get_publisher(path), "embedded")
    except (OSError, ValueError, ctypes.ArgumentError):
        return SignatureInfo(UNAVAILABLE)


def verify_signature(path: Path) -> str:
    return inspect_signature(path).status


if __name__ == "__main__":
    # python -m scanner.signature путь1 путь2 ...
    for arg in sys.argv[1:]:
        info = inspect_signature(Path(arg))
        print(f"{arg}\n  {info.status}  издатель: {info.publisher}  источник: {info.source}")