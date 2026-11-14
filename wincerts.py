r"""Корневые сертификаты Windows, которых ещё нет на компьютере.

Windows хранит у себя лишь часть доверенных корневых сертификатов, остальные скачивает с
Windows Update, когда они впервые понадобились при проверке цепочки (CryptoAPI). Python
(ssl.load_default_certs) видит только то, что уже лежит в хранилище, и сам докачку не
запускает. А Chrome и Edge давно проверяют сайты своими списками корней и хранилище Windows
не пополняют. Поэтому на «чистом» компьютере (так было на Windows 10 с 1.1.0) базы не
обновлялись: abuse.ch (корень Let's Encrypt ISRG Root X1), GitHub и VirusShare отвечали
CERTIFICATE_VERIFY_FAILED, и служба писала только «нет сети?».

install() — один раз при запуске (окно и служба): если проверка сертификата сервера не
прошла, берём сертификат сервера (соединение без проверки — только чтобы его получить),
просим Windows построить для него цепочку (CertGetCertificateChain: недостающие промежуточные
сертификаты — по ссылкам из самого сертификата, корень — с Windows Update, по списку доверия
Microsoft) и повторяем соединение с обычной проверкой. Доверие решает Windows: сертификат,
которому она не доверяет, после повтора даёт ту же ошибку. Один раз на сервер за запуск.
"""
import ctypes
import socket
import ssl
import sys
import threading
from ctypes import wintypes

X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
USAGE_MATCH_TYPE_AND = 0
SERVER_AUTH = b"1.3.6.1.5.5.7.3.1"

_tried: set[tuple[str, int]] = set()
_lock = threading.Lock()
_installed = False


class CERT_ENHKEY_USAGE(ctypes.Structure):
    _fields_ = [("cUsageIdentifier", wintypes.DWORD),
                ("rgpszUsageIdentifier", ctypes.POINTER(ctypes.c_char_p))]


class CERT_USAGE_MATCH(ctypes.Structure):
    _fields_ = [("dwType", wintypes.DWORD), ("Usage", CERT_ENHKEY_USAGE)]


class CERT_CHAIN_PARA(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("RequestedUsage", CERT_USAGE_MATCH)]


class CERT_TRUST_STATUS(ctypes.Structure):
    _fields_ = [("dwErrorStatus", wintypes.DWORD), ("dwInfoStatus", wintypes.DWORD)]


class CERT_CHAIN_CONTEXT(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("TrustStatus", CERT_TRUST_STATUS)]


def build_chain(der: bytes) -> int | None:
    """Цепочка сертификата сервера средствами Windows (с докачкой недостающего).
    Код ошибок доверия (0 — Windows доверяет) или None, если вызов не удался."""
    if sys.platform != "win32" or not der:
        return None
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CertCreateCertificateContext.restype = ctypes.c_void_p
    crypt.CertCreateCertificateContext.argtypes = [wintypes.DWORD, ctypes.c_char_p,
                                                   wintypes.DWORD]
    crypt.CertGetCertificateChain.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(CERT_CHAIN_PARA), wintypes.DWORD, ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(CERT_CHAIN_CONTEXT))]
    crypt.CertFreeCertificateChain.argtypes = [ctypes.POINTER(CERT_CHAIN_CONTEXT)]
    crypt.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    cert = crypt.CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                              der, len(der))
    if not cert:
        return None
    try:
        usage = (ctypes.c_char_p * 1)(SERVER_AUTH)
        para = CERT_CHAIN_PARA()
        para.cbSize = ctypes.sizeof(para)
        para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND
        para.RequestedUsage.Usage.cUsageIdentifier = 1
        para.RequestedUsage.Usage.rgpszUsageIdentifier = usage
        chain = ctypes.POINTER(CERT_CHAIN_CONTEXT)()
        if not crypt.CertGetCertificateChain(None, cert, None, None, ctypes.byref(para), 0,
                                             None, ctypes.byref(chain)):
            return None
        try:
            return int(chain.contents.TrustStatus.dwErrorStatus)
        finally:
            crypt.CertFreeCertificateChain(chain)
    finally:
        crypt.CertFreeCertificateContext(cert)


def server_certificate(host: str, port: int, timeout: float | None) -> bytes:
    """Сертификат сервера (DER) без проверки — только чтобы передать его Windows."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout or 15) as raw, \
            context.wrap_socket(raw, server_hostname=host) as tls:
        return tls.getpeercert(binary_form=True) or b""


def fetch_root(host: str, port: int = 443, timeout: float | None = 15) -> bool:
    """Попросить Windows докачать корень для сервера. True — стоит повторить соединение
    (первая попытка для этого сервера за запуск и Windows построила цепочку)."""
    key = (host.lower(), port)
    with _lock:
        if key in _tried:
            return False
        _tried.add(key)
    try:
        status = build_chain(server_certificate(host, port, timeout))
    except (OSError, ValueError):
        status = None
    from diag.log import get
    log = get("net")
    if status is None:
        log.warning("Сертификат %s: цепочку в Windows построить не удалось", host)
        return False
    log.info("Сертификат %s: Python не нашёл корень в хранилище Windows; цепочка Windows — %s",
             host, "доверенная, повтор" if status == 0 else f"ошибки 0x{status:x}")
    return status == 0


def install() -> None:
    """Повтор HTTPS-соединения после докачки корня — для всех запросов urllib/http.client."""
    global _installed
    if _installed or sys.platform != "win32":
        return
    import http.client
    original = http.client.HTTPSConnection.connect

    def connect(self):
        try:
            return original(self)
        except ssl.SSLCertVerificationError as e:
            if e.verify_code != 20 or getattr(self, "_tunnel_host", None):
                raise  # 20 — «нет издателя в хранилище»; через прокси сервер не наш
            if not fetch_root(self.host, self.port, self.timeout):
                raise
            if self.sock is not None:
                self.sock.close()
                self.sock = None
            self._context.load_default_certs()  # хранилище Windows прочитать заново
            return original(self)

    http.client.HTTPSConnection.connect = connect
    _installed = True
