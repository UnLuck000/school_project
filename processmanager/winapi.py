"""advapi32 с объявленными функциями маркера доступа — общий для ntsnap и system."""
import ctypes
import sys

if sys.platform == "win32":
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(ctypes.c_void_p)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                                             wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
else:
    advapi32 = None
