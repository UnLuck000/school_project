import math
from collections import Counter

try:
    from scanner import _native  # появится после сборки C++-модуля
except ImportError:
    _native = None


def _py_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in Counter(data).values()))


def entropy(data: bytes) -> float:
    """Энтропия Шеннона: от 0 (одинаковые байты) до 8 (случайные данные)."""
    if _native is not None:
        return _native.entropy(data)
    return _py_entropy(data)


def backend() -> str:
    return "native (C++)" if _native is not None else "python"