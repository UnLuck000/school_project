import os
import time

from scanner import features

data = os.urandom(8 * 1024 * 1024)
for name, fn in (("python", features._py_entropy),
                 ("native", features._native.entropy if features._native else None)):
    if fn is None:
        print(name, "недоступен")
        continue
    t = time.perf_counter()
    value = fn(data)
    print(f"{name}: {time.perf_counter() - t:.3f} с, энтропия {value:.4f}")