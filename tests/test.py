from NewEra.myav.scanner.hashing import sha256_of
from pathlib import Path

print(sha256_of(Path("../test_samples/eicar.exe")))