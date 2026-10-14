from pathlib import Path

from scanner.hashing import load_all_signatures
from scanner.yara_engine import load_rules

sigs = load_all_signatures(Path("../signatures"))
print("Хэшей загружено:", len(sigs))

files = list(Path("../signatures/rules").rglob("*.yar")) + list(Path("../signatures/rules").rglob("*.yara"))
rules, errors = load_rules(Path("../signatures/rules"))
print("Файлов правил:", len(files))
print("Пропущено из-за ошибок:", len(errors))
for e in errors[:10]:
    print("  ", e)