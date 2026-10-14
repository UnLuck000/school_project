import inspect
from pathlib import Path

from scanner.engine import scan_tree
from scanner.hashing import load_signatures
from scanner.yara_engine import load_rules
from scanner.whitelist import load_whitelist

print("сигнатура scan_tree:", inspect.signature(scan_tree))

sigs = load_signatures(Path("signatures/hashes.txt"))
rules, errors = load_rules(Path("signatures/rules"))
wl = set(load_whitelist())

result = list(scan_tree(Path(r"C:\Users\vlsin\Desktop\folderF\PythonProjects\NewEra\myav\test_samples"), sigs, rules, whitelist=wl))
print("найдено при белом списке:", result)