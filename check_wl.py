from pathlib import Path
from scanner.hashing import sha256_of
from scanner.whitelist import load_whitelist, WHITELIST_FILE

f = Path(r"C:/Users/vlsin/Desktop/folderF/PythonProjects/NewEra/myav/test_samples/eicar.exe")
h = sha256_of(f)
wl = load_whitelist()

print("файл белого списка:", WHITELIST_FILE.resolve(), "| существует:", WHITELIST_FILE.exists())
print("записей в списке:", len(wl))
print("хэш файла:", h)
print("хэш в белом списке:", h in wl)