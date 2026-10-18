import subprocess
import sys

import pytest
import yara

from processmanager.memscan import scan_process

# метку собираем из частей: в исходниках теста она целиком не встречается,
# поэтому файловый сканер не принимает сам тест за угрозу
MARKER = "".join(["MYAV", "_TEST", "_MEMORY_MARKER"])


@pytest.mark.skipif(sys.platform != "win32", reason="сканирование памяти проверяем на Windows")
def test_memory_scan_finds_marker():
    code = (f"import time; x = ''.join({['MYAV', '_TEST', '_MEMORY_MARKER']!r}); "
            "print('ready', flush=True); time.sleep(60)")
    # _base_executable: в venv python.exe запускает дочерний процесс, а метка в нём
    proc = subprocess.Popen([sys._base_executable, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "ready"
        rules = yara.compile(source=f'rule M {{ strings: $a = "{MARKER}" condition: $a }}')
        result = scan_process(rules, proc.pid)
        assert result.status == "match", result
        assert result.matches == ["M"]
    finally:
        proc.kill()