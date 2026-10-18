rule Memory_Test_Marker
{
    meta:
        description = "Тестовая метка для проверки сканирования памяти (tests/test_memscan.py)"
    strings:
        $m = "MYAV_TEST_MEMORY_MARKER" ascii
    condition:
        $m
}

rule Mimikatz_Strings_In_Memory
{
    meta:
        description = "Характерные строки Mimikatz в памяти процесса"
    strings:
        $a = "sekurlsa::logonpasswords" ascii wide nocase
        $b = "gentilkiwi" ascii wide nocase
        $c = "mimikatz" ascii wide nocase
        $d = "lsadump::sam" ascii wide nocase
    condition:
        2 of them
}