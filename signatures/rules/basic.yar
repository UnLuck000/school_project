rule EICAR_Test_File
{
    meta:
        description = "Тестовая строка EICAR"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii
    condition:
        filesize < 1KB and $eicar
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "Учебный пример: скрипт с загрузкой и кодированной командой"
        note = "Только для файлов-скриптов: в программах (MZ) и в памяти эти слова встречаются часто"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "DownloadString" nocase
        $d = "IEX" nocase
    condition:
        filepath != "" and uint16(0) != 0x5A4D and filesize < 1MB and $a and 2 of ($b, $c, $d)
}