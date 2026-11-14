; Установщик StretchBIT (Inno Setup 6). Собирается из build_release.py --installer:
;   ISCC installer.iss /DEdition=release|test /DAppVersion=... /DSourceDir=dist\StretchBIT
; Релизная ставится в C:\Program Files\StretchBIT, тестовая — в C:\Program Files\StretchBIT-test
; (свои AppId: не мешают друг другу). Нужны права администратора: папка программы закрыта от
; записи. Поверх прежней версии: заменяются только файлы программы — журналы, кэш и карантин
; в папке и настройки в %APPDATA%\StretchBitConfiguration[-test] остаются. Прежнее место
; (C:\Utils\SBIT[-test], до 1.0.0 включительно) переносится: карантин, журналы и отчёты —
; в новую папку, старая копия удаляется своим «--uninstall --silent» и папкой целиком.
; Удаление: StretchBIT.exe --uninstall --silent [--wipe] (uninstall.py: сеть после VPN,
; брандмауэр, ETW, ловушки, автозапуск, меню Проводника), затем Inno удаляет папку целиком.
; Флажок «Удалить все настройки пользователя» — ещё и папку конфигурации (userdata.py).
; Служба Windows (service/, с 1.1): защита файлов, карантин и журнал защиты работают в службе
; StretchBITService[-test] от имени системы, окно программы — без прав администратора. Перед
; заменой файлов служба останавливается (net stop ждёт остановки: иначе StretchBIT.exe занят),
; после — «StretchBIT.exe --service-install» создаёт или обновляет её и запускает. Удаление:
; шаги uninstall.py останавливают и удаляют службу; на крайний случай — sc delete.

#ifndef Edition
  #define Edition "release"
#endif
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "dist\StretchBIT"
#endif
#ifndef OutputDir
  #define OutputDir "release"
#endif

#define ExeName "StretchBIT.exe"
#if Edition == "test"
  #define ServiceName "StretchBITService-test"
  #define AppKey "StretchBIT-test"
  #define DisplayName "StretchBIT (тест)"
  #define InstallDir "{autopf}\StretchBIT-test"
  #define OldDir "C:\Utils\SBIT-test"
  #define ConfigName "StretchBitConfiguration-test"
#else
  #define ServiceName "StretchBITService"
  #define AppKey "StretchBIT"
  #define DisplayName "StretchBIT"
  #define InstallDir "{autopf}\StretchBIT"
  #define OldDir "C:\Utils\SBIT"
  #define ConfigName "StretchBitConfiguration"
#endif

[Setup]
; 64-битный режим: без него {autopf} — «Program Files (x86)», а записи реестра установщика —
; в WOW6432Node (13.11.2026 тестовая так и встала: C:\Program Files (x86)\StretchBIT-test)
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
AppId={#AppKey}
AppName={#DisplayName}
AppVersion={#AppVersion}
AppVerName={#DisplayName} {#AppVersion}
AppPublisher=StretchBIT
DefaultDirName={#InstallDir}
DisableDirPage=yes
; установка 1.0.0 в C:\Utils не должна удерживать новую там же: переезд — PrepareToInstall
UsePreviousAppDir=no
DisableProgramGroupPage=yes
DisableReadyPage=no
; Установка — с правами администратора: программа работает с ними же (автозапуск — задание
; с наивысшими правами), а папку, куда может писать любая программа пользователя, можно
; было подменить (положить свою DLL — и получить права администратора при следующем входе).
; После копирования файлов права папки закрываются ([Run], icacls): пользователям только
; чтение, целиком, включая журналы, кэш и отчёты. Программа с правами пишет только сюда;
; без прав (отказ в окне UAC) — в %LOCALAPPDATA%\StretchBIT (datadirs.py). Раньше logs,
; cache и reports были открыты всем: процесс без прав подменял вложенную папку ссылкой
; (junction) — и программа с правами писала и удаляла файлы уже в чужой папке. Базы, карантин
; и всё остальное — только администраторам. Правила YARA — в %ProgramData%\StretchBIT\yara.
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename={#AppKey}-{#AppVersion}-setup
SetupIconFile=ui\assets\icon.ico
UninstallDisplayIcon={app}\{#ExeName}
UninstallDisplayName={#DisplayName}
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes
WizardStyle=modern
; запущенную программу просит закрыть (Restart Manager), сама потом не перезапускает
CloseApplications=yes
RestartApplications=no
ShowLanguageDialog=no

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Ярлык на рабочем столе"; GroupDescription: "Ярлыки:"

[Dirs]
; папки данных — только для программы с правами (запись пользователям не выдаётся)
Name: "{app}\app\logs"
Name: "{app}\app\cache"
Name: "{app}\app\reports"
Name: "{app}\app\quarantine_data"
Name: "{app}\app\signatures"
#if Edition == "test"
Name: "{app}\app\diag"
#endif

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "\app\native\windivert"; Flags: ignoreversion recursesubdirs createallsubdirs
; WinDivert (сборка кладёт по умолчанию) — отдельно: драйвер WinDivert64.sys, загруженный из этой
; папки, держит файл, пока работает. Остановка службы не помогает, если к драйверу подключился
; zapret (winws.exe): он не грузит свою копию, а берёт уже загруженную. С ignoreversion
; установка падала «DeleteFile: код 5» (Windows 10, 14.11.2026). Теперь та же версия не
; заменяется вовсе, новая при занятом файле — после перезагрузки (restartreplace), при
; удалении занятый файл удаляется после перезагрузки (uninsrestartdelete)
Source: "{#SourceDir}\app\native\windivert\*"; DestDir: "{app}\app\native\windivert"; Flags: restartreplace uninsrestartdelete skipifsourcedoesntexist

[Icons]
Name: "{autoprograms}\{#DisplayName}"; Filename: "{app}\{#ExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#DisplayName}"; Filename: "{app}\{#ExeName}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{autoprograms}\Удалить {#DisplayName}"; Filename: "{uninstallexe}"

[Run]
; владелец — «Администраторы» (файлы прежней установки без прав принадлежали пользователю, а
; владелец может вернуть себе запись); наследуемые права сброшены; S-1-5-32-544 —
; администраторы, S-1-5-18 — система, S-1-5-32-545 — пользователи
Filename: "{sys}\icacls.exe"; Parameters: """{app}"" /setowner *S-1-5-32-544 /T /C /Q"; Flags: runhidden; StatusMsg: "Закрываю папку программы от изменений..."
Filename: "{sys}\icacls.exe"; Parameters: """{app}"" /reset /T /C /Q"; Flags: runhidden
Filename: "{sys}\icacls.exe"; Parameters: """{app}"" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX /C /Q"; Flags: runhidden
; служба защиты: создать или обновить (путь, автозапуск, перезапуск при сбое) и запустить
Filename: "{app}\{#ExeName}"; Parameters: "--service-install"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; StatusMsg: "Устанавливаю службу защиты..."
Filename: "{app}\{#ExeName}"; Description: "Запустить {#DisplayName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; карантин, журналы работы, кэш, скачанные базы — всё, что программа создала в своей папке
Type: filesandordirs; Name: "{app}"

[Code]
var
  WipeSettings: Boolean;

{ прежний установщик (installer.py) писал запись «Приложения» под именем без _is1;
  версии до 1.0.0 ставились без прав администратора: их запись «Приложения» и ярлыки были
  у пользователя (HKCU, меню «Пуск» пользователя) — убираем, иначе всё задвоится }
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RegDeleteKeyIncludingSubkeys(HKCU,
      'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppKey}');
    RegDeleteKeyIncludingSubkeys(HKCU,
      'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppKey}_is1');
    DeleteFile(ExpandConstant('{userprograms}\{#DisplayName}.lnk'));
    DeleteFile(ExpandConstant('{userprograms}\Удалить {#DisplayName}.lnk'));
    if FileExists(ExpandConstant('{commondesktop}\{#DisplayName}.lnk')) then
      DeleteFile(ExpandConstant('{userdesktop}\{#DisplayName}.lnk'));
  end;
end;

{ копия папки данных (robocopy: коды 0–7 — успех) }
procedure CopyData(const Src, Dst: String);
var
  Code: Integer;
begin
  if DirExists(Src) then
    Exec(ExpandConstant('{sys}\robocopy.exe'),
         '"' + Src + '" "' + Dst + '" /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP', '', SW_HIDE,
         ewWaitUntilTerminated, Code);
end;

{ прежнее место установки (C:\Utils\SBIT): данные — в новую папку, старая копия убирает за
  собой (сеть после VPN, брандмауэр, ETW, автозапуск, меню Проводника, провайдер AMSI) — её
  же «--uninstall --silent», настройки в AppData остаются; затем папка удаляется }
procedure MoveOldInstall();
var
  Old, App: String;
  Code: Integer;
begin
  Old := '{#OldDir}';
  App := ExpandConstant('{app}');
  if (not DirExists(Old + '\app')) or (CompareText(Old, App) = 0) then
    exit;
  ForceDirectories(Old + '\app\cache');
  SaveStringToFile(Old + '\app\cache\no_restart', 'setup', False);
  ForceDirectories(App + '\app');
  CopyData(Old + '\app\quarantine_data', App + '\app\quarantine_data');
  CopyData(Old + '\app\logs', App + '\app\logs');
  CopyData(Old + '\app\reports', App + '\app\reports');
  if FileExists(Old + '\{#ExeName}') then
    Exec(Old + '\{#ExeName}', '--uninstall --silent', Old, SW_HIDE, ewWaitUntilTerminated, Code);
  DelTree(Old, True, True, True);
  RemoveDir(ExtractFileDir(Old));  { C:\Utils — только если пустая }
end;

{ установка 32-битным установщиком (до 64-битного режима) — в «Program Files (x86)»: данные
  переносятся, папка и запись «Приложения» в WOW6432Node удаляются. Деинсталлятор прежней копии
  НЕ запускается: он снял бы общие для обеих версий правила брандмауэра «SBIT» и прочее, а
  служба, ловушки и меню Проводника переходят к новой копии сами (--service-install и запуск) }
procedure MoveX86Install();
var
  Old, App: String;
begin
  Old := ExpandConstant('{commonpf32}\{#AppKey}');
  App := ExpandConstant('{app}');
  if (not DirExists(Old + '\app')) or (CompareText(Old, App) = 0) then
    exit;
  ForceDirectories(Old + '\app\cache');
  SaveStringToFile(Old + '\app\cache\no_restart', 'setup', False);
  ForceDirectories(App + '\app');
  CopyData(Old + '\app\quarantine_data', App + '\app\quarantine_data');
  CopyData(Old + '\app\logs', App + '\app\logs');
  CopyData(Old + '\app\reports', App + '\app\reports');
  DelTree(Old, True, True, True);
  RegDeleteKeyIncludingSubkeys(HKLM32,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppKey}_is1');
end;

{ служба держит StretchBIT.exe открытым: остановить до замены файлов. net stop ждёт, пока
  служба остановится; службы нет или не работает — код ошибки, это не мешает }
procedure StopService();
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\net.exe'), 'stop {#ServiceName}', '', SW_HIDE,
       ewWaitUntilTerminated, Code);
end;

{ окно программы на закрытие сворачивается в трей, у сторожа (--watchdog) окна нет: Restart
  Manager их не закрывает, и обновление откатывалось («не удалось закрыть приложения»).
  Закрываются процессы StretchBIT.exe только из папки этой установки (по пути, не по имени —
  другая версия и чужие программы не трогаются); метка no_restart уже стоит }
procedure CloseRunning();
var
  Code: Integer;
  App: String;
begin
  App := ExpandConstant('{app}');
  if not FileExists(App + '\{#ExeName}') then
    exit;
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
       '-NoProfile -NonInteractive -Command "$d = ''' + App + '\''; ' +
       'Get-Process -Name StretchBIT -ErrorAction SilentlyContinue | ' +
       'Where-Object { $_.Path -and $_.Path.StartsWith($d, ''OrdinalIgnoreCase'') } | ' +
       'Stop-Process -Force -ErrorAction SilentlyContinue"',
       '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

{ перед заменой файлов программу закроют: её сторож (selfguard.py) не должен вернуть её }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  StopService();
  if DirExists(ExpandConstant('{app}\app')) then
  begin
    ForceDirectories(ExpandConstant('{app}\app\cache'));
    SaveStringToFile(ExpandConstant('{app}\app\cache\no_restart'), 'setup', False);
  end;
  CloseRunning();
  MoveOldInstall();
  MoveX86Install();
end;

{ окно перед удалением: флажок «Удалить все настройки пользователя» }
function InitializeUninstall(): Boolean;
var
  Form: TSetupForm;
  Text: TNewStaticText;
  Box: TNewCheckBox;
  OkButton, CancelButton: TNewButton;
begin
  WipeSettings := False;
  if UninstallSilent then
  begin
    Result := True;
    exit;
  end;
  Form := CreateCustomForm(ScaleX(460), ScaleY(190), False, True);
  try
    Form.Caption := 'Удаление {#DisplayName}';
    Text := TNewStaticText.Create(Form);
    Text.Parent := Form;
    Text.Left := ScaleX(16);
    Text.Top := ScaleY(16);
    Text.Width := Form.ClientWidth - ScaleX(32);
    Text.AutoSize := False;
    Text.WordWrap := True;
    Text.Height := ScaleY(64);
    Text.Caption := 'Программа будет закрыта, её автозапуск и пункт меню Проводника убраны, ' +
      'настройки сети после VPN возвращены. Папка ' + ExpandConstant('{app}') +
      ' будет удалена целиком — ' +
      'вместе с карантином, журналами и отчётами.';
    Box := TNewCheckBox.Create(Form);
    Box.Parent := Form;
    Box.Left := ScaleX(16);
    Box.Top := ScaleY(88);
    Box.Width := Form.ClientWidth - ScaleX(32);
    Box.Height := ScaleY(36);
    Box.Caption := 'Удалить все настройки пользователя (настройки, журнал действий, ' +
      'белый список, исключения, профили VPN, правила брандмауэра)';
    Box.Checked := False;
    OkButton := TNewButton.Create(Form);
    OkButton.Parent := Form;
    OkButton.Caption := 'Удалить';
    OkButton.Width := ScaleX(96);
    OkButton.Height := ScaleY(26);
    OkButton.Left := Form.ClientWidth - ScaleX(16 + 96 + 8 + 96);
    OkButton.Top := Form.ClientHeight - ScaleY(16 + 26);
    OkButton.ModalResult := mrOk;
    OkButton.Default := True;
    CancelButton := TNewButton.Create(Form);
    CancelButton.Parent := Form;
    CancelButton.Caption := 'Отмена';
    CancelButton.Width := ScaleX(96);
    CancelButton.Height := ScaleY(26);
    CancelButton.Left := Form.ClientWidth - ScaleX(16 + 96);
    CancelButton.Top := OkButton.Top;
    CancelButton.ModalResult := mrCancel;
    CancelButton.Cancel := True;
    Result := Form.ShowModal() = mrOk;
    WipeSettings := Box.Checked;
  finally
    Form.Free();
  end;
end;

{ шаги удаления самой программы — с правами администратора (брандмауэр, ETW);
  отказ в UAC — без прав: то, что можно, всё равно уберётся }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Params: String;
  Code: Integer;
begin
  if CurUninstallStep <> usUninstall then
    exit;
  Params := '--uninstall --silent';
  if WipeSettings then
    Params := Params + ' --wipe';
  if FileExists(ExpandConstant('{app}\{#ExeName}')) then
    if not ShellExec('runas', ExpandConstant('{app}\{#ExeName}'), Params,
                     ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code) then
      Exec(ExpandConstant('{app}\{#ExeName}'), Params, ExpandConstant('{app}'), SW_HIDE,
           ewWaitUntilTerminated, Code);
  { на случай, если программа не смогла (нет файла, ошибка): служба не должна остаться
    указывать на удалённую папку }
  StopService();
  Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#ServiceName}', '', SW_HIDE,
       ewWaitUntilTerminated, Code);
  if WipeSettings then
    DelTree(ExpandConstant('{userappdata}\{#ConfigName}'), True, True, True);
end;
