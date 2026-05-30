; =============================================================================
; Inno Setup script for the SMTP Relay native-Windows package.
; =============================================================================

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef StageDir
  #define StageDir "staging"
#endif
#ifndef OutDir
  #define OutDir "."
#endif

#define MyAppName "SMTP Relay"
#define MyAppPublisher "SMTP Relay"

[Setup]
AppId={{8F4C2B7A-3E5D-4C9A-9B21-7A6E1D2F3C40}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\smtp-relay

DefaultGroupName={#MyAppName}
DisableProgramGroupPage=no
AlwaysShowGroupOnReadyPage=yes

PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=smtp-relay-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopfolder"; Description: "Create a Desktop shortcut folder"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
; --- MENU START ---
Name: "{group}\SMTP Relay Admin Panel"; Filename: "{app}\panel.url"
Name: "{group}\Start SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action start"; WorkingDir: "{app}"
Name: "{group}\Stop SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action stop"; WorkingDir: "{app}"
Name: "{group}\Restart SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action restart"; WorkingDir: "{app}"
Name: "{group}\SMTP Relay Status"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action status"; WorkingDir: "{app}"
Name: "{group}\Data and Logs folder"; Filename: "{win}\explorer.exe"; \
  Parameters: """{commonappdata}\smtp-relay"""; IconFilename: "{sys}\imageres.dll"; IconIndex: 3
Name: "{group}\Uninstall SMTP Relay"; Filename: "{uninstallexe}"

; --- CARTELLA DESKTOP ---
Name: "{autodesktop}\{#MyAppName}\SMTP Relay Panel"; Filename: "{app}\panel.url"; Tasks: desktopfolder
Name: "{autodesktop}\{#MyAppName}\Start SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action start"; WorkingDir: "{app}"; Tasks: desktopfolder
Name: "{autodesktop}\{#MyAppName}\Stop SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action stop"; WorkingDir: "{app}"; Tasks: desktopfolder
Name: "{autodesktop}\{#MyAppName}\SMTP Relay Status"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action status"; WorkingDir: "{app}"; Tasks: desktopfolder

[UninstallDelete]
; Forza la rimozione della cartella sul desktop alla disinstallazione (se vuota)
Type: dirifempty; Name: "{autodesktop}\{#MyAppName}"

[Run]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install.ps1"" -InstallDir ""{app}"""; \
  StatusMsg: "Installing services and initialising the database..."; \
  Flags: waituntilterminated
Filename: "http://127.0.0.1:8000"; Description: "Open the admin panel now"; \
  Flags: postinstall shellexec nowait skipifsilent

[Code]
procedure StopRelayServices;
var
  rc: Integer;
begin
  Exec('net', 'stop smtp-relay-ui', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec('net', 'stop smtp-relay-relay', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Sleep(1500);
end;

procedure RefreshStartMenu;
var
  rc: Integer;
begin
  { Best-effort: on Windows 11 the "All apps" list is cached and a freshly
    created program group often shows only under "Recently added" until the
    cache rebuilds. Restarting StartMenuExperienceHost forces that rebuild and
    is harmless (Windows relaunches it immediately; it only closes the Start
    flyout for a moment, unlike restarting explorer.exe). }
  Exec('taskkill', '/f /im StartMenuExperienceHost.exe', '', SW_HIDE, ewNoWait, rc);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopRelayServices
  else if CurStep = ssPostInstall then
    RefreshStartMenu;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  rc: Integer;
  params: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    params := '-NoProfile -ExecutionPolicy Bypass -File "' +
      ExpandConstant('{app}\uninstall.ps1') + '" -InstallDir "' +
      ExpandConstant('{app}') + '"';
    if MsgBox('Remove ALL SMTP Relay data too?' + #13#10#13#10 +
              'This permanently deletes the database, the mail archive, the ' +
              'configuration and the encryption keys in ' +
              'C:\ProgramData\smtp-relay.' + #13#10#13#10 +
              'Choose No to keep them for a future reinstall.',
              mbConfirmation, MB_YESNO) = IDYES then
      params := params + ' -RemoveData';
    Exec('powershell.exe', params, '', SW_SHOW, ewWaitUntilTerminated, rc);
  end;
end;
