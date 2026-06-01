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
Name: "{group}\SMTP Relay Admin Panel"; Filename: "{app}\panel.url"; \
  IconFilename: "{app}\icons\app.ico"
Name: "{group}\Start SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action start"; WorkingDir: "{app}"; \
  IconFilename: "{app}\icons\start.ico"
Name: "{group}\Stop SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action stop"; WorkingDir: "{app}"; \
  IconFilename: "{app}\icons\stop.ico"
Name: "{group}\Restart SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action restart"; WorkingDir: "{app}"; \
  IconFilename: "{app}\icons\restart.ico"
Name: "{group}\SMTP Relay Status"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action status"; WorkingDir: "{app}"; \
  IconFilename: "{app}\icons\status.ico"
Name: "{group}\Reset admin password"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action reset-admin"; WorkingDir: "{app}"; \
  IconFilename: "{app}\icons\reset.ico"
Name: "{group}\Data and Logs folder"; Filename: "{win}\explorer.exe"; \
  Parameters: """{commonappdata}\smtp-relay"""; IconFilename: "{app}\icons\folder.ico"
Name: "{group}\SMTP Relay Tray icon"; Filename: "{sys}\wscript.exe"; \
  Parameters: """{app}\start-tray.vbs"""; WorkingDir: "{app}"; \
  IconFilename: "{app}\icons\app.ico"
Name: "{group}\Uninstall SMTP Relay"; Filename: "{uninstallexe}"

; --- AUTOSTART (tray icon at logon, all users) ---
Name: "{commonstartup}\SMTP Relay Tray"; Filename: "{sys}\wscript.exe"; \
  Parameters: """{app}\start-tray.vbs"""; WorkingDir: "{app}"; \
  IconFilename: "{app}\icons\app.ico"

; --- CARTELLA DESKTOP ---
Name: "{autodesktop}\{#MyAppName}\SMTP Relay Panel"; Filename: "{app}\panel.url"; Tasks: desktopfolder; \
  IconFilename: "{app}\icons\app.ico"
Name: "{autodesktop}\{#MyAppName}\Start SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action start"; WorkingDir: "{app}"; Tasks: desktopfolder; \
  IconFilename: "{app}\icons\start.ico"
Name: "{autodesktop}\{#MyAppName}\Stop SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action stop"; WorkingDir: "{app}"; Tasks: desktopfolder; \
  IconFilename: "{app}\icons\stop.ico"
Name: "{autodesktop}\{#MyAppName}\SMTP Relay Status"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action status"; WorkingDir: "{app}"; Tasks: desktopfolder; \
  IconFilename: "{app}\icons\status.ico"

[UninstallDelete]
; Forza la rimozione della cartella sul desktop alla disinstallazione (se vuota)
Type: dirifempty; Name: "{autodesktop}\{#MyAppName}"

[Run]
; Run the setup script hidden (no PowerShell console window). Everything is
; captured to install-log.txt, and the finish-page checkboxes below give the
; operator the admin password and the panel. The chosen ports are passed
; through (ignored on an upgrade, which keeps the existing config.env).
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{app}\install.ps1"" -InstallDir ""{app}"" -SmtpPort {code:GetSmtpPort} -UiPort {code:GetUiPort}"; \
  StatusMsg: "Installing services and initialising the database..."; \
  Flags: runhidden waituntilterminated
; On a FRESH install only, offer to open the first-login note (admin password).
Filename: "{commonappdata}\smtp-relay\FIRST-LOGIN.txt"; \
  Description: "Show the first-login details (admin password)"; \
  Flags: postinstall shellexec nowait skipifsilent; Check: FreshInstall
; Always offer to open the admin panel (at the chosen / configured web port).
Filename: "{code:GetPanelUrl}"; Description: "Open the admin panel now"; \
  Flags: postinstall shellexec nowait skipifsilent

[Code]
var
  IsUpgrade: Boolean;          { an existing install was detected }
  PortPage: TInputQueryWizardPage;

{ A new admin (with a one-time password) was created this run -> the file is
  present. Used to offer opening FIRST-LOGIN.txt only on a real fresh install. }
function FreshInstall: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonappdata}\smtp-relay\FIRST-LOGIN.txt'));
end;

function GetSmtpPort(Param: String): String;
begin
  if IsUpgrade then Result := '2525'
  else Result := Trim(PortPage.Values[0]);
end;

function GetUiPort(Param: String): String;
begin
  if IsUpgrade then Result := '8000'
  else Result := Trim(PortPage.Values[1]);
end;

function GetPanelUrl(Param: String): String;
begin
  { On a fresh install use the chosen web port; on an upgrade default to 8000
    (install.ps1 still honours whatever is in the existing config.env). }
  if IsUpgrade then Result := 'http://127.0.0.1:8000'
  else Result := 'http://127.0.0.1:' + Trim(PortPage.Values[1]);
end;

procedure InitializeWizard;
begin
  IsUpgrade := FileExists(ExpandConstant('{commonappdata}\smtp-relay\config.env'));

  { Port page — shown only on a fresh install (see ShouldSkipPage). }
  PortPage := CreateInputQueryPage(wpSelectDir,
    'Network ports',
    'Choose the ports SMTP Relay will listen on',
    'You can keep the defaults or change them. Standard SMTP is port 25; 2525 ' +
    'avoids needing to free port 25. The web panel default is 8000. The ' +
    'installer checks each port is free before continuing.');
  PortPage.Add('SMTP port (mail in):', False);
  PortPage.Add('Web panel port:', False);
  PortPage.Values[0] := '2525';
  PortPage.Values[1] := '8000';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  { Skip the port page on an upgrade (we keep the existing config.env). }
  Result := (PageID = PortPage.ID) and IsUpgrade;
end;

{ Validate the two ports as the user leaves the port page: numeric, 1..65535,
  distinct, and not already in use on this machine. }
function ValidatePort(Caption, Value: String): Boolean;
var
  n, code: Integer;
begin
  Result := False;
  Value := Trim(Value);
  if Value = '' then begin
    MsgBox(Caption + ': please enter a port number.', mbError, MB_OK);
    exit;
  end;
  for code := 1 to Length(Value) do
    if (Value[code] < '0') or (Value[code] > '9') then begin
      MsgBox(Caption + ': only digits are allowed.', mbError, MB_OK);
      exit;
    end;
  n := StrToIntDef(Value, -1);
  if (n < 1) or (n > 65535) then begin
    MsgBox(Caption + ': the port must be between 1 and 65535.', mbError, MB_OK);
    exit;
  end;
  Result := True;
end;

{ Returns True if something is already listening on the TCP port (PowerShell). }
function PortInUse(Port: String): Boolean;
var
  rc: Integer;
begin
  { exit code 0 = a listener was found = port in use. }
  Exec('powershell.exe',
    '-NoProfile -ExecutionPolicy Bypass -Command "if (Get-NetTCPConnection -State Listen -LocalPort ' +
    Port + ' -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"',
    '', SW_HIDE, ewWaitUntilTerminated, rc);
  Result := (rc = 0);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  smtp, web: String;
begin
  Result := True;
  if (CurPageID = PortPage.ID) and (not IsUpgrade) then
  begin
    smtp := Trim(PortPage.Values[0]);
    web := Trim(PortPage.Values[1]);
    if not ValidatePort('SMTP port', smtp) then begin Result := False; exit; end;
    if not ValidatePort('Web panel port', web) then begin Result := False; exit; end;
    if smtp = web then begin
      MsgBox('The SMTP port and the web panel port must be different.', mbError, MB_OK);
      Result := False; exit;
    end;
    if PortInUse(smtp) then begin
      MsgBox('The SMTP port ' + smtp + ' is already in use by another program. Choose a different port.', mbError, MB_OK);
      Result := False; exit;
    end;
    if PortInUse(web) then begin
      MsgBox('The web panel port ' + web + ' is already in use by another program. Choose a different port.', mbError, MB_OK);
      Result := False; exit;
    end;
  end;
end;

{ On an upgrade, tell the user up-front what will happen. }
procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpReady) and IsUpgrade then
    MsgBox('SMTP Relay is already installed.' + #13#10#13#10 +
           'This will UPDATE the program files and keep your existing data, ' +
           'configuration and ports unchanged.' + #13#10#13#10 +
           'To change the ports or other settings, either edit ' +
           'C:\ProgramData\smtp-relay\config.env, or uninstall and reinstall.',
           mbInformation, MB_OK);
end;

procedure StopRelayServices;
var
  rc: Integer;
begin
  Exec('net', 'stop smtp-relay-ui', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec('net', 'stop smtp-relay-relay', '', SW_HIDE, ewWaitUntilTerminated, rc);
  { Also stop the tray (smtp-relay.exe in the user's session) so the new EXE is
    not locked while we copy files during a reinstall/upgrade. }
  Exec('taskkill', '/f /im smtp-relay.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
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

procedure LaunchTrayAsUser;
var
  rc: Integer;
begin
  { Start the tray now, DE-elevated: a process launched via explorer.exe runs
    with the logged-on user's normal token instead of Setup's admin token, so
    the tray (and the folder it opens) behave as a normal user app. The .vbs
    starts smtp-relay.exe tray hidden. Best-effort; if it fails, the Startup
    shortcut launches it at the next logon anyway. }
  Exec(ExpandConstant('{win}\explorer.exe'),
       '"' + ExpandConstant('{app}\start-tray.vbs') + '"',
       '', SW_HIDE, ewNoWait, rc);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopRelayServices
  else if CurStep = ssPostInstall then
  begin
    RefreshStartMenu;
    LaunchTrayAsUser;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  rc: Integer;
  params: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    { Stop the tray so its smtp-relay.exe stops locking the install folder. }
    Exec('taskkill', '/f /im smtp-relay.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
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
