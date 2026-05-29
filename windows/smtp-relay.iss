; =============================================================================
; Inno Setup script for the SMTP Relay native-Windows package.
; Produces a single smtp-relay-setup.exe wizard that installs the application
; bundle, registers the two Windows services and configures everything via
; install.ps1.
;
; Build (from the repo root, on Windows, after staging the payload):
;   iscc /DMyAppVersion=1.2.3 /DStageDir=<abs path to staging> windows\smtp-relay.iss
;
; The staging directory must contain:
;   app\                     (the PyInstaller onedir bundle contents)
;   smtp-relay-relay.exe     (WinSW, renamed)   + smtp-relay-relay.xml
;   smtp-relay-ui.exe        (WinSW, renamed)   + smtp-relay-ui.xml
;   install.ps1  uninstall.ps1  config.env.template  README-windows.md
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
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=smtp-relay-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; A code-signing step can be wired in later via SignTool (see the CI workflow).

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; The entire staged payload, preserving the app\ subfolder layout.
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
; Start-Menu group with day-to-day management shortcuts. The manage.ps1 script
; self-elevates (UAC prompt) for the actions that need Administrator rights.
Name: "{group}\SMTP Relay Admin Panel"; Filename: "{app}\panel.url"
Name: "{group}\Start SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action start"; \
  WorkingDir: "{app}"
Name: "{group}\Stop SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action stop"; \
  WorkingDir: "{app}"
Name: "{group}\Restart SMTP Relay"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action restart"; \
  WorkingDir: "{app}"
Name: "{group}\SMTP Relay Status"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\manage.ps1"" -Action status"; \
  WorkingDir: "{app}"
Name: "{group}\Data and Logs folder"; Filename: "{commonappdata}\smtp-relay"
Name: "{group}\Uninstall SMTP Relay"; Filename: "{uninstallexe}"

[Run]
; Configure services, keys, DB and firewall. Visible window so the operator can
; read the one-time admin password printed at the end.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install.ps1"" -InstallDir ""{app}"""; \
  StatusMsg: "Installing services and initialising the database..."; \
  Flags: waituntilterminated
; Single finish-page checkbox to open the panel (asked once, at the end).
Filename: "http://127.0.0.1:8000"; Description: "Open the admin panel now"; \
  Flags: postinstall shellexec nowait skipifsilent

[Code]
{ Stop the services before files are copied, otherwise the running EXEs are
  locked and a reinstall/upgrade fails. "net stop" is a clean stop (WinSW does
  not treat it as a failure, so it won't auto-restart). Harmless if the
  services do not exist yet (first install). }
procedure StopRelayServices;
var
  rc: Integer;
begin
  Exec('net', 'stop smtp-relay-ui', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec('net', 'stop smtp-relay-relay', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Sleep(1500);  { give the wrapper processes a moment to release file handles }
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopRelayServices;
end;

{ On uninstall, ask whether to also wipe the data directory (DB, archive,
  config, keys), then run uninstall.ps1 accordingly. }
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
