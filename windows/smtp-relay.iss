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
DisableProgramGroupPage=yes
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

[Tasks]
Name: "openpanel"; Description: "Open the admin panel after install"; Flags: checkedonce

[Files]
; The entire staged payload, preserving the app\ subfolder layout.
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Run]
; Configure services, keys, DB and firewall. Visible window so the operator can
; read the one-time admin password printed at the end.
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install.ps1"" -InstallDir ""{app}"""; \
  StatusMsg: "Installing services and initialising the database..."; \
  Flags: waituntilterminated
; Optionally open the panel in the default browser.
Filename: "http://127.0.0.1:8000"; Flags: postinstall shellexec nowait skipifsilent; \
  Description: "Open the admin panel"; Tasks: openpanel

[UninstallRun]
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall.ps1"" -InstallDir ""{app}"""; \
  Flags: runhidden waituntilterminated; \
  RunOnceId: "RemoveSmtpRelayServices"
