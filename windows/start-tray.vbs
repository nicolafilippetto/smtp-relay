' Launch the SMTP Relay tray icon with no visible console window.
' Resolves smtp-relay.exe relative to this script's folder (the install dir),
' then runs "<install>\app\smtp-relay.exe tray" hidden (window style 0).
Option Explicit
Dim shell, scriptDir, exePath
Set shell = CreateObject("WScript.Shell")
scriptDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
exePath = scriptDir & "app\smtp-relay.exe"
shell.Run """" & exePath & """ tray", 0, False
