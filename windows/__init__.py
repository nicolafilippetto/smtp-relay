"""Windows packaging helpers.

This package contains the native-Windows entry point (``launcher.py``) and
the build/install assets (PyInstaller spec, Inno Setup script, WinSW service
definitions, PowerShell installer). None of it is imported by the Docker
deployment — the Linux/Docker path is completely unaffected.
"""
