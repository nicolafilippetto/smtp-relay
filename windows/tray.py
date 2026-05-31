"""System-tray controller for SMTP Relay (Windows).

A small tray icon that shows whether the two Windows services are running and
offers quick actions (open panel, open data/logs folder, start/stop/restart).
It runs in the user's session and is started at logon by a Startup shortcut
that launches it hidden via start-tray.vbs (so there is no console window).

Status colours:
  * green   - both services running
  * orange  - only one running
  * grey    - both stopped (dark grey on a light theme, light grey on a dark
              theme, so it stays visible against the taskbar)

Service control needs elevation, so those actions are delegated to manage.ps1,
which self-elevates (a single UAC prompt). Status polling (`sc query`) needs no
elevation.

Only the Pillow import is at module top (it imports fine everywhere, which keeps
the helpers unit-testable off-Windows); pystray is imported lazily inside main()
because it needs a GUI backend.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

from PIL import Image, ImageDraw

SERVICES = ("smtp-relay-relay", "smtp-relay-ui")
PANEL_URL = "http://127.0.0.1:8000"

# Avoid flashing a console window for the helper subprocesses on Windows; the
# flag does not exist off-Windows, so fall back to 0 to keep this importable.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

def data_dir() -> Path:
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    return Path(base) / "smtp-relay"


def manage_script() -> Path:
    """Locate manage.ps1 relative to the running executable.

    Install layout: <install>\\app\\smtp-relay.exe and <install>\\manage.ps1,
    so manage.ps1 is normally the exe's grandparent dir. Fall back to a couple
    of other locations for dev runs.
    """
    here = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve()
    for candidate in (
        here.parent.parent / "manage.ps1",   # frozen: <install>\manage.ps1
        here.parent / "manage.ps1",
        Path(__file__).resolve().parent / "manage.ps1",  # source tree
    ):
        if candidate.is_file():
            return candidate
    # Last resort: assume alongside the install dir.
    return here.parent.parent / "manage.ps1"


# -----------------------------------------------------------------------------
# Service status
# -----------------------------------------------------------------------------

def service_running(name: str) -> bool:
    try:
        out = subprocess.run(
            ["sc", "query", name],
            capture_output=True, text=True, creationflags=_NO_WINDOW,
        )
        return "RUNNING" in out.stdout
    except Exception:
        return False


def status() -> str:
    states = [service_running(s) for s in SERVICES]
    if all(states):
        return "running"
    if any(states):
        return "partial"
    return "stopped"


# -----------------------------------------------------------------------------
# Icon
# -----------------------------------------------------------------------------

def uses_light_theme() -> bool:
    """True if Windows is using a light theme (taskbar light). Defaults True."""
    if os.name != "nt":
        return True
    try:
        import winreg
        key = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            val, _ = winreg.QueryValueEx(k, "SystemUsesLightTheme")
            return bool(val)
    except OSError:
        return True


def make_icon(state: str) -> Image.Image:
    """Render a 64x64 status dot."""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    if state == "running":
        fill = (40, 200, 80, 255)        # green
    elif state == "partial":
        fill = (240, 170, 40, 255)       # orange
    else:
        # stopped: theme-aware grey so it stays visible on the taskbar
        fill = (60, 60, 60, 255) if uses_light_theme() else (225, 225, 225, 255)
    # Outline contrasts with the fill for definition.
    outline = (0, 0, 0, 90) if uses_light_theme() else (255, 255, 255, 90)
    draw.ellipse([8, 8, size - 8, size - 8], fill=fill, outline=outline, width=3)
    return img


# -----------------------------------------------------------------------------
# Actions
# -----------------------------------------------------------------------------

def open_panel() -> None:
    webbrowser.open(PANEL_URL)


def open_data_folder() -> None:
    target = str(data_dir())
    try:
        os.startfile(target)  # type: ignore[attr-defined]  # Windows only
    except Exception:
        webbrowser.open(target)


def run_manage(action: str) -> None:
    """Invoke manage.ps1 (which self-elevates) for start/stop/restart."""
    script = str(manage_script())
    subprocess.Popen(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", script, "-Action", action],
        creationflags=_NO_WINDOW,
    )


# -----------------------------------------------------------------------------
# Tray app
# -----------------------------------------------------------------------------

def main() -> int:
    import pystray

    def _status_text(_item) -> str:
        st = status()
        label = {"running": "running", "partial": "partial", "stopped": "stopped"}[st]
        return f"Services: {label}"

    menu = pystray.Menu(
        pystray.MenuItem(_status_text, None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open admin panel", lambda: open_panel(), default=True),
        pystray.MenuItem("Open config / logs folder", lambda: open_data_folder()),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Start services", lambda: run_manage("start")),
        pystray.MenuItem("Stop services", lambda: run_manage("stop")),
        pystray.MenuItem("Restart services", lambda: run_manage("restart")),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit tray", lambda icon, item: icon.stop()),
    )

    icon = pystray.Icon(
        "smtp-relay",
        make_icon(status()),
        "SMTP Relay",
        menu=menu,
    )

    def _poller() -> None:
        last = None
        while getattr(icon, "visible", True) or last is None:
            st = status()
            if st != last:
                try:
                    icon.icon = make_icon(st)
                    icon.title = f"SMTP Relay - services {st}"
                    # Refresh the dynamic menu text ("Services: ...") in step with
                    # the icon; otherwise pystray keeps showing the cached value
                    # and the menu line lags behind the colour.
                    icon.update_menu()
                except Exception:
                    pass
                last = st
            time.sleep(5)

    threading.Thread(target=_poller, daemon=True).start()
    icon.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
