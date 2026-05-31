"""Generate the SMTP Relay shortcut/app icons as multi-resolution .ico files.

Flat, modern look: a solid coloured disc with a white glyph that hints at the
action. Drawn at 4x and downscaled for anti-aliasing, then saved as .ico with
the standard sizes Windows expects (16/32/48/64/128/256).

Run from the repo root:  python windows/icons/generate_icons.py
Requires Pillow (already in windows/requirements.txt).
"""

from __future__ import annotations

import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
S = 1024  # supersampled canvas
ICON_SIZES = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

# Palette (R, G, B)
BLUE = (37, 99, 235)
GREEN = (22, 163, 74)
RED = (220, 38, 38)
AMBER = (217, 119, 6)
CYAN = (8, 145, 178)
VIOLET = (124, 58, 237)
YELLOW = (245, 158, 11)
WHITE = (255, 255, 255, 255)


def _canvas():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    return img, ImageDraw.Draw(img)


def _disc(draw, color):
    m = int(S * 0.06)
    draw.ellipse([m, m, S - m, S - m], fill=color + (255,))


def _save(img: Image.Image, name: str):
    small = img.resize((256, 256), Image.LANCZOS)
    small.save(os.path.join(HERE, name), format="ICO", sizes=ICON_SIZES)
    print("wrote", name)


def app_icon():
    """Envelope = the relay / web panel."""
    img, d = _canvas()
    _disc(d, BLUE)
    # Envelope body
    x0, y0, x1, y1 = S * 0.26, S * 0.34, S * 0.74, S * 0.66
    d.rounded_rectangle([x0, y0, x1, y1], radius=S * 0.03, fill=WHITE)
    # Flap (triangle)
    d.line([(x0, y0), ((x0 + x1) / 2, S * 0.52), (x1, y0)],
           fill=BLUE + (255,), width=int(S * 0.025), joint="curve")
    return img


def start_icon():
    """Play triangle."""
    img, d = _canvas()
    _disc(d, GREEN)
    d.polygon([(S * 0.40, S * 0.34), (S * 0.40, S * 0.66), (S * 0.68, S * 0.50)], fill=WHITE)
    return img


def stop_icon():
    """Stop square."""
    img, d = _canvas()
    _disc(d, RED)
    d.rounded_rectangle([S * 0.38, S * 0.38, S * 0.62, S * 0.62], radius=S * 0.02, fill=WHITE)
    return img


def restart_icon():
    """Circular arrow (refresh)."""
    img, d = _canvas()
    _disc(d, AMBER)
    bbox = [S * 0.36, S * 0.36, S * 0.64, S * 0.64]
    d.arc(bbox, start=40, end=320, fill=WHITE, width=int(S * 0.045))
    # Arrowhead at the open end (~40 deg).
    import math
    cx, cy, r = S * 0.50, S * 0.50, S * 0.14
    ang = math.radians(40)
    tx, ty = cx + r * math.cos(ang), cy + r * math.sin(ang)
    h = S * 0.06
    d.polygon([(tx - h, ty - h), (tx + h, ty - h * 0.2), (tx - h * 0.2, ty + h)], fill=WHITE)
    return img


def status_icon():
    """Info 'i'."""
    img, d = _canvas()
    _disc(d, CYAN)
    d.ellipse([S * 0.47, S * 0.33, S * 0.53, S * 0.39], fill=WHITE)        # dot
    d.rounded_rectangle([S * 0.47, S * 0.43, S * 0.53, S * 0.66], radius=S * 0.02, fill=WHITE)  # stem
    return img


def reset_icon():
    """Key = password reset."""
    img, d = _canvas()
    _disc(d, VIOLET)
    # Bow (ring)
    d.ellipse([S * 0.34, S * 0.40, S * 0.52, S * 0.58], outline=WHITE, width=int(S * 0.05))
    # Shaft + two teeth
    d.line([(S * 0.50, S * 0.49), (S * 0.70, S * 0.49)], fill=WHITE, width=int(S * 0.045))
    d.line([(S * 0.64, S * 0.49), (S * 0.64, S * 0.58)], fill=WHITE, width=int(S * 0.045))
    d.line([(S * 0.70, S * 0.49), (S * 0.70, S * 0.56)], fill=WHITE, width=int(S * 0.045))
    return img


def folder_icon():
    """Folder = data/logs."""
    img, d = _canvas()
    _disc(d, YELLOW)
    # Back tab + body
    d.rounded_rectangle([S * 0.30, S * 0.38, S * 0.52, S * 0.46], radius=S * 0.015, fill=WHITE)
    d.rounded_rectangle([S * 0.30, S * 0.42, S * 0.70, S * 0.64], radius=S * 0.02, fill=WHITE)
    return img


def main():
    _save(app_icon(), "app.ico")
    _save(start_icon(), "start.ico")
    _save(stop_icon(), "stop.ico")
    _save(restart_icon(), "restart.ico")
    _save(status_icon(), "status.ico")
    _save(reset_icon(), "reset.ico")
    _save(folder_icon(), "folder.ico")


if __name__ == "__main__":
    main()
