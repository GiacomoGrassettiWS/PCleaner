# -*- coding: utf-8 -*-
"""
Generate the PCleaner application icon (pie chart on a green background).

Produces:
  - icon.ico  (multi-resolution: 16, 32, 48, 64, 128, 256)
  - icon.png  (256x256, for the README / preview)

Run: python generate_icon.py
"""

import math
from PIL import Image, ImageDraw

SS = 4                      # supersampling factor for smooth edges
BASE = 256
S = BASE * SS              # working canvas size


def lerp(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def rounded_mask(size, radius):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return m


def vertical_gradient(size, top, bottom):
    grad = Image.new("RGB", (size, size), top)
    px = grad.load()
    for y in range(size):
        t = y / (size - 1)
        c = lerp(top, bottom, t)
        for x in range(size):
            px[x, y] = c
    return grad


def draw_pie(img):
    d = ImageDraw.Draw(img)
    cx, cy = S * 0.5, S * 0.52
    r = S * 0.30

    # Soft drop shadow behind the pie
    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    sd = ImageDraw.Draw(shadow)
    off = S * 0.02
    sd.ellipse([cx - r + off, cy - r + off * 2, cx + r + off, cy + r + off * 2],
               fill=(0, 0, 0, 70))
    shadow = shadow.filter(__import__("PIL.ImageFilter", fromlist=["GaussianBlur"])
                           .GaussianBlur(S * 0.012))
    img.alpha_composite(shadow)

    # White base disk (so slices read cleanly on the green background)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255, 255))

    # Slices (proportion, color). The last slice is "freed space": exploded out.
    slices = [
        (0.34, (78, 121, 167)),    # blue
        (0.24, (242, 142, 43)),    # orange
        (0.20, (118, 183, 178)),   # teal
        (0.22, None),              # freed -> exploded, light
    ]

    gap = S * 0.012  # white separation between slices
    start = -90.0
    for frac, color in slices:
        extent = 360.0 * frac
        end = start + extent
        mid = math.radians((start + end) / 2.0)

        if color is None:
            # Exploded "freed" slice: offset outward, light gray + dashed look
            dx = math.cos(mid) * (S * 0.07)
            dy = math.sin(mid) * (S * 0.07)
            bbox = [cx - r + dx, cy - r + dy, cx + r + dx, cy + r + dy]
            d.pieslice(bbox, start, end, fill=(225, 232, 226, 255),
                       outline=(255, 255, 255, 255), width=int(S * 0.012))
        else:
            bbox = [cx - r, cy - r, cx + r, cy + r]
            d.pieslice(bbox, start, end, fill=color + (255,),
                       outline=(255, 255, 255, 255), width=int(gap))
        start = end

    # Thin white ring around the (non-exploded) disk for crisp contrast
    d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(255, 255, 255, 255),
              width=int(S * 0.018))

    # Small sparkle (clean!) near the freed slice
    sx, sy = cx + r * 0.95, cy - r * 0.75
    a = S * 0.035
    d.polygon([(sx, sy - a), (sx + a * 0.32, sy - a * 0.32),
               (sx + a, sy), (sx + a * 0.32, sy + a * 0.32),
               (sx, sy + a), (sx - a * 0.32, sy + a * 0.32),
               (sx - a, sy), (sx - a * 0.32, sy - a * 0.32)],
              fill=(255, 255, 255, 255))


def main():
    # Green gradient background
    bg = vertical_gradient(S, (31, 184, 102), (12, 122, 61)).convert("RGBA")

    # Apply rounded corners
    mask = rounded_mask(S, int(S * 0.22))
    bg.putalpha(mask)

    draw_pie(bg)

    # Downscale to base size with antialiasing
    icon = bg.resize((BASE, BASE), Image.LANCZOS)
    icon.save("icon.png")

    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    icon.save("icon.ico", sizes=sizes)
    print("Created icon.ico and icon.png")


if __name__ == "__main__":
    main()
