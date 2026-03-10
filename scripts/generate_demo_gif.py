#!/usr/bin/env python3

from __future__ import annotations

import math
import os
import subprocess
import sys
import textwrap
from pathlib import Path


def ensure_pillow() -> None:
    candidate_roots = []

    if os.environ.get("TRACEROOT_GIF_LIB"):
        candidate_roots.append(os.environ["TRACEROOT_GIF_LIB"])

    candidate_roots.append("/tmp/traceroot-gif-lib")

    for root in candidate_roots:
        if root and root not in sys.path and Path(root).exists():
            sys.path.insert(0, root)

    try:
        global Image, ImageDraw, ImageFont, ImageColor
        from PIL import Image, ImageColor, ImageDraw, ImageFont
    except ModuleNotFoundError as error:
        raise SystemExit(
            "Pillow is required for GIF generation. Install it temporarily with "
            "`python3 -m pip install Pillow --target /tmp/traceroot-gif-lib`."
        ) from error


ensure_pillow()

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "docs" / "assets" / "traceroot-demo.gif"
CANVAS_SIZE = (1200, 720)
FRAME_COUNT = 20
FRAME_DURATION_MS = 750


def load_font(size: int, mono: bool = False, bold: bool = False):
    font_candidates = []

    if mono:
        font_candidates.extend(
            [
                "/System/Library/Fonts/Supplemental/Menlo.ttc",
                "/System/Library/Fonts/SFNSMono.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
            ]
        )
    else:
        font_candidates.extend(
            [
                "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
                "/System/Library/Fonts/Supplemental/Helvetica.ttc",
                "/System/Library/Fonts/SFNS.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
            ]
        )

    if bold:
        font_candidates = [
            candidate
            for candidate in [
                "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
                "/System/Library/Fonts/Supplemental/Helvetica.ttc",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                *font_candidates
            ]
            if candidate
        ]

    for candidate in font_candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size=size)

    return ImageFont.load_default()


TITLE_FONT = load_font(44, bold=True)
SUBTITLE_FONT = load_font(22)
CARD_TITLE_FONT = load_font(24, bold=True)
LABEL_FONT = load_font(17, bold=True)
UI_FONT = load_font(18)
UI_BOLD_FONT = load_font(18, bold=True)
MONO_FONT = load_font(17, mono=True)
MONO_SMALL_FONT = load_font(15, mono=True)
COMMENT_MONO_FONT = load_font(14, mono=True)


def run_cli(*args: str) -> str:
    output = subprocess.check_output(
        ["node", str(ROOT / "dist" / "cli" / "index.js"), *args],
        cwd=ROOT,
        text=True
    )
    return output.strip()


def wrap_line(line: str, width: int) -> list[str]:
    if not line:
        return [""]

    return textwrap.wrap(
        line,
        width=width,
        replace_whitespace=False,
        drop_whitespace=False,
        break_long_words=False,
        break_on_hyphens=False
    ) or [line]


def prepare_lines(content: str, width: int) -> list[str]:
    prepared: list[str] = []

    for line in content.splitlines():
        prepared.extend(wrap_line(line, width))

    return prepared


def rounded_box(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    radius: int,
    fill: str,
    outline: str | None = None,
    width: int = 1
) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def draw_text_block(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    lines: list[str],
    font,
    fill: str,
    line_height: int
) -> None:
    for index, line in enumerate(lines):
        draw.text((x, y + index * line_height), line, font=font, fill=fill)


def draw_gradient_background(frame: Image.Image) -> None:
    draw = ImageDraw.Draw(frame)

    top = ImageColor.getrgb("#08111F")
    bottom = ImageColor.getrgb("#12243E")

    for row in range(CANVAS_SIZE[1]):
        blend = row / (CANVAS_SIZE[1] - 1)
        color = tuple(
            int(top[channel] * (1 - blend) + bottom[channel] * blend)
            for channel in range(3)
        )
        draw.line((0, row, CANVAS_SIZE[0], row), fill=color)

    draw.ellipse((860, -140, 1280, 280), fill="#1D4ED855")
    draw.ellipse((-140, 420, 280, 860), fill="#F9731650")


def draw_shell_panel(
    frame: Image.Image,
    progress: float,
    terminal_lines: list[str]
) -> None:
    draw = ImageDraw.Draw(frame)
    x1, y1, x2, y2 = 52, 132, 602, 660
    rounded_box(draw, (x1, y1, x2, y2), 28, "#0B1220", "#334155", 2)
    rounded_box(draw, (x1, y1, x2, y1 + 56), 28, "#111827")
    draw.rectangle((x1, y1 + 28, x2, y1 + 56), fill="#111827")
    for offset, color in enumerate(["#FB7185", "#FBBF24", "#34D399"]):
        draw.ellipse((x1 + 22 + offset * 26, y1 + 19, x1 + 38 + offset * 26, y1 + 35), fill=color)

    draw.text((x1 + 108, y1 + 17), "Local scan", font=CARD_TITLE_FONT, fill="#E5E7EB")

    command = "npx traceroot-audit scan ./examples/risky-skill"
    typed_length = min(len(command), math.ceil(progress * len(command)))
    typed_command = command[:typed_length]
    cursor_on = int(progress * 10) % 2 == 0 and progress < 1
    cursor = "█" if cursor_on else ""

    rounded_box(draw, (x1 + 22, y1 + 78, x2 - 22, y1 + 128), 16, "#0F172A")
    draw.text((x1 + 40, y1 + 93), f"$ {typed_command}{cursor}", font=MONO_FONT, fill="#93C5FD")

    total_visible_lines = max(1, math.floor(progress * len(terminal_lines)))
    visible_lines = terminal_lines[:total_visible_lines]
    draw_text_block(
        draw,
        x1 + 32,
        y1 + 154,
        visible_lines,
        MONO_SMALL_FONT,
        "#E2E8F0",
        24
    )

    if progress >= 0.35:
        highlight_y = y1 + 152 + min(total_visible_lines - 1, 6) * 24
        rounded_box(
            draw,
            (x1 + 24, highlight_y - 6, x2 - 24, highlight_y + 22),
            10,
            "#7F1D1D55",
            "#EF4444",
            1
        )


def draw_comment_panel(
    frame: Image.Image,
    progress: float,
    comment_lines: list[str],
    pulse: float
) -> None:
    draw = ImageDraw.Draw(frame)
    base_x1, y1, width, height = 638, 132, 510, 520
    offset = int((1 - progress) * 150)
    x1 = base_x1 + offset
    x2 = x1 + width
    y2 = y1 + height

    shadow = Image.new("RGBA", frame.size, (0, 0, 0, 0))
    shadow_draw = ImageDraw.Draw(shadow)
    shadow_draw.rounded_rectangle(
        (x1 + 10, y1 + 14, x2 + 10, y2 + 14),
        radius=28,
        fill=(15, 23, 42, int(70 * progress))
    )
    frame.alpha_composite(shadow)

    rounded_box(draw, (x1, y1, x2, y2), 28, "#F8FAFC", "#CBD5E1", 2)
    rounded_box(draw, (x1, y1, x2, y1 + 64), 28, "#FFFFFF")
    draw.rectangle((x1, y1 + 32, x2, y1 + 64), fill="#FFFFFF")

    draw.ellipse((x1 + 24, y1 + 18, x1 + 56, y1 + 50), fill="#0F172A")
    draw.text((x1 + 70, y1 + 18), "TraceRoot Audit PR Summary", font=CARD_TITLE_FONT, fill="#0F172A")

    badge_fill = "#DCFCE7" if pulse < 0.5 else "#BFDBFE"
    badge_text = "#166534" if pulse < 0.5 else "#1D4ED8"
    rounded_box(draw, (x2 - 110, y1 + 18, x2 - 24, y1 + 50), 14, badge_fill)
    draw.text((x2 - 91, y1 + 28), "Updated", font=LABEL_FONT, fill=badge_text)

    visible_count = max(2, math.floor(progress * len(comment_lines)))
    visible_lines = comment_lines[:visible_count]

    draw_text_block(
      draw,
      x1 + 28,
      y1 + 90,
      visible_lines,
      COMMENT_MONO_FONT,
      "#1E293B",
      20
    )

    if progress >= 1:
        accent_color = "#F97316" if pulse < 0.5 else "#38BDF8"
        draw.rounded_rectangle((x1, y1, x2, y2), radius=28, outline=accent_color, width=3)


def create_frames(terminal_lines: list[str], comment_lines: list[str]) -> list[Image.Image]:
    frames: list[Image.Image] = []

    for index in range(FRAME_COUNT):
        frame = Image.new("RGBA", CANVAS_SIZE, "#08111F")
        draw_gradient_background(frame)
        draw = ImageDraw.Draw(frame)

        draw.text((56, 44), "Scan locally. Comment automatically.", font=TITLE_FONT, fill="#F8FAFC")
        draw.text(
            (58, 92),
            "15-second demo loop: human scan output on the left, compact PR summary on the right.",
            font=SUBTITLE_FONT,
            fill="#BFDBFE"
        )

        terminal_progress = min(1.0, index / 7)
        comment_progress = max(0.0, min(1.0, (index - 7) / 4))
        pulse = 0.5 + 0.5 * math.sin(index / 2)

        draw_shell_panel(frame, terminal_progress, terminal_lines)
        draw_comment_panel(frame, comment_progress, comment_lines, pulse)

        footer = "Built from the real CLI outputs of ./examples/risky-skill"
        draw.text((58, 680), footer, font=SUBTITLE_FONT, fill="#93C5FD")

        frames.append(frame.convert("P", palette=Image.ADAPTIVE, colors=128))

    return frames


def reorder_for_readme_preview(frames: list[Image.Image]) -> list[Image.Image]:
    preview_start = 12
    return frames[preview_start:] + frames[:preview_start]


def main() -> None:
    terminal_output = run_cli("scan", "./examples/risky-skill")
    compact_output = run_cli(
        "scan",
        "./examples/risky-skill",
        "--format",
        "markdown",
        "--compact"
    )

    terminal_lines = prepare_lines(terminal_output, 60)[:18]
    comment_lines = prepare_lines(compact_output, 56)[:20]

    frames = reorder_for_readme_preview(create_frames(terminal_lines, comment_lines))
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    first_frame, *remaining_frames = frames
    first_frame.save(
        OUTPUT_PATH,
        save_all=True,
        append_images=remaining_frames,
        duration=[FRAME_DURATION_MS] * len(frames),
        loop=0,
        optimize=True,
        disposal=2
    )
    print(f"Created {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
