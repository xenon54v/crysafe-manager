"""Generate sanitized interface screenshots and the Sprint 8 demo video."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
IMAGE_DIR = ROOT / "docs" / "images"
BUILD_DIR = ROOT / "build" / "demo-media"
VIDEO_PATH = ROOT / "docs" / "CryptoSafe_Manager_Demo.mp4"

WIDTH = 1280
HEIGHT = 720
BG = "#151515"
PANEL = "#242424"
CARD = "#2b2b2b"
BORDER = "#444444"
TEXT = "#f3f4f6"
MUTED = "#b7bbc2"
PINK = "#d98ca3"
GREEN = "#4ade80"
YELLOW = "#fbbf24"
RED = "#f87171"


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    filename = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    return ImageFont.truetype(f"/usr/share/fonts/truetype/dejavu/{filename}", size)


def _text(
    draw: ImageDraw.ImageDraw, xy, value: str, size: int = 20, color=TEXT, bold=False
):
    draw.text(xy, value, font=_font(size, bold), fill=color)


def _button(draw: ImageDraw.ImageDraw, box, label: str, *, active: bool = True):
    fill = PINK if active else "#3a3a3a"
    draw.rounded_rectangle(box, radius=8, fill=fill)
    left, top, right, bottom = box
    font = _font(16, True)
    bounds = draw.textbbox((0, 0), label, font=font)
    x = left + (right - left - (bounds[2] - bounds[0])) / 2
    y = top + (bottom - top - (bounds[3] - bounds[1])) / 2 - 2
    draw.text((x, y), label, font=font, fill="#181818" if active else TEXT)


def _field(draw: ImageDraw.ImageDraw, box, value: str, label: str | None = None):
    left, top, right, bottom = box
    if label:
        _text(draw, (left, top - 27), label, 15, MUTED)
    draw.rounded_rectangle(box, radius=6, fill="#1c1c1c", outline=BORDER, width=1)
    _text(draw, (left + 12, top + 9), value, 17, TEXT)


def _window(title: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((20, 18, WIDTH - 20, HEIGHT - 18), radius=12, fill=PANEL)
    draw.rectangle((20, 18, WIDTH - 20, 62), fill="#202020")
    _text(draw, (42, 31), title, 17, TEXT, True)
    for index, color in enumerate((RED, YELLOW, GREEN)):
        x = WIDTH - 122 + index * 28
        draw.ellipse((x, 34, x + 12, 46), fill=color)
    return image, draw


def screenshot_setup(path: Path) -> None:
    image, draw = _window("CryptoSafe Manager — Setup")
    _text(draw, (90, 95), "Create a secure vault", 31, TEXT, True)
    _text(draw, (90, 140), "The master password never leaves this device", 18, MUTED)
    draw.rounded_rectangle((80, 185, 1200, 635), radius=14, fill=CARD)
    _text(draw, (120, 220), "1", 24, PINK, True)
    _text(draw, (158, 220), "Master password", 22, TEXT, True)
    _field(draw, (120, 285, 740, 330), "••••••••••••••••", "Master password")
    _field(draw, (120, 382, 740, 427), "••••••••••••••••", "Confirm password")
    checks = [
        "12 or more characters",
        "Uppercase and lowercase letters",
        "Number and special character",
    ]
    for index, label in enumerate(checks):
        y = 470 + index * 35
        draw.ellipse((125, y + 3, 141, y + 19), fill=GREEN)
        _text(draw, (154, y), label, 16, TEXT)
    _button(draw, (900, 555, 1135, 605), "Continue")
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path)


def screenshot_vault(path: Path) -> None:
    image, draw = _window("CryptoSafe Manager")
    menu = ["File", "Edit", "Security", "Tools", "Help"]
    for index, item in enumerate(menu):
        _text(draw, (48 + index * 94, 78), item, 16, MUTED)
    _text(draw, (48, 120), "CryptoSafe Manager", 29, TEXT, True)
    buttons = ["Add", "Edit", "Delete", "Show Passwords", "Clear Clipboard", "Share"]
    x = 420
    for label in buttons:
        width = 118 if len(label) < 10 else 155
        _button(draw, (x, 112, x + width, 154), label)
        x += width + 10
    _field(draw, (48, 182, 565, 226), "Search title, username, URL, tag…")
    _field(draw, (580, 182, 760, 226), "All categories")
    _field(draw, (775, 182, 955, 226), "Any date")
    _field(draw, (970, 182, 1215, 226), "Any password strength")
    draw.rounded_rectangle((48, 252, 1215, 620), radius=10, fill=CARD)
    columns = [
        (72, "Title"),
        (330, "Username"),
        (550, "Password"),
        (750, "URL"),
        (1010, "Updated"),
    ]
    for x, label in columns:
        _text(draw, (x, 272), label, 16, MUTED, True)
    draw.line((64, 307, 1198, 307), fill=BORDER, width=1)
    rows = [
        ("Course portal", "stud••••", "••••••••••••", "course.example", "Today 09:40"),
        ("Personal mail", "alex••••", "••••••••••••", "mail.example", "Yesterday"),
        ("Source control", "xeno••••", "••••••••••••", "github.com", "2026-09-20"),
        ("Banking demo", "user••••", "••••••••••••", "bank.example", "2026-09-11"),
    ]
    for row_index, values in enumerate(rows):
        y = 326 + row_index * 67
        if row_index == 0:
            draw.rounded_rectangle((60, y - 8, 1202, y + 45), radius=6, fill="#513b46")
        for (x, _), value in zip(columns, values, strict=True):
            _text(draw, (x, y), value, 16, TEXT)
        draw.line((64, y + 54, 1198, y + 54), fill="#383838", width=1)
    _text(draw, (56, 650), "4 entries loaded", 15, MUTED)
    _text(draw, (470, 650), "Audit: verified", 15, GREEN, True)
    _text(draw, (650, 650), "Security: unlocked", 15, GREEN, True)
    _text(draw, (905, 650), "Clipboard: clear", 15, MUTED)
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path)


def screenshot_entry(path: Path) -> None:
    image, draw = _window("CryptoSafe Manager — Add entry")
    draw.rounded_rectangle((300, 78, 980, 666), radius=14, fill=CARD)
    _text(draw, (340, 112), "Add vault entry", 28, TEXT, True)
    _field(draw, (340, 185, 940, 226), "Course portal", "Title")
    _field(draw, (340, 270, 940, 311), "student@example.com", "Username")
    _field(draw, (340, 355, 785, 396), "••••••••••••••••", "Password")
    _button(draw, (800, 355, 940, 396), "Generate")
    draw.rounded_rectangle((340, 420, 940, 432), radius=6, fill="#444444")
    draw.rounded_rectangle((340, 420, 876, 432), radius=6, fill=GREEN)
    _text(draw, (340, 445), "Strong — estimated entropy 92 bits", 15, GREEN)
    _field(draw, (340, 505, 940, 546), "https://course.example", "URL")
    _button(draw, (785, 590, 940, 638), "Save")
    _button(draw, (615, 590, 770, 638), "Cancel", active=False)
    image.save(path)


def screenshot_clipboard(path: Path) -> None:
    image, draw = _window("CryptoSafe Manager — Secure clipboard")
    _text(draw, (64, 96), "Clipboard protection", 30, TEXT, True)
    draw.rounded_rectangle((60, 150, 780, 610), radius=14, fill=CARD)
    _text(draw, (98, 190), "Protected value copied", 25, GREEN, True)
    _text(draw, (98, 238), "Type", 15, MUTED)
    _text(draw, (220, 238), "Password", 17, TEXT)
    _text(draw, (98, 282), "Preview", 15, MUTED)
    _text(draw, (220, 282), "••••••••••••", 17, TEXT)
    _text(draw, (98, 326), "Source", 15, MUTED)
    _text(draw, (220, 326), "Course portal", 17, TEXT)
    draw.arc((150, 370, 350, 570), 270, 565, fill=PINK, width=18)
    _text(draw, (207, 424), "18", 44, TEXT, True)
    _text(draw, (194, 480), "seconds", 16, MUTED)
    _button(draw, (430, 410, 700, 458), "Clear now")
    _button(draw, (430, 478, 700, 526), "Preview", active=False)
    draw.rounded_rectangle((825, 150, 1215, 610), radius=14, fill="#30252a")
    _text(draw, (865, 190), "Security status", 24, TEXT, True)
    items = [
        ("Vault", "Unlocked", GREEN),
        ("Audit chain", "Verified", GREEN),
        ("Memory guard", "Active", GREEN),
        ("Auto-lock", "10 minutes", YELLOW),
    ]
    for index, (label, value, color) in enumerate(items):
        y = 255 + index * 72
        _text(draw, (866, y), label, 15, MUTED)
        _text(draw, (1010, y), value, 16, color, True)
    _button(draw, (865, 520, 1175, 568), "Activate panic mode", active=False)
    image.save(path)


def screenshot_exchange(path: Path) -> None:
    image, draw = _window("CryptoSafe Manager — Export")
    _text(draw, (58, 94), "Encrypted export", 30, TEXT, True)
    draw.rounded_rectangle((50, 145, 1230, 620), radius=14, fill=CARD)
    _text(draw, (85, 180), "Format", 16, MUTED)
    _field(draw, (85, 210, 365, 252), "CryptoSafe JSON")
    _text(draw, (405, 180), "Protection", 16, MUTED)
    _field(draw, (405, 210, 705, 252), "AES-256-GCM password")
    _text(draw, (745, 180), "Compression", 16, MUTED)
    _field(draw, (745, 210, 1020, 252), "GZIP enabled")
    _text(draw, (85, 292), "Select entries", 19, TEXT, True)
    entries = ["Course portal", "Personal mail", "Source control", "Banking demo"]
    for index, label in enumerate(entries):
        y = 335 + index * 55
        draw.rounded_rectangle((88, y, 116, y + 28), radius=4, fill=PINK)
        _text(draw, (94, y + 1), "✓", 18, "#181818", True)
        _text(draw, (135, y + 2), label, 17, TEXT)
    draw.rounded_rectangle(
        (675, 305, 1168, 485), radius=10, fill="#202020", outline=BORDER
    )
    _text(draw, (710, 335), "Export preview", 20, TEXT, True)
    preview = [
        "4 encrypted entries",
        "Unique salt and nonce",
        "SHA-256 and HMAC integrity",
        "Passwords never written as plaintext",
    ]
    for index, label in enumerate(preview):
        _text(draw, (710, 380 + index * 28), f"• {label}", 15, MUTED)
    _button(draw, (950, 540, 1168, 588), "Export")
    image.save(path)


def screenshot_audit(path: Path) -> None:
    image, draw = _window("CryptoSafe Manager — Audit log")
    _text(draw, (48, 90), "Signed audit log", 29, TEXT, True)
    _text(draw, (950, 98), "Integrity: VALID", 18, GREEN, True)
    _field(draw, (48, 140, 510, 182), "Search events…")
    _field(draw, (525, 140, 735, 182), "All event types")
    _button(draw, (980, 140, 1205, 182), "Verify full chain")
    draw.rounded_rectangle((48, 210, 1205, 610), radius=10, fill=CARD)
    columns = [
        (70, "Seq"),
        (150, "Timestamp"),
        (390, "Event"),
        (700, "Severity"),
        (875, "Signature"),
    ]
    for x, label in columns:
        _text(draw, (x, 232), label, 15, MUTED, True)
    events = [
        ("104", "2026-09-27 16:42", "ENTRY_CREATED", "INFO", "VALID"),
        ("105", "2026-09-27 16:43", "CLIPBOARD_COPIED", "INFO", "VALID"),
        ("106", "2026-09-27 16:43", "CLIPBOARD_CLEARED", "INFO", "VALID"),
        ("107", "2026-09-27 16:45", "VAULT_EXPORTED", "NOTICE", "VALID"),
        ("108", "2026-09-27 16:46", "PANIC_MODE_TEST", "WARNING", "VALID"),
    ]
    for index, row in enumerate(events):
        y = 280 + index * 58
        for (x, _), value in zip(columns, row, strict=True):
            color = (
                GREEN if value == "VALID" else (YELLOW if value == "WARNING" else TEXT)
            )
            _text(draw, (x, y), value, 15, color)
        draw.line((65, y + 40, 1185, y + 40), fill="#383838")
    _text(draw, (50, 650), "Page 1 of 3 · 108 signed records", 15, MUTED)
    image.save(path)


def generate_screenshots() -> list[Path]:
    """Create all sanitized screenshots used by the documentation."""

    IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    outputs = [
        ("setup.png", screenshot_setup),
        ("vault_overview.png", screenshot_vault),
        ("entry_editor.png", screenshot_entry),
        ("secure_clipboard.png", screenshot_clipboard),
        ("encrypted_export.png", screenshot_exchange),
        ("audit_log.png", screenshot_audit),
    ]
    result = []
    for filename, renderer in outputs:
        path = IMAGE_DIR / filename
        renderer(path)
        result.append(path)
    return result


def _caption_scene(source: Path, output: Path, heading: str, caption: str) -> None:
    image = Image.open(source).convert("RGB")
    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    draw.rectangle((0, 0, WIDTH, 92), fill=(8, 8, 8, 235))
    draw.rectangle((0, HEIGHT - 86, WIDTH, HEIGHT), fill=(8, 8, 8, 235))
    _text(draw, (46, 22), heading, 30, TEXT, True)
    _text(draw, (46, HEIGHT - 61), caption, 20, TEXT)
    Image.alpha_composite(image.convert("RGBA"), overlay).convert("RGB").save(output)


def generate_video() -> Path:
    """Build a 3 minute 12 second MP4 with captions and sanitized interface scenes."""

    screenshots = {path.name: path for path in generate_screenshots()}
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    scenes = [
        (
            "vault_overview.png",
            "CryptoSafe Manager",
            "Локальный менеджер паролей · Sprint 8 · итоговая интеграция",
        ),
        (
            "setup.png",
            "Создание хранилища",
            "Мастер-пароль проверяется локально и не сохраняется в открытом виде",
        ),
        (
            "setup.png",
            "Вывод ключей",
            "Argon2 защищает проверку пароля, PBKDF2 и HKDF разделяют рабочие ключи",
        ),
        (
            "entry_editor.png",
            "Новая запись",
            "Запись проверяется и шифруется AES-256-GCM с уникальным nonce",
        ),
        (
            "entry_editor.png",
            "Генератор паролей",
            "Настраиваемый генератор показывает оценку стойкости до сохранения",
        ),
        (
            "vault_overview.png",
            "Поиск и управление",
            "Фильтры, редактирование и мягкое удаление работают в одном окне",
        ),
        (
            "secure_clipboard.png",
            "Защищённый буфер",
            "Таймер очищает скопированный секрет и уведомляет пользователя",
        ),
        (
            "encrypted_export.png",
            "Импорт и экспорт",
            "AES-GCM, проверка целостности и предварительный просмотр защищают обмен",
        ),
        (
            "audit_log.png",
            "Журнал аудита",
            "Ed25519-подписи и хеш-цепочка обнаруживают изменение записей",
        ),
        (
            "secure_clipboard.png",
            "Panic mode",
            "Аварийный режим очищает буфер и память, скрывает окно и блокирует хранилище",
        ),
        (
            "audit_log.png",
            "Проверка качества",
            "201+ автоматических тестов · покрытие 80%+ · менее 30 секунд",
        ),
        (
            "vault_overview.png",
            "Готовая поставка",
            "Исходный запуск, PyInstaller-дистрибутив, отчёт и документация",
        ),
    ]
    scene_paths = []
    for index, (filename, heading, caption) in enumerate(scenes, start=1):
        output = BUILD_DIR / f"scene-{index:02d}.png"
        _caption_scene(screenshots[filename], output, heading, caption)
        scene_paths.append(output)

    concat_path = BUILD_DIR / "scenes.ffconcat"
    lines = ["ffconcat version 1.0"]
    for scene in scene_paths:
        lines.append(f"file '{scene.as_posix()}'")
        lines.append("duration 16")
    lines.append(f"file '{scene_paths[-1].as_posix()}'")
    concat_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    VIDEO_PATH.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-f",
            "concat",
            "-safe",
            "0",
            "-i",
            str(concat_path),
            "-f",
            "lavfi",
            "-i",
            "anullsrc=channel_layout=stereo:sample_rate=48000",
            "-vf",
            "fps=30,format=yuv420p",
            "-c:v",
            "libx264",
            "-preset",
            "medium",
            "-crf",
            "22",
            "-c:a",
            "aac",
            "-shortest",
            "-movflags",
            "+faststart",
            str(VIDEO_PATH),
        ],
        check=True,
    )
    return VIDEO_PATH


def main() -> None:
    """Generate screenshots and optionally the final demo video."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--video", action="store_true")
    arguments = parser.parse_args()
    generate_screenshots()
    if arguments.video:
        generate_video()


if __name__ == "__main__":
    main()
