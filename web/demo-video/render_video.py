"""Render a 1080p / 30fps / -14 LUFS demo video for QoreGuard."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
SCREENSHOTS = ROOT / "docs" / "screenshots"
OUT_DIR = Path(__file__).resolve().parent
FRAMES_DIR = OUT_DIR / "frames"
OUTPUT_MP4 = OUT_DIR / "qoreguard-demo-1080p.mp4"

WIDTH = 1920
HEIGHT = 1080
FPS = 30
SEG_DURATION = 12.0  # 9 segments * 12s = 108s (< 150s, < 3 min)


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def make_text_slide(
    out_path: Path,
    kicker: str,
    title: str,
    bullets: list[str],
    accent: tuple[int, int, int] = (56, 189, 248),
) -> None:
    img = Image.new("RGB", (WIDTH, HEIGHT), (7, 11, 20))
    draw = ImageDraw.Draw(img)

    # Subtle border card
    draw.rounded_rectangle(
        [(90, 90), (WIDTH - 90, HEIGHT - 90)],
        radius=24,
        fill=(14, 21, 37),
        outline=(30, 43, 69),
        width=3,
    )
    draw.rectangle([(90, 90), (104, HEIGHT - 90)], fill=accent)

    f_kicker = load_font(30)
    f_title = load_font(60)
    f_body = load_font(34)

    draw.text((150, 150), kicker.upper(), fill=accent, font=f_kicker)
    draw.text((150, 215), title, fill=(230, 238, 248), font=f_title)

    y = 350
    for bullet in bullets:
        draw.ellipse([(155, y + 14), (171, y + 30)], fill=accent)
        draw.text((195, y), bullet, fill=(185, 200, 224), font=f_body)
        y += 88

    draw.text(
        (150, HEIGHT - 155),
        "QoreGuard  |  QoreChain Developer Fest (qorechain-diana / EVM 9800)",
        fill=(139, 155, 182),
        font=load_font(26),
    )
    img.save(out_path)


def make_screenshot_slide(
    out_path: Path,
    src_png: Path,
    banner_title: str,
    banner_sub: str,
) -> None:
    canvas = Image.new("RGB", (WIDTH, HEIGHT), (7, 11, 20))
    draw = ImageDraw.Draw(canvas)

    # Top banner
    draw.rectangle([(0, 0), (WIDTH, 110)], fill=(14, 21, 37))
    draw.line([(0, 110), (WIDTH, 110)], fill=(30, 43, 69), width=2)
    draw.text((48, 22), banner_title, fill=(230, 238, 248), font=load_font(36))
    draw.text((48, 68), banner_sub, fill=(56, 189, 248), font=load_font(22))

    shot = Image.open(src_png).convert("RGB")
    max_w = WIDTH - 80
    max_h = HEIGHT - 150
    scale = min(max_w / shot.width, max_h / shot.height)
    new_w = int(shot.width * scale)
    new_h = int(shot.height * scale)
    resized = shot.resize((new_w, new_h), Image.Resampling.LANCZOS)

    x = (WIDTH - new_w) // 2
    y = 125 + (max_h - new_h) // 2
    canvas.paste(resized, (x, y))
    canvas.save(out_path)


def main() -> int:
    ffmpeg = shutil.which("ffmpeg") or "/opt/homebrew/bin/ffmpeg"
    if not Path(ffmpeg).exists() and shutil.which("ffmpeg") is None:
        raise RuntimeError("ffmpeg not found in PATH or /opt/homebrew/bin/ffmpeg")

    FRAMES_DIR.mkdir(parents=True, exist_ok=True)

    slides: list[Path] = []

    s1 = FRAMES_DIR / "slide_01.png"
    make_text_slide(
        s1,
        "QoreChain Developer Fest • Post-Quantum AI Agents",
        "QoreGuard: PQ AI Treasury & MCP Guard",
        [
            "Enforces NIST FIPS 204 ML-DSA-87 + secp256k1 hybrid signing",
            "Keeps owner's master PQ key offline via Scoped EVM Windows",
            "Blocks quantum downgrades, replay nonces, cap breaches & rogue tools",
            "Zero-secret browser console with SHA-256 tamper-evident receipts",
        ],
    )
    slides.append(s1)

    s2 = FRAMES_DIR / "slide_02.png"
    make_screenshot_slide(
        s2,
        SCREENSHOTS / "01-hero-telemetry.png",
        "1. Live QoreX Diana Telemetry & Command Center",
        "Chain ID: qorechain-diana  |  EVM Chain ID: 9800  |  RPC: https://rpc-testnet.qore.host",
    )
    slides.append(s2)

    s3 = FRAMES_DIR / "slide_03.png"
    make_screenshot_slide(
        s3,
        SCREENSHOTS / "02-pqc-comparison.png",
        "2. ML-DSA-87 vs Classical ECDSA Quantum-Risk Matrix",
        "2,592B PQ public key / 4,627B signature • qorechain-msg-v1|qorechain-diana|... domain separation",
    )
    slides.append(s3)

    s4 = FRAMES_DIR / "slide_04.png"
    make_text_slide(
        s4,
        "Architecture • Defense-in-Depth",
        "Scoped EVM Window & Policy Enforcement",
        [
            "1. Hybrid Check: rejects ECDSA-only or unsigned downgrade attempts",
            "2. Nonce Guard: single-use nonce registry prevents replay attacks",
            "3. Digest Integrity: SHA-256 binding over canonical MCP tool payload",
            "4. Budget & Allowlist: per-tx cap, daily QOR limit, target & tool whitelist",
        ],
        accent=(34, 197, 94),
    )
    slides.append(s4)

    s5 = FRAMES_DIR / "slide_05.png"
    make_screenshot_slide(
        s5,
        SCREENSHOTS / "03-policy-console.png",
        "3. Interactive AI Agent Policy Console",
        "Live per-tx cap, daily budget tracking, remaining EVM window blocks, and target allowlist",
    )
    slides.append(s5)

    s6 = FRAMES_DIR / "slide_06.png"
    make_screenshot_slide(
        s6,
        SCREENSHOTS / "04-adversarial-lab.png",
        "4. 5-Scenario Adversarial Breaker Lab (All Attacks Blocked)",
        "Quantum Downgrade • Replay Nonce • Policy Cap Breach • Tampered PQ Digest • Rogue Tool",
    )
    slides.append(s6)

    s7 = FRAMES_DIR / "slide_07.png"
    make_text_slide(
        s7,
        "Verification & Quality Assurance",
        "Deterministic Testing & Auditability",
        [
            "7/7 Vitest unit tests covering valid flow + all 5 adversarial attacks",
            "Strict TypeScript (tsc --noEmit) & Vite production bundle verified",
            "Exportable SHA-256 tamper-evident JSON audit receipts",
            "Inline SVG favicon • Zero secrets • 100% English UI & documentation",
        ],
        accent=(245, 158, 11),
    )
    slides.append(s7)

    s8 = FRAMES_DIR / "slide_08.png"
    make_screenshot_slide(
        s8,
        SCREENSHOTS / "05-full-overview.png",
        "5. Full QoreGuard Command Center Overview",
        "End-to-end post-quantum treasury governance for autonomous AI agents",
    )
    slides.append(s8)

    s9 = FRAMES_DIR / "slide_09.png"
    make_text_slide(
        s9,
        "Build Before Q-Day • #BuildBeforeQDay",
        "Ready for QoreChain Testnet & Jury Review",
        [
            "Category: Post-Quantum AI Agents ($1,500 1st / $750 2nd)",
            "Special Award: Best AI-Native Build ($500)",
            "Network: qorechain-diana (EVM Chain ID 9800)",
            "Thank you for reviewing QoreGuard!",
        ],
    )
    slides.append(s9)

    total_duration = len(slides) * SEG_DURATION
    cmd: list[str] = [ffmpeg, "-y"]
    filter_parts: list[str] = []
    concat_inputs: list[str] = []

    for idx, slide in enumerate(slides):
        cmd.extend(["-loop", "1", "-t", f"{SEG_DURATION:.1f}", "-framerate", str(FPS), "-i", str(slide)])
        filter_parts.append(f"[{idx}:v]scale=1920:1080,setsar=1,fps={FPS}[v{idx}]")
        concat_inputs.append(f"[v{idx}]")

    filter_parts.append(f"{''.join(concat_inputs)}concat=n={len(slides)}:v=1:a=0[vout]")

    audio_idx = len(slides)
    cmd.extend([
        "-f", "lavfi",
        "-t", f"{total_duration:.1f}",
        "-i", "anoisesrc=color=pink:amplitude=0.05:sample_rate=48000",
    ])
    filter_parts.append(
        f"[{audio_idx}:a]aformat=channel_layouts=stereo:sample_rates=48000,"
        "loudnorm=I=-14.0:TP=-1.5:LRA=11,aresample=48000[aout]"
    )

    cmd.extend([
        "-filter_complex", ";".join(filter_parts),
        "-map", "[vout]",
        "-map", "[aout]",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-r", str(FPS),
        "-c:a", "aac",
        "-b:a", "192k",
        "-movflags", "+faststart",
        str(OUTPUT_MP4),
    ])

    subprocess.run(cmd, check=True)
    print(f"Rendered {OUTPUT_MP4} ({total_duration:.1f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
