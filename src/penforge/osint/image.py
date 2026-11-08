import os
import re
import subprocess

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]")
_MAX_REVERSE_RESULTS = 10


def _strip_ansi(text):
    return _ANSI_RE.sub("", text)


def _level(score):
    if score >= 0.75:
        return "ÉLEVÉ    — forte suspicion IA"
    if score >= 0.50:
        return "MODÉRÉ   — caractéristiques suspectes"
    if score >= 0.25:
        return "FAIBLE   — quelques signes, non concluant"
    return "MINIMAL  — cohérent avec photo réelle"


def _pct(score):
    return f"{round(score * 100, 1):5.1f}%"


def _exif_forensics(pil_img):
    try:
        from PIL import ExifTags
        exif = pil_img._getexif()
        if not exif:
            return 1.0
        meta = {ExifTags.TAGS.get(k, k): v for k, v in exif.items()}
        camera_tags = ["Make", "Model", "LensModel", "SerialNumber"]
        present = sum(1 for t in camera_tags if t in meta)
        return [1.0, 0.7, 0.4, 0.2, 0.1][present]
    except Exception:
        return 0.8


def _noise_forensics(cv_img):
    import numpy as np
    import cv2 as _cv2
    img_f = cv_img.astype(np.float32)
    denoise = _cv2.fastNlMeansDenoisingColored(cv_img, None, 10, 10, 7, 21)
    std_val = float(np.std(img_f - denoise.astype(np.float32)))
    if std_val < 2:
        return 1.0
    if std_val < 5:
        return 0.7
    if std_val < 10:
        return 0.3
    return 0.1


def _fft_forensics(cv_gray):
    import numpy as np
    f = np.fft.fft2(cv_gray.astype(np.float32))
    mag = np.log(np.abs(np.fft.fftshift(f)) + 1)
    strength = float(np.mean(mag > (mag.mean() + 2 * mag.std())))
    if strength > 0.25:
        return 1.0
    if strength > 0.15:
        return 0.7
    if strength > 0.08:
        return 0.4
    return 0.1


def _edge_forensics(cv_img):
    import numpy as np
    import cv2 as _cv2
    edges = _cv2.Canny(cv_img, 100, 200)
    ratio = float(np.sum(edges > 0) / edges.size)
    if ratio < 0.02:
        return 0.9
    if ratio > 0.18:
        return 0.8
    if ratio > 0.12:
        return 0.5
    return 0.2


def _pil_exif_dump(image_path):
    try:
        from PIL import Image, ExifTags
        img = Image.open(image_path)
        exif_raw = img._getexif()
        if not exif_raw:
            return "(aucune métadonnée EXIF)"
        lines = []
        for tag_id, value in sorted(exif_raw.items()):
            tag = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
            if isinstance(value, bytes) and len(value) > 64:
                value = f"<binaire {len(value)} octets>"
            lines.append(f"  {tag:<30}: {value}")
        return "\n".join(lines)
    except Exception as exc:
        return f"(erreur lecture EXIF PIL : {exc})"


def _reverse_image_search(image_path):
    sep = "=" * 52
    lines = ["", sep, "RECHERCHE D'IMAGE INVERSÉE", sep]
    try:
        from PicImageSearch.sync import GoogleLens as _GoogleLens
        try:
            gl = _GoogleLens(search_type="visual_matches")
            resp = gl.search(file=image_path)
            lines.append(f"\n  Google Lens ({len(resp.raw)} correspondance(s)) :")
            if resp.raw:
                for item in resp.raw[:_MAX_REVERSE_RESULTS]:
                    lines.append(f"    {item.title}  —  {item.url}")
            else:
                lines.append("    (aucun résultat)")
        except Exception as exc:
            lines.append(f"  Google Lens indisponible : {exc}")

        from PicImageSearch.sync import Yandex as _Yandex
        try:
            yx = _Yandex()
            resp = yx.search(file=image_path)
            lines.append(f"\n  Yandex ({len(resp.raw)} correspondance(s)) :")
            if resp.raw:
                for item in resp.raw[:_MAX_REVERSE_RESULTS]:
                    lines.append(f"    {item.title}  —  {item.url}")
            else:
                lines.append("    (aucun résultat)")
        except Exception as exc:
            lines.append(f"  Yandex indisponible : {exc}")

    except ImportError:
        lines.append("  (PicImageSearch absent — reconstruire l'image avec PicImageSearch)")

    return "\n".join(lines)


def run_image(image_path, outdir):
    report_path = os.path.join(outdir, "image-forensics-report.txt")
    sep = "=" * 52
    lines = []

    lines.append(sep)
    lines.append("MÉTADONNÉES EXIF")
    lines.append(sep)
    try:
        r = subprocess.run(["exiftool", image_path], capture_output=True, text=True, timeout=30)
        lines.append(_strip_ansi(r.stdout).strip() or "(aucune métadonnée)")
    except FileNotFoundError:
        lines.append("(exiftool absent — lecture via PIL)")
        lines.append(_pil_exif_dump(image_path))
    except Exception as exc:
        lines.append(f"(erreur exiftool : {exc})")

    lines.append("")
    lines.append(sep)
    lines.append("ANALYSE FORENSIQUE — DÉTECTION IA")
    lines.append(sep)

    try:
        import numpy as np  # noqa: F401
        from PIL import Image
        import cv2 as _cv2

        pil_img = Image.open(image_path).convert("RGB")
        max_side = max(pil_img.size)
        if max_side > 2048:
            scale = 2048 / max_side
            pil_img = pil_img.resize(
                (int(pil_img.width * scale), int(pil_img.height * scale)),
                Image.LANCZOS,
            )
            tmp_path = image_path + "_resized.jpg"
            pil_img.save(tmp_path, "JPEG", quality=92)
            cv_img = _cv2.imread(tmp_path)
            os.remove(tmp_path)
        else:
            cv_img = _cv2.imread(image_path)

        if cv_img is None:
            raise ValueError("OpenCV ne peut pas lire ce format d'image.")

        cv_gray = _cv2.cvtColor(cv_img, _cv2.COLOR_BGR2GRAY)

        exif_s  = _exif_forensics(pil_img)
        noise_s = _noise_forensics(cv_img)
        fft_s   = _fft_forensics(cv_gray)
        edge_s  = _edge_forensics(cv_img)

        final = round(exif_s * 0.25 + noise_s * 0.25 + fft_s * 0.25 + edge_s * 0.25, 3)

        lines.append("")
        lines.append(f"  Score global IA : {_pct(final)}")
        lines.append(f"  Verdict        : {_level(final)}")
        lines.append("")
        lines.append("  Détail par dimension :")
        lines.append(f"    EXIF (absence tags caméra)        : {_pct(exif_s)}  [{_level(exif_s)}]")
        lines.append(f"    Résidu de bruit (trop lisse = IA) : {_pct(noise_s)}  [{_level(noise_s)}]")
        lines.append(f"    Artefacts spectraux (FFT)         : {_pct(fft_s)}  [{_level(fft_s)}]")
        lines.append(f"    Régularité des contours (Canny)   : {_pct(edge_s)}  [{_level(edge_s)}]")
        lines.append("")
        lines.append("  Note : score IA élevé indique des caractéristiques atypiques ;")
        lines.append("  confirmer avec plusieurs outils (Hive Moderation, AI-or-Not…).")

    except ImportError as exc:
        lines.append(f"\n  (Analyse IA désactivée : bibliothèque manquante — {exc})")
        lines.append("  Reconstruire l'image pentest avec python-opencv python-numpy python-pillow.")
    except Exception as exc:
        lines.append(f"\n  (Erreur analyse forensique : {exc})")

    lines.append(_reverse_image_search(image_path))

    output = "\n".join(lines)
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(output)
    return output
