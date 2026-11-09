import os
import re
import uuid as _uuid_mod
from urllib.parse import quote as _url_quote, unquote as _url_unquote

from flask import Blueprint, abort, redirect, render_template, request, url_for

from penforge.worker.tasks import run_osint

bp = Blueprint("osint", __name__)

OSINT_ROOT = "/osint"
_OSINT_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".heic", ".heif", ".raw", ".cr2", ".nef", ".arw"}
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,100}$")
_PHONE_RE = re.compile(r"^[\d\s+\-().]{4,30}$")

from penforge.config import DOMAIN_RE as _DOMAIN_RE


@bp.route("/osint")
def osint():
    return render_template("osint.html", error=None)


@bp.route("/osint/submit", methods=["POST"])
def osint_submit():
    target_type = request.form.get("target_type", "")
    if target_type not in ("username", "phone", "email", "image", "domain"):
        abort(400)

    if target_type == "image":
        uploads = [f for f in request.files.getlist("image") if f and f.filename]
        if not uploads:
            return render_template("osint.html", error="Aucune image fournie.", active_tab="image"), 400
        task_ids, names = [], []
        for upload in uploads:
            ext = os.path.splitext(upload.filename)[1].lower()
            if ext not in _OSINT_IMAGE_EXTS:
                continue
            uid = str(_uuid_mod.uuid4())
            outdir = os.path.join(OSINT_ROOT, uid)
            os.makedirs(outdir, exist_ok=True)
            image_path = os.path.join(outdir, f"input{ext}")
            upload.save(image_path)
            task_ids.append(run_osint.delay("image", image_path, uid).id)
            names.append(upload.filename)
        if not task_ids:
            return render_template("osint.html", error="Aucun format supporté. Formats acceptés : JPG, PNG, GIF, BMP, TIFF, WEBP, HEIC, RAW.", active_tab="image"), 400
        return redirect("/osint/batch?ids={}&names={}".format(
            ",".join(task_ids),
            ",".join(_url_quote(n, safe="") for n in names),
        ))

    uid = str(_uuid_mod.uuid4())
    target = (request.form.get("target") or "").strip()
    if not target:
        return render_template("osint.html", error="Cible vide.", active_tab=target_type), 400
    if target_type == "username" and not _USERNAME_RE.match(target):
        return render_template("osint.html", error="Nom d'utilisateur invalide (alphanumérique, . _ - uniquement, 1-100 caractères).", active_tab=target_type), 400
    if target_type == "phone" and not _PHONE_RE.match(target):
        return render_template("osint.html", error="Numéro de téléphone invalide.", active_tab=target_type), 400
    if target_type == "email" and "@" not in target:
        return render_template("osint.html", error="Adresse email invalide.", active_tab=target_type), 400
    if target_type == "domain" and not _DOMAIN_RE.match(target):
        return render_template("osint.html", error="Nom de domaine invalide.", active_tab=target_type), 400

    result = run_osint.delay(target_type, target, uid)
    return redirect(url_for("osint.osint_result", task_id=result.id))


@bp.route("/osint/result/<task_id>")
def osint_result(task_id):
    result = run_osint.AsyncResult(task_id)
    output = None
    error = None
    if result.state == "SUCCESS":
        data = result.result or {}
        output = data.get("output", "")
    elif result.state == "FAILURE":
        error = str(result.result)
    return render_template(
        "osint_result.html",
        task_id=task_id,
        state=result.state,
        output=output,
        error=error,
    )


@bp.route("/osint/batch")
def osint_batch():
    ids_raw = request.args.get("ids", "")
    names_raw = request.args.get("names", "")
    task_ids = [t.strip() for t in ids_raw.split(",") if t.strip()]
    names = [_url_unquote(n) for n in names_raw.split(",") if n.strip()]
    if not task_ids:
        abort(400)

    results = []
    all_done = True
    for i, tid in enumerate(task_ids):
        r = run_osint.AsyncResult(tid)
        if r.state in ("PENDING", "STARTED"):
            all_done = False
        item = {
            "task_id": tid,
            "state": r.state,
            "output": None,
            "error": None,
            "name": names[i] if i < len(names) else f"Image {i + 1}",
        }
        if r.state == "SUCCESS":
            item["output"] = (r.result or {}).get("output", "")
        elif r.state == "FAILURE":
            item["error"] = str(r.result)
        results.append(item)

    return render_template(
        "osint_result.html",
        batch=results,
        all_done=all_done,
        ids_raw=ids_raw,
        names_raw=names_raw,
    )
