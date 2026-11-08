import json
import os
import re
import time

import psycopg2
import psycopg2.extras
from flask import (
    Blueprint, Response, abort, redirect, render_template, request, send_file, url_for,
)

from penforge import config
from penforge.db.connection import resolve_report_path
from penforge.pentest.steps import STEP_FUNCS, excludable_steps
from penforge.worker.scheduler import start_scan, resume_scan, rerun_step

bp = Blueprint("scans", __name__)

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


def _get_conn():
    return psycopg2.connect()


def _parse_domains(text):
    valid, invalid = [], []
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if DOMAIN_RE.match(line):
            valid.append(line)
        else:
            invalid.append(line)
    return list(dict.fromkeys(valid)), invalid


@bp.route("/")
def index():
    with _get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT j.id, j.domain, j.status, j.scan_id, s.current_step
            FROM jobs j
            LEFT JOIN scans s ON s.id = j.scan_id
            WHERE j.status IN ('queued', 'running')
            ORDER BY j.id
            """
        )
        jobs = cur.fetchall()
        cur.execute(
            """
            SELECT id, domain, started_at, finished_at, ok_count, fail_count, skip_count
            FROM scans ORDER BY started_at DESC
            """
        )
        scans = cur.fetchall()
    return render_template("index.html", scans=scans, jobs=jobs)


@bp.route("/jobs/new")
def new_job():
    return render_template("new.html", invalid=[], domains_text="", steps=excludable_steps())


@bp.route("/jobs", methods=["POST"])
def create_jobs():
    text = request.form.get("domains", "")
    upload = request.files.get("file")
    if upload is not None and upload.filename:
        text += "\n" + upload.read().decode("utf-8", errors="replace")

    domains, invalid = _parse_domains(text)
    if invalid or not domains:
        return render_template(
            "new.html", invalid=invalid, domains_text=text, no_domain=not domains,
            steps=excludable_steps(),
        ), 400

    valid_step_ids = {step_id for step_id, _ in excludable_steps()}
    excluded_steps = set(request.form.getlist("exclude_steps")) & valid_step_ids
    for domain in domains:
        start_scan(domain, excluded_steps=excluded_steps)
    return redirect(url_for("scans.index"))


@bp.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    with _get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
        scan = cur.fetchone()
        if scan is None:
            abort(404)
        cur.execute(
            "SELECT * FROM scan_steps WHERE scan_id = %s ORDER BY recorded_at", (scan_id,)
        )
        steps = cur.fetchall()
        cur.execute(
            "SELECT EXISTS(SELECT 1 FROM scan_steps WHERE scan_id = %s AND status = 'RUNNING') AS running",
            (scan_id,),
        )
        running = cur.fetchone()["running"]
    for step in steps:
        step["has_file"] = resolve_report_path(step["report_path"]) is not None
        step["rerunnable"] = step["step_id"] in STEP_FUNCS
    resumable = scan["finished_at"] is None and not running
    return render_template("scan.html", scan=scan, steps=steps, running=running, resumable=resumable)


@bp.route("/scan/<int:scan_id>/stop", methods=["POST"])
def scan_stop(scan_id):
    from penforge.db import scans as _db_scans
    _db_scans.stop_scan(scan_id)
    return redirect(url_for("scans.scan_detail", scan_id=scan_id))


@bp.route("/scan/<int:scan_id>/step/<step_id>/skip", methods=["POST"])
def scan_skip(scan_id, step_id):
    from penforge.db import steps as _db_steps
    _db_steps.request_skip(scan_id, step_id)
    return redirect(url_for("scans.scan_detail", scan_id=scan_id))


@bp.route("/scan/<int:scan_id>/resume", methods=["POST"])
def scan_resume(scan_id):
    resume_scan(scan_id)
    return redirect(url_for("scans.scan_detail", scan_id=scan_id))


@bp.route("/scan/<int:scan_id>/step/<step_id>/rerun", methods=["POST"])
def step_rerun(scan_id, step_id):
    if step_id not in STEP_FUNCS:
        abort(404)
    rerun_step(scan_id, step_id)
    return redirect(url_for("scans.scan_detail", scan_id=scan_id))


@bp.route("/scan/<int:scan_id>/live")
def scan_live(scan_id):
    with _get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, domain, finished_at FROM scans WHERE id = %s", (scan_id,))
        scan = cur.fetchone()
    if scan is None:
        abort(404)
    return render_template("live.html", scan=scan)


@bp.route("/scan/<int:scan_id>/logs")
def scan_logs(scan_id):
    last_id = request.headers.get("Last-Event-ID", "0")
    cursor_id = int(last_id) if last_id.isdigit() else 0

    def stream():
        nonlocal cursor_id
        while True:
            with _get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT finished_at IS NOT NULL AS finished FROM scans WHERE id = %s", (scan_id,))
                state = cur.fetchone()
                if state is None:
                    yield "event: end\ndata: scan introuvable\n\n"
                    return
                finished = state["finished"]
                cur.execute(
                    "SELECT id, line FROM scan_logs WHERE scan_id = %s AND id > %s ORDER BY id LIMIT 500",
                    (scan_id, cursor_id),
                )
                rows = cur.fetchall()
            for row in rows:
                cursor_id = row["id"]
                yield f"id: {row['id']}\ndata: {json.dumps(row['line'], ensure_ascii=False)}\n\n"
            if finished and not rows:
                yield "event: end\ndata: fin\n\n"
                return
            time.sleep(1)

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@bp.route("/scan/<int:scan_id>/delete", methods=["POST"])
def scan_delete(scan_id):
    with _get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
        if cur.rowcount == 0:
            abort(404)
    return redirect(url_for("scans.index"))


def _get_step_or_404(scan_id, step_id):
    with _get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM scan_steps WHERE scan_id = %s AND step_id = %s ORDER BY id DESC LIMIT 1",
            (scan_id, step_id),
        )
        step = cur.fetchone()
    if step is None:
        abort(404)
    real = resolve_report_path(step["report_path"])
    if real is None:
        abort(404)
    return step, real


@bp.route("/scan/<int:scan_id>/step/<step_id>/file")
@bp.route("/scan/<int:scan_id>/step/<step_id>/file/<path:subpath>")
def step_file(scan_id, step_id, subpath=""):
    step, base_real = _get_step_or_404(scan_id, step_id)
    target = os.path.realpath(os.path.join(base_real, subpath)) if subpath else base_real
    if os.path.commonpath([target, base_real]) != base_real:
        abort(404)
    if os.path.isdir(target):
        entries = sorted(os.listdir(target))
        return render_template(
            "listing.html",
            scan_id=scan_id,
            step_id=step_id,
            label=step["label"],
            subpath=subpath,
            entries=entries,
        )
    if os.path.isfile(target):
        return send_file(target)
    abort(404)
