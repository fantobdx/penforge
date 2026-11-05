#!/usr/bin/env python3
"""Interface web pentest : historique des scans, file d'attente, lancement et logs en direct.

Connexion via psycopg2.connect() sans argument : lit nativement PGHOST/PGPORT/PGDATABASE/
PGUSER/PGPASSWORD, les mêmes variables que db_insert.py et pentest.py. Le volume
pentest-reports est monté en lecture seule sous /reports (comme dans le conteneur pentest) pour
servir les rapports, y compris ceux de type répertoire (wapiti, dirbuster).

Authentification HTTP Basic obligatoire : WEB_PASSWORD doit être défini, WEB_USER vaut admin
par défaut. Servie par gunicorn en HTTPS (voir web/Dockerfile).
"""

import collections
import hmac
import json
import logging
import os
import re
import threading
import time

import psycopg2
import psycopg2.extras
import redis
from flask import Flask, Response, abort, redirect, render_template, request, send_file, url_for

import db_insert
import pentest
import tasks

WEB_USER = os.environ.get("WEB_USER", "admin")
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
if not WEB_PASSWORD:
    raise RuntimeError("WEB_PASSWORD requis : l'interface n'est pas démarrée sans authentification.")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1 Mo : une liste de domaines n'a pas besoin de plus


def get_conn():
    return psycopg2.connect()


# --- Mesures Redis / Celery pour la page /queues ----------------------------------------------
# Un thread relève la file toutes les 2 s : compteurs, contenu (nom et arguments de chaque
# tâche) et journal des changements d'état entre deux relevés. Tout est en mémoire du process,
# borné par des deque. gunicorn tourne avec --workers 1 (web/Dockerfile) : un seul échantillonneur.
SAMPLE_INTERVAL_S = 2
SAMPLE_WINDOW = 1800
EVENTS_WINDOW = 500
SNAPSHOT_LIMIT = 200
QUEUE_NAME = "celery"  # file par défaut de Celery (aucune route ni priorité dans tasks.py)
UNACKED_KEY = "unacked"  # hash Kombu : tag -> [message brut, exchange, routing_key] des tâches livrées non acquittées

redis_client = redis.Redis.from_url(tasks.app.conf.broker_url)
samples = collections.deque(maxlen=SAMPLE_WINDOW)
events = collections.deque(maxlen=EVENTS_WINDOW)
current_tasks = {"pending": [], "unacked": []}
samples_lock = threading.Lock()
log = logging.getLogger(__name__)


def task_info(raw):
    headers = raw.get("headers", {})
    return {"id": headers.get("id"), "task": headers.get("task"), "args": headers.get("argsrepr", "")}


def read_queue():
    """Retourne (en attente, non acquittées), chacun indexé par id de tâche."""
    pending = {}
    for item in redis_client.lrange(QUEUE_NAME, 0, -1):
        info = task_info(json.loads(item))
        pending[info["id"]] = info
    unacked = {}
    for value in redis_client.hvals(UNACKED_KEY):
        info = task_info(json.loads(value)[0])
        unacked[info["id"]] = info
    return pending, unacked


def take_server_metrics():
    memory = redis_client.info("memory")["used_memory"]
    clients = redis_client.info("clients")["connected_clients"]
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*), count(locked_by_task_id) FROM tor_instances")
        capacity, busy = cur.fetchone()
    return {
        "busy": busy,
        "capacity": capacity,
        "memory_mb": round(memory / 1024 / 1024, 2),
        "clients": clients,
    }


def diff_events(before_pending, before_unacked, pending, unacked, now):
    """Décrit les changements d'état de tâches entre deux relevés consécutifs."""
    found = []

    def add(label, info):
        found.append({"t": now, "event": label, "task": info["task"], "args": info["args"]})

    for tid, info in pending.items():
        if tid not in before_pending and tid not in before_unacked:
            add("en file", info)
    for tid, info in unacked.items():
        if tid not in before_unacked:
            add("prise par un worker", info)
    for tid, info in before_unacked.items():
        if tid not in unacked:
            add("remise en file" if tid in pending else "acquittée", info)
    for tid, info in before_pending.items():
        if tid not in pending and tid not in unacked:
            add("retirée de la file", info)
    return found


def sample_loop():
    before_pending, before_unacked = {}, {}
    while True:
        try:
            pending, unacked = read_queue()
            now = int(time.time() * 1000)
            sample = {"t": now, "pending": len(pending), "unacked": len(unacked), **take_server_metrics()}
            new_events = diff_events(before_pending, before_unacked, pending, unacked, now)
            with samples_lock:
                samples.append(sample)
                events.extend(new_events)
                current_tasks["pending"] = list(pending.values())[:SNAPSHOT_LIMIT]
                current_tasks["unacked"] = list(unacked.values())[:SNAPSHOT_LIMIT]
            before_pending, before_unacked = pending, unacked
        except Exception:
            log.exception("Échec de l'échantillonnage Redis/Postgres")
        time.sleep(SAMPLE_INTERVAL_S)


threading.Thread(target=sample_loop, daemon=True, name="queue-sampler").start()


@app.before_request
def require_auth():
    auth = request.authorization
    if (
        auth is None
        or not hmac.compare_digest((auth.username or "").encode(), WEB_USER.encode())
        or not hmac.compare_digest((auth.password or "").encode(), WEB_PASSWORD.encode())
    ):
        return Response("Authentification requise.", 401, {"WWW-Authenticate": 'Basic realm="pentest"'})
    # Basic auth est renvoyé par le navigateur même pour un POST venant d'un autre site :
    # on refuse les POST dont l'origine n'est pas cette interface (protection CSRF).
    origin = request.headers.get("Origin")
    if request.method == "POST" and origin is not None and origin != request.host_url.rstrip("/"):
        abort(403)


def parse_domains(text):
    """Retourne (domaines valides dédupliqués, lignes invalides). Ignore lignes vides et #."""
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


@app.route("/")
def index():
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
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


@app.route("/stats")
def stats():
    return render_template("stats.html")


@app.route("/stats/counters")
def stats_counters():
    """Compteurs cumulés de la base : sessions ouvertes, transactions validées, lignes de logs."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT d.sessions, d.xact_commit, t.n_tup_ins
            FROM pg_stat_database d, pg_stat_user_tables t
            WHERE d.datname = current_database() AND t.relname = 'scan_logs'
            """
        )
        sessions, xact_commit, log_rows = cur.fetchone()
    return {"sessions": sessions, "xact_commit": xact_commit, "log_rows": log_rows}


@app.route("/queues")
def queues():
    return render_template("queues.html")


@app.route("/queues/metrics")
def queues_metrics():
    """Échantillons et événements postérieurs à `since` (epoch ms, 0 = tout l'historique borné),
    plus le contenu courant de la file (tâches en attente et en cours)."""
    since = request.args.get("since", "0")
    since = int(since) if since.isdigit() else 0
    with samples_lock:
        recent_samples = [s for s in samples if s["t"] > since]
        recent_events = [e for e in events if e["t"] > since]
        tasks_now = {"pending": list(current_tasks["pending"]), "unacked": list(current_tasks["unacked"])}
    return {"samples": recent_samples, "events": recent_events, "tasks": tasks_now}


@app.route("/jobs/new")
def new_job():
    return render_template("new.html", invalid=[], domains_text="", steps=pentest.excludable_steps())


@app.route("/jobs", methods=["POST"])
def create_jobs():
    text = request.form.get("domains", "")
    upload = request.files.get("file")
    if upload is not None and upload.filename:
        text += "\n" + upload.read().decode("utf-8", errors="replace")

    domains, invalid = parse_domains(text)
    if invalid or not domains:
        return render_template(
            "new.html", invalid=invalid, domains_text=text, no_domain=not domains,
            steps=pentest.excludable_steps(),
        ), 400

    valid_step_ids = {step_id for step_id, _ in pentest.excludable_steps()}
    excluded_steps = set(request.form.getlist("exclude_steps")) & valid_step_ids
    for domain in domains:
        tasks.start_scan(domain, excluded_steps=excluded_steps)
    return redirect(url_for("index"))


@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
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
        step["has_file"] = db_insert.resolve_report_path(step["report_path"]) is not None
        # Rejouable seulement si l'étape appartient à la chaîne Celery (même garde que la route
        # /rerun). Les étapes hors chaîne (ex. metasploit-auto, synchrone) ne le sont pas.
        step["rerunnable"] = step["step_id"] in pentest.STEP_FUNCS
    resumable = scan["finished_at"] is None and not running
    return render_template("scan.html", scan=scan, steps=steps, running=running, resumable=resumable)


@app.route("/scan/<int:scan_id>/stop", methods=["POST"])
def scan_stop(scan_id):
    db_insert.stop_scan(scan_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/step/<step_id>/skip", methods=["POST"])
def scan_skip(scan_id, step_id):
    """Saute step_id s'il est RUNNING, sans arrêter le reste du scan (db_insert.request_skip, lu
    par pentest.run() dans l'étape active) — à distinguer de /stop, qui arrête tout le scan.
    Ciblé par step_id (et non plus par scan_id seul) depuis que plusieurs étapes indépendantes
    peuvent être RUNNING en même temps pour un même scan (tasks._schedule_for)."""
    db_insert.request_skip(scan_id, step_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/resume", methods=["POST"])
def scan_resume(scan_id):
    tasks.resume_scan(scan_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/step/<step_id>/rerun", methods=["POST"])
def step_rerun(scan_id, step_id):
    if step_id not in pentest.STEP_FUNCS:
        abort(404)
    tasks.rerun_step(scan_id, step_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/live")
def scan_live(scan_id):
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, domain, finished_at FROM scans WHERE id = %s", (scan_id,))
        scan = cur.fetchone()
    if scan is None:
        abort(404)
    return render_template("live.html", scan=scan)


@app.route("/scan/<int:scan_id>/logs")
def scan_logs(scan_id):
    """Flux Server-Sent Events : envoie les lignes de scan_logs au fil de leur écriture,
    et se termine quand le scan est fini et que tout a été envoyé."""
    last_id = request.headers.get("Last-Event-ID", "0")
    cursor_id = int(last_id) if last_id.isdigit() else 0

    def stream():
        nonlocal cursor_id
        while True:
            with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
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


@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
def scan_delete(scan_id):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
        if cur.rowcount == 0:
            abort(404)
    return redirect(url_for("index"))


def get_step_or_404(scan_id, step_id):
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM scan_steps WHERE scan_id = %s AND step_id = %s ORDER BY id DESC LIMIT 1",
            (scan_id, step_id),
        )
        step = cur.fetchone()
    if step is None:
        abort(404)
    real = db_insert.resolve_report_path(step["report_path"])
    if real is None:
        abort(404)
    return step, real


@app.route("/scan/<int:scan_id>/step/<step_id>/file")
@app.route("/scan/<int:scan_id>/step/<step_id>/file/<path:subpath>")
def step_file(scan_id, step_id, subpath=""):
    step, base_real = get_step_or_404(scan_id, step_id)
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
