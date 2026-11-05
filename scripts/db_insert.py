"""Accès Postgres de pentest.py, tasks.py (Celery) et du web.

Connexion via psycopg2.connect() sans argument : lit nativement les variables d'environnement
standard PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD, les mêmes que celles utilisées pour
configurer pentest.py.

Les chemins de rapport enregistrés sont relatifs au volume /reports : ils sont préfixés par
scans/<scan_id>/, le dossier de travail de chaque scan.

Un scan est maintenant orchestré par une chain() Celery (tasks.py) plutôt que par un worker à
base de polling : chaque étape (scan_steps) passe par 'RUNNING' pendant son exécution, ce qui
permet au web de savoir si un scan a une étape active (pour proposer Arrêter) ou non (Reprendre /
Relancer un outil). 'STOPPED' marque une étape interrompue par l'utilisateur, à distinguer de
'FAIL' (échec de l'outil) : une étape STOPPED n'est pas "déjà passée" et sera rejouée par
resume_scan().
"""

import os

from contextlib import contextmanager

import psycopg2
import psycopg2.extras

MAX_REPORT_BYTES = 2 * 1024 * 1024  # 2 Mo : au-delà, on garde le chemin plutôt que le contenu.
REPORTS_ROOT = os.path.realpath("/reports")  # volume pentest-reports, monté en lecture seule
                                              # par web/app.py et pentest_mcp.py (deux services).

_conn = None
_conn_pid = None


@contextmanager
def _cursor():
    """Curseur sur une connexion partagée par processus. Ouvrir une connexion à chaque appel
    créait une socket TCP par requête (stop_requested est appelé chaque seconde pendant une
    étape) : d'où des milliers de TIME-WAIT vers Postgres. Recréée si elle est fermée ou si le
    process a été forké (pool prefork de Celery)."""
    global _conn, _conn_pid
    if _conn is None or _conn.closed or _conn_pid != os.getpid():
        _conn = psycopg2.connect()
        _conn_pid = os.getpid()
    with _conn, _conn.cursor() as cur:
        yield cur


def _read_report_content(report_path):
    """Retourne le contenu texte si report_path est un fichier régulier lisible et
    raisonnablement petit, sinon None (répertoires wapiti/dirbuster, chemins
    inexistants ou simples descriptions textuelles comme pour metagoofil)."""
    if not report_path or not os.path.isfile(report_path):
        return None
    try:
        if os.path.getsize(report_path) > MAX_REPORT_BYTES:
            return None
        with open(report_path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def resolve_report_path(report_path):
    """Résout report_path (tel qu'enregistré par pentest.py, relatif à /reports ou déjà
    absolu sous /reports) en chemin réel, et vérifie qu'il reste bien sous /reports.
    Retourne None si absent, hors de /reports, ou introuvable sur le disque. Partagée par
    web/app.py et pentest_mcp.py (même volume /reports, monté en lecture seule par les deux)."""
    if not report_path:
        return None
    candidate = report_path if os.path.isabs(report_path) else os.path.join(REPORTS_ROOT, report_path)
    real = os.path.realpath(candidate)
    if os.path.commonpath([real, REPORTS_ROOT]) != REPORTS_ROOT:
        return None
    if not os.path.exists(real):
        return None
    return real


def ensure_database(name):
    """Crée la base <name> sur le même serveur Postgres si elle n'existe pas (connexion
    autocommit dédiée : CREATE DATABASE ne peut pas s'exécuter dans une transaction). Utilisée
    par pentest.run_metasploit_auto() pour la base de travail de Metasploit (db_nmap/db_autopwn),
    séparée de la base applicative pentest."""
    conn = psycopg2.connect()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            if cur.fetchone() is None:
                cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        conn.close()


def start_scan(domain, excluded=None):
    """Insère une nouvelle ligne dans scans, retourne son id. `excluded` : liste de (step_id,
    label) à enregistrer tout de suite en SKIP (exclus avant le lancement par l'appelant, voir
    tasks.start_scan) — jamais mis dans la chaîne Celery, donc jamais RUNNING."""
    with _cursor() as cur:
        cur.execute("INSERT INTO scans (domain) VALUES (%s) RETURNING id", (domain,))
        scan_id = cur.fetchone()[0]
        for step_id, label in excluded or []:
            cur.execute(
                "INSERT INTO scan_steps (scan_id, step_id, label, status, note) "
                "VALUES (%s, %s, %s, 'SKIP', 'exclu avant le lancement du scan')",
                (scan_id, step_id, label),
            )
        return scan_id


def finish_scan(scan_id, ok, fail, skip):
    """Marque le scan comme terminé avec ses compteurs finaux."""
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE scans
            SET finished_at = now(), ok_count = %s, fail_count = %s, skip_count = %s, current_step = NULL
            WHERE id = %s
            """,
            (ok, fail, skip, scan_id),
        )


def append_logs(scan_id, lines):
    """Ajoute des lignes de sortie d'un scan, lues en direct par la page de logs du web.
    Un seul INSERT dans une seule transaction pour tout le lot."""
    with _cursor() as cur:
        psycopg2.extras.execute_values(
            cur, "INSERT INTO scan_logs (scan_id, line) VALUES %s", [(scan_id, line) for line in lines]
        )


def create_job(domain, scan_id):
    """Crée la ligne jobs associée à un scan déjà démarré (start_scan), état initial 'queued'."""
    with _cursor() as cur:
        cur.execute("INSERT INTO jobs (domain, status, scan_id) VALUES (%s, 'queued', %s)", (domain, scan_id))


# --- Pool de ports Tor, partagé entre les workers Celery --------------------------------
# Une étape active = un port loué pour sa durée. FOR UPDATE SKIP LOCKED : même idiome que
# l'ancien claim_job(), deux workers ne prennent jamais le même port.

def register_tor_ports(ports):
    """Repeuple tor_instances avec exactement les ports donnés (TRUNCATE puis insert), pour
    rester cohérent avec SCAN_WORKERS même s'il a changé depuis le dernier démarrage."""
    with _cursor() as cur:
        cur.execute("TRUNCATE tor_instances")
        psycopg2.extras.execute_values(
            cur, "INSERT INTO tor_instances (port) VALUES %s", [(p,) for p in ports]
        )


def acquire_tor_port(task_id):
    """Réserve un port libre, retourne son numéro, ou None si tous sont occupés."""
    with _cursor() as cur:
        cur.execute(
            "SELECT port FROM tor_instances WHERE locked_by_task_id IS NULL "
            "ORDER BY port LIMIT 1 FOR UPDATE SKIP LOCKED"
        )
        row = cur.fetchone()
        if row is None:
            return None
        cur.execute("UPDATE tor_instances SET locked_by_task_id = %s WHERE port = %s", (task_id, row[0]))
        return row[0]


def release_tor_port(port):
    with _cursor() as cur:
        cur.execute("UPDATE tor_instances SET locked_by_task_id = NULL WHERE port = %s", (port,))


# --- Étapes d'un scan --------------------------------------------------------------------
# Depuis la parallélisation des étapes indépendantes (tasks._schedule_for), plusieurs lignes
# scan_steps peuvent être RUNNING en même temps pour un même scan : current_step n'est plus
# écrit par chaque étape avec son propre label (dernier écrivain gagne, racy), mais recalculé
# ici même, dans la même transaction, comme l'agrégat de tout ce qui est RUNNING à cet instant.

def _recompute_current_step(cur, scan_id):
    cur.execute(
        "SELECT string_agg(label, ', ' ORDER BY id) FROM scan_steps "
        "WHERE scan_id = %s AND status = 'RUNNING'",
        (scan_id,),
    )
    cur.execute("UPDATE scans SET current_step = %s WHERE id = %s", (cur.fetchone()[0], scan_id))


def mark_step_running(scan_id, step_id, label, task_id):
    """Insère la ligne RUNNING et passe le job 'running'. Retourne l'id de la ligne, ou None
    si un arrêt a été demandé entre deux étapes de la chaîne (l'étape ne doit pas démarrer)."""
    with _cursor() as cur:
        cur.execute("SELECT status FROM jobs WHERE scan_id = %s", (scan_id,))
        row = cur.fetchone()
        if row and row[0] == "stopped":
            return None
        cur.execute(
            "UPDATE jobs SET status = 'running', started_at = COALESCE(started_at, now()) "
            "WHERE scan_id = %s",
            (scan_id,),
        )
        cur.execute(
            "INSERT INTO scan_steps (scan_id, step_id, label, status, task_id) "
            "VALUES (%s, %s, %s, 'RUNNING', %s) RETURNING id",
            (scan_id, step_id, label, task_id),
        )
        step_row_id = cur.fetchone()[0]
        _recompute_current_step(cur, scan_id)
        return step_row_id


def finish_step(step_row_id, status, report_path, note):
    """Termine une ligne scan_steps déjà RUNNING (OK/FAIL/SKIP/STOPPED), avec le contenu du
    rapport s'il est lisible (_read_report_content, comme avant). report_path est relatif au
    dossier du scan (cwd de l'étape) ; il est stocké préfixé par scans/<scan_id>/ pour être
    résolu depuis /reports par le web."""
    content = _read_report_content(report_path)
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE scan_steps
            SET status = %s, report_path = 'scans/' || scan_id || '/' || %s,
                report_content = %s, note = %s, recorded_at = now()
            WHERE id = %s
            RETURNING scan_id
            """,
            (status, report_path, content, note, step_row_id),
        )
        _recompute_current_step(cur, cur.fetchone()[0])


def stop_requested(scan_id):
    """Lu par pentest.run() à chaque réveil périodique, pour tuer l'outil en cours si demandé."""
    with _cursor() as cur:
        cur.execute("SELECT status = 'stopped' FROM jobs WHERE scan_id = %s", (scan_id,))
        row = cur.fetchone()
    return bool(row and row[0])


def stop_scan(scan_id):
    """Demande l'arrêt : seulement si une étape de ce scan est active. Retourne False sinon
    (rien à arrêter — scan déjà terminé ou déjà arrêté)."""
    with _cursor() as cur:
        cur.execute("SELECT 1 FROM scan_steps WHERE scan_id = %s AND status = 'RUNNING'", (scan_id,))
        if cur.fetchone() is None:
            return False
        cur.execute("UPDATE jobs SET status = 'stopped' WHERE scan_id = %s", (scan_id,))
    return True


def request_skip(scan_id, step_id):
    """Demande de sauter l'étape step_id de scan_id si elle est RUNNING, sans arrêter le reste
    du scan (web et MCP) : marque skip_requested sur sa ligne. Plusieurs étapes pouvant être
    RUNNING en même temps (voir tasks._schedule_for), step_id désambiguïse laquelle sauter --
    stable tant qu'elle est active, un step_id donné n'a jamais deux lignes RUNNING à la fois
    pour un même scan (begin_rerun refuse de relancer une étape pendant qu'une autre tourne).
    Retourne False si cette étape n'est pas active (rien à sauter)."""
    with _cursor() as cur:
        cur.execute(
            "UPDATE scan_steps SET skip_requested = true "
            "WHERE scan_id = %s AND step_id = %s AND status = 'RUNNING'",
            (scan_id, step_id),
        )
        return cur.rowcount > 0


def skip_requested(scan_id, step_id):
    """Lu par pentest.run() à chaque réveil périodique, pour sauter l'outil en cours (sans
    arrêter le scan) si demandé — pendant de stop_requested. Ciblé par step_id comme
    request_skip, pour ne pas lire la ligne RUNNING d'une autre étape du même scan."""
    with _cursor() as cur:
        cur.execute(
            "SELECT skip_requested FROM scan_steps WHERE scan_id = %s AND step_id = %s AND status = 'RUNNING'",
            (scan_id, step_id),
        )
        row = cur.fetchone()
    return bool(row and row[0])


def resume_scan(scan_id):
    """None si le scan n'existe pas, est déjà terminé, ou a une étape active. Sinon
    (domain, {step_id déjà OK/FAIL/SKIP}) et repasse le job 'running'. Une étape STOPPED n'est
    volontairement pas dans cet ensemble : elle sera rejouée par l'appelant (tasks.resume_scan)."""
    with _cursor() as cur:
        cur.execute(
            """
            SELECT domain FROM scans s WHERE s.id = %s AND s.finished_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM scan_steps WHERE scan_id = s.id AND status = 'RUNNING')
            """,
            (scan_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        domain = row[0]
        cur.execute(
            "SELECT step_id FROM scan_steps WHERE scan_id = %s AND status IN ('OK', 'FAIL', 'SKIP')",
            (scan_id,),
        )
        done = {r[0] for r in cur.fetchall()}
        cur.execute("UPDATE jobs SET status = 'running' WHERE scan_id = %s", (scan_id,))
    return domain, done


def begin_rerun(scan_id):
    """Domaine du scan si aucune étape n'y est active, sinon None. Repasse le job 'running'
    (annule un 'stopped'/'failed' précédent, sinon le polling de run() auto-arrêterait la
    nouvelle tentative immédiatement)."""
    with _cursor() as cur:
        cur.execute(
            """
            SELECT domain FROM scans s WHERE s.id = %s
            AND NOT EXISTS (SELECT 1 FROM scan_steps WHERE scan_id = s.id AND status = 'RUNNING')
            """,
            (scan_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        cur.execute("UPDATE jobs SET status = 'running' WHERE scan_id = %s", (scan_id,))
    return row[0]


def tally_latest_statuses(scan_id):
    """Compte les statuts du dernier enregistrement de chaque step_id (une étape relancée ne
    compte qu'une fois, avec son résultat le plus récent)."""
    with _cursor() as cur:
        cur.execute(
            """
            SELECT status, count(*) FROM (
                SELECT DISTINCT ON (step_id) step_id, status FROM scan_steps
                WHERE scan_id = %s ORDER BY step_id, id DESC
            ) latest GROUP BY status
            """,
            (scan_id,),
        )
        counts = dict(cur.fetchall())
    return counts.get("OK", 0), counts.get("FAIL", 0), counts.get("SKIP", 0)


def finish_job_for_scan(scan_id, status):
    with _cursor() as cur:
        cur.execute(
            "UPDATE jobs SET status = %s, finished_at = now() WHERE scan_id = %s", (status, scan_id)
        )


def fail_job_for_scan(scan_id):
    """Utilisé par l'errback de la chain() Celery (exception inattendue, pas un échec d'outil
    normal) : ne touche que les jobs encore 'running', pour ne pas écraser un 'stopped' voulu."""
    with _cursor() as cur:
        cur.execute(
            "UPDATE jobs SET status = 'failed', finished_at = now() WHERE scan_id = %s AND status = 'running'",
            (scan_id,),
        )


def fail_dangling_running_step(scan_id, note):
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE scan_steps SET status = 'FAIL', note = COALESCE(note || ' ', '') || %s
            WHERE scan_id = %s AND status = 'RUNNING'
            """,
            (f"[erreur interne : {note}]", scan_id),
        )


def refresh_finished_counts(scan_id):
    """Recalcule ok/fail/skip après la relance d'une seule étape sur un scan déjà terminé."""
    ok, fail, skip = tally_latest_statuses(scan_id)
    with _cursor() as cur:
        cur.execute(
            "UPDATE scans SET ok_count = %s, fail_count = %s, skip_count = %s "
            "WHERE id = %s AND finished_at IS NOT NULL",
            (ok, fail, skip, scan_id),
        )


def get_findings(scan_id, step_id=None, severity=None):
    """Retourne les findings d'un scan, filtrés optionnellement par step_id et/ou severity.
    Utilisé par les steps adaptatifs (credential_spray) pour lire les résultats des steps
    précédents sans parser les fichiers texte bruts."""
    with _cursor() as cur:
        conditions = ["scan_id = %s"]
        params = [scan_id]
        if step_id is not None:
            conditions.append("step_id = %s")
            params.append(step_id)
        if severity is not None:
            conditions.append("severity = %s")
            params.append(severity)
        cur.execute(
            "SELECT step_id, severity, title, detail, recommendation "
            f"FROM findings WHERE {' AND '.join(conditions)} ORDER BY id",
            params,
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def insert_findings(scan_id, findings):
    """Insère une liste de findings [{step_id, severity, title, detail, recommendation}].
    Appelée par pentest._analyze_step_output() après chaque étape OK."""
    if not findings:
        return
    with _cursor() as cur:
        psycopg2.extras.execute_values(
            cur,
            "INSERT INTO findings (scan_id, step_id, severity, title, detail, recommendation) VALUES %s",
            [
                (scan_id, f["step_id"], f["severity"], f["title"], f.get("detail"), f.get("recommendation"))
                for f in findings
            ],
        )


def recover_crashed_steps():
    """Au démarrage du worker : les étapes restées RUNNING et les jobs restés 'running'
    appartiennent à un worker arrêté (crash, redémarrage)."""
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE scan_steps SET status = 'FAIL',
                note = COALESCE(note || ' ', '') || '[interrompu par un redémarrage du worker]'
            WHERE status = 'RUNNING'
            """
        )
        cur.execute("UPDATE jobs SET status = 'failed', finished_at = now() WHERE status = 'running'")
