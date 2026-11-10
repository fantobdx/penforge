import psycopg2.extras

from penforge.db.connection import _cursor, _read_report_content


PRIORITY_CHOICES = {1: "Urgente", 3: "Haute", 5: "Normale", 7: "Basse", 9: "Arrière-plan"}
_VALID_PRIORITIES = frozenset(PRIORITY_CHOICES)


def start_scan(domain, excluded=None, priority=5):
    """Insère un nouveau scan. excluded : liste de (step_id, label) enregistrés SKIP d'emblée."""
    if priority not in _VALID_PRIORITIES:
        priority = 5
    with _cursor() as cur:
        cur.execute("INSERT INTO scans (domain, priority) VALUES (%s, %s) RETURNING id", (domain, priority))
        scan_id = cur.fetchone()[0]
        for step_id, label in excluded or []:
            cur.execute(
                "INSERT INTO scan_steps (scan_id, step_id, label, status, note) "
                "VALUES (%s, %s, %s, 'SKIP', 'exclu avant le lancement du scan')",
                (scan_id, step_id, label),
            )
        return scan_id


def finish_scan(scan_id, ok, fail, skip):
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE scans
            SET finished_at = now(), ok_count = %s, fail_count = %s, skip_count = %s, current_step = NULL
            WHERE id = %s
            """,
            (ok, fail, skip, scan_id),
        )


def append_logs(scan_id, lines, step_id=None):
    with _cursor() as cur:
        psycopg2.extras.execute_values(
            cur, "INSERT INTO scan_logs (scan_id, line, step_id) VALUES %s",
            [(scan_id, line, step_id) for line in lines],
        )


def create_job(domain, scan_id):
    with _cursor() as cur:
        cur.execute("INSERT INTO jobs (domain, status, scan_id) VALUES (%s, 'queued', %s)", (domain, scan_id))


def stop_scan(scan_id):
    """Demande l'arrêt si une étape est active. Retourne False sinon."""
    with _cursor() as cur:
        cur.execute("SELECT 1 FROM scan_steps WHERE scan_id = %s AND status = 'RUNNING'", (scan_id,))
        if cur.fetchone() is None:
            return False
        cur.execute("UPDATE jobs SET status = 'stopped' WHERE scan_id = %s", (scan_id,))
    return True


def resume_scan(scan_id):
    """None si non reprennable. Sinon (domain, {step_ids déjà OK/FAIL/SKIP})."""
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
    """Retourne le domaine du scan si actif, None sinon."""
    with _cursor() as cur:
        cur.execute("SELECT domain FROM scans WHERE id = %s AND finished_at IS NULL", (scan_id,))
        row = cur.fetchone()
    return row[0] if row else None


def tally_latest_statuses(scan_id):
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
    with _cursor() as cur:
        cur.execute(
            "UPDATE jobs SET status = 'failed', finished_at = now() WHERE scan_id = %s AND status = 'running'",
            (scan_id,),
        )


def refresh_finished_counts(scan_id):
    ok, fail, skip = tally_latest_statuses(scan_id)
    with _cursor() as cur:
        cur.execute(
            "UPDATE scans SET ok_count = %s, fail_count = %s, skip_count = %s "
            "WHERE id = %s AND finished_at IS NOT NULL",
            (ok, fail, skip, scan_id),
        )


def get_findings(scan_id, step_id=None, severity=None):
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


def get_scan_priority(scan_id):
    with _cursor() as cur:
        cur.execute("SELECT priority FROM scans WHERE id = %s", (scan_id,))
        row = cur.fetchone()
    return row[0] if row else 5


def set_scan_priority(scan_id, priority):
    if priority not in _VALID_PRIORITIES:
        return False
    with _cursor() as cur:
        cur.execute("UPDATE scans SET priority = %s WHERE id = %s RETURNING id", (priority, scan_id))
        return cur.fetchone() is not None


def insert_findings(scan_id, findings):
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
