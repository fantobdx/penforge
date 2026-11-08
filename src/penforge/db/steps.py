from penforge.db.connection import _cursor, _read_report_content


def _recompute_current_step(cur, scan_id):
    cur.execute(
        "SELECT string_agg(label, ', ' ORDER BY id) FROM scan_steps "
        "WHERE scan_id = %s AND status = 'RUNNING'",
        (scan_id,),
    )
    cur.execute("UPDATE scans SET current_step = %s WHERE id = %s", (cur.fetchone()[0], scan_id))


def mark_step_running(scan_id, step_id, label, task_id):
    """Insère la ligne RUNNING. Retourne l'id de la ligne, ou None si arrêt demandé."""
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
    with _cursor() as cur:
        cur.execute("SELECT status = 'stopped' FROM jobs WHERE scan_id = %s", (scan_id,))
        row = cur.fetchone()
    return bool(row and row[0])


def request_skip(scan_id, step_id):
    """Marque skip_requested sur la ligne RUNNING de step_id. Retourne False si non active."""
    with _cursor() as cur:
        cur.execute(
            "UPDATE scan_steps SET skip_requested = true "
            "WHERE scan_id = %s AND step_id = %s AND status = 'RUNNING'",
            (scan_id, step_id),
        )
        return cur.rowcount > 0


def skip_requested(scan_id, step_id):
    with _cursor() as cur:
        cur.execute(
            "SELECT skip_requested FROM scan_steps WHERE scan_id = %s AND step_id = %s AND status = 'RUNNING'",
            (scan_id, step_id),
        )
        row = cur.fetchone()
    return bool(row and row[0])


def begin_rerun(scan_id):
    """Domaine du scan si aucune étape active, sinon None. Repasse le job 'running'."""
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


def fail_dangling_running_step(scan_id, note):
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE scan_steps SET status = 'FAIL', note = COALESCE(note || ' ', '') || %s
            WHERE scan_id = %s AND status = 'RUNNING'
            """,
            (f"[erreur interne : {note}]", scan_id),
        )


def recover_crashed_steps():
    """Au démarrage du worker : nettoie les étapes et jobs d'un crash précédent."""
    with _cursor() as cur:
        cur.execute(
            """
            UPDATE scan_steps SET status = 'FAIL',
                note = COALESCE(note || ' ', '') || '[interrompu par un redémarrage du worker]'
            WHERE status = 'RUNNING'
            """
        )
        cur.execute("UPDATE jobs SET status = 'failed', finished_at = now() WHERE status = 'running'")
