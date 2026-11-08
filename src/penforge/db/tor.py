import psycopg2.extras

from penforge.db.connection import _cursor


def register_tor_ports(ports):
    """Repeuple tor_instances avec exactement les ports donnés."""
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
