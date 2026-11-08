import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras

MAX_REPORT_BYTES = 2 * 1024 * 1024
REPORTS_ROOT = os.path.realpath("/reports")

_conn = None
_conn_pid = None


@contextmanager
def _cursor():
    """Curseur sur une connexion partagée par processus. Recréée si fermée ou si forkée."""
    global _conn, _conn_pid
    if _conn is None or _conn.closed or _conn_pid != os.getpid():
        _conn = psycopg2.connect()
        _conn_pid = os.getpid()
    with _conn, _conn.cursor() as cur:
        yield cur


def _read_report_content(report_path):
    """Contenu texte si fichier régulier et < MAX_REPORT_BYTES, sinon None."""
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
    """Résout report_path en chemin réel sous /reports. None si absent ou hors de /reports."""
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
    """Crée la base <name> si elle n'existe pas (connexion autocommit dédiée)."""
    conn = psycopg2.connect()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (name,))
            if cur.fetchone() is None:
                cur.execute(f'CREATE DATABASE "{name}"')
    finally:
        conn.close()
