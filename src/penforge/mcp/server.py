#!/usr/bin/env python3
"""Serveur MCP exposant les scans pentest, leurs rapports, et des actions de contrôle.

Ressources et outils de lecture :
  scan://list                                     - liste des scans
  scan://{scan_id}                                 - détail d'un scan + ses étapes
  scan://{scan_id}/{step_id}                       - rapport d'une étape
  scan://{scan_id}/{step_id}/file/{encoded_path}   - fichier précis d'un rapport-dossier

Outils de contrôle :
  excludable_steps  - step_id/label valides pour start_scan(excluded_steps=...)
  start_scan        - démarre un nouveau scan
  skip_step         - saute une étape RUNNING sans arrêter le scan
  set_scan_priority - change la priorité d'un scan existant
"""

import base64
import json
import os

from mcp.server.fastmcp import FastMCP

from penforge.db.connection import MAX_REPORT_BYTES, _cursor, resolve_report_path
from penforge.db.scans import PRIORITY_CHOICES, set_scan_priority as _set_scan_priority
from penforge.db.steps import request_skip as _request_skip
from penforge.pentest.steps import excludable_steps as _get_excludable_steps
from penforge.config import DOMAIN_RE
from penforge.worker.scheduler import start_scan as _scheduler_start_scan

MAX_FILE_BYTES = MAX_REPORT_BYTES  # 2 Mo, même limite que pour le contenu stocké en base

mcp = FastMCP(
    "pentest-reports",
    instructions=(
        "Scans pentest et leurs rapports (lecture), plus des actions de contrôle : "
        "start_scan (démarrer un scan, avec exclusion d'outils optionnelle) et skip_step "
        "(sauter une étape RUNNING d'un scan, par step_id, sans l'arrêter -- plusieurs étapes "
        "indépendantes pouvant tourner en parallèle pour un même scan). Toute autre action de "
        "contrôle (arrêt, reprise, relance d'un outil déjà terminé) reste réservée à l'interface web. "
        "scan_findings retourne les findings automatiques extraits des rapports (wpscan, nuclei, "
        "sqlmap…) classés par sévérité : critical > high > medium > low > info."
    ),
    host=os.environ.get("PENTEST_MCP_HOST", "0.0.0.0"),
    port=int(os.environ.get("PENTEST_MCP_PORT", "8766")),
    streamable_http_path="/mcp",
)


def _rows_as_dicts(cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _encode_path(rel_path):
    return base64.urlsafe_b64encode(rel_path.encode()).decode()


def _decode_path(token):
    try:
        return base64.urlsafe_b64decode(token.encode()).decode()
    except Exception:  # noqa: BLE001 - jeton malformé, traité comme invalide
        return None


def _read_bounded(path):
    """Contenu texte de path, borné à MAX_FILE_BYTES."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return json.dumps({
                "error": f"fichier trop volumineux (> {MAX_FILE_BYTES} octets) : "
                         "le télécharger depuis l'interface web plutôt."
            })
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        return json.dumps({"error": str(exc)})


def _latest_step(scan_id, step_id):
    """Dernier enregistrement (report_path, report_content) de step_id pour ce scan, ou None."""
    with _cursor() as cur:
        cur.execute(
            "SELECT report_path, report_content FROM scan_steps "
            "WHERE scan_id = %s AND step_id = %s ORDER BY id DESC LIMIT 1",
            (scan_id, step_id),
        )
        return cur.fetchone()


@mcp.resource("scan://list")
@mcp.tool()
def list_scans() -> str:
    """Liste des scans, du plus récent au plus ancien."""
    with _cursor() as cur:
        cur.execute(
            """
            SELECT id, domain, started_at, finished_at, ok_count, fail_count, skip_count, current_step
            FROM scans ORDER BY started_at DESC
            """
        )
        rows = _rows_as_dicts(cur)
    return json.dumps(rows, default=str, ensure_ascii=False)


@mcp.resource("scan://{scan_id}")
@mcp.tool()
def scan_detail(scan_id: str) -> str:
    """Détail d'un scan et de ses étapes (sans le contenu des rapports)."""
    with _cursor() as cur:
        cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
        scans = _rows_as_dicts(cur)
        if not scans:
            return json.dumps({"error": f"scan {scan_id} introuvable"})
        scan = scans[0]
        cur.execute(
            "SELECT id, step_id, label, status, report_path, note, recorded_at "
            "FROM scan_steps WHERE scan_id = %s ORDER BY recorded_at",
            (scan_id,),
        )
        steps = _rows_as_dicts(cur)
    for step in steps:
        step["has_report"] = resolve_report_path(step["report_path"]) is not None
    return json.dumps({"scan": scan, "steps": steps}, default=str, ensure_ascii=False)


@mcp.resource("scan://{scan_id}/{step_id}")
@mcp.tool()
def step_report(scan_id: str, step_id: str) -> str:
    """Rapport d'une étape : contenu texte s'il est en base ou sur disque, listing si dossier."""
    row = _latest_step(scan_id, step_id)
    if row is None:
        return json.dumps({"error": f"étape {step_id!r} introuvable pour le scan {scan_id}"})
    report_path, report_content = row
    if report_content:
        return report_content
    real = resolve_report_path(report_path)
    if real is None:
        return json.dumps({"error": "aucun rapport disponible pour cette étape"})
    if os.path.isdir(real):
        entries = sorted(os.listdir(real))
        return json.dumps({
            "directory": True,
            "entries": entries,
            "file_resource": f"scan://{scan_id}/{step_id}/file/<encoded_path>",
            "encoded_entries": {name: _encode_path(name) for name in entries},
        }, ensure_ascii=False)
    return _read_bounded(real)


@mcp.resource("scan://{scan_id}/{step_id}/file/{encoded_path}")
@mcp.tool()
def step_report_file(scan_id: str, step_id: str, encoded_path: str) -> str:
    """Fichier précis d'un rapport-dossier. encoded_path est le chemin relatif encodé en base64 urlsafe."""
    rel = _decode_path(encoded_path)
    if rel is None:
        return json.dumps({"error": "encoded_path invalide"})
    row = _latest_step(scan_id, step_id)
    if row is None:
        return json.dumps({"error": f"étape {step_id!r} introuvable pour le scan {scan_id}"})
    base = resolve_report_path(row[0])
    if base is None or not os.path.isdir(base):
        return json.dumps({"error": "rapport-dossier introuvable"})
    target = os.path.realpath(os.path.join(base, rel))
    if os.path.commonpath([target, base]) != base:
        return json.dumps({"error": "chemin hors du rapport"})
    if os.path.isdir(target):
        entries = sorted(os.listdir(target))
        return json.dumps({
            "directory": True,
            "entries": entries,
            "encoded_entries": {name: _encode_path(os.path.join(rel, name)) for name in entries},
        }, ensure_ascii=False)
    if not os.path.isfile(target):
        return json.dumps({"error": "fichier introuvable"})
    return _read_bounded(target)


@mcp.resource("scan://{scan_id}/findings")
@mcp.tool()
def scan_findings(scan_id: str) -> str:
    """Findings automatiques extraits des rapports après chaque étape OK.
    Classés par sévérité décroissante : critical → high → medium → low → info."""
    with _cursor() as cur:
        cur.execute(
            """
            SELECT step_id, severity, title, detail, recommendation, created_at
            FROM findings WHERE scan_id = %s
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4 ELSE 5
                END, id
            """,
            (scan_id,),
        )
        rows = _rows_as_dicts(cur)
    return json.dumps(rows, default=str, ensure_ascii=False)


@mcp.tool()
def excludable_steps() -> str:
    """Liste (step_id, label) des outils qu'un scan peut exclure."""
    return json.dumps(
        [{"step_id": step_id, "label": label} for step_id, label in _get_excludable_steps()],
        ensure_ascii=False,
    )


_VALID_PRIORITIES = {1, 3, 5, 7, 9}
_PRIORITY_LABELS = PRIORITY_CHOICES


@mcp.tool()
def start_scan(domain: str, with_msf: bool = True, excluded_steps: list[str] | None = None,
               priority: int = 5) -> str:
    """Démarre un nouveau scan sur domain.
    priority : 1=Urgente, 3=Haute, 5=Normale (défaut), 7=Basse, 9=Arrière-plan."""
    if not DOMAIN_RE.match(domain):
        return json.dumps({"error": f"domaine invalide : {domain!r}"})
    if priority not in _VALID_PRIORITIES:
        priority = 5
    scan_id = _scheduler_start_scan(domain, with_msf=with_msf, excluded_steps=excluded_steps, priority=priority)
    return json.dumps({"scan_id": scan_id})


@mcp.tool()
def set_scan_priority(scan_id: str, priority: int) -> str:
    """Change la priorité d'un scan existant.
    priority : 1=Urgente, 3=Haute, 5=Normale, 7=Basse, 9=Arrière-plan."""
    if priority not in _VALID_PRIORITIES:
        return json.dumps({"error": f"priorité invalide : {priority!r} — valeurs autorisées : 1, 3, 5, 7, 9"})
    if not _set_scan_priority(scan_id, priority):
        return json.dumps({"error": f"scan {scan_id} introuvable"})
    return json.dumps({"ok": True, "priority": priority, "label": _PRIORITY_LABELS[priority]})


@mcp.tool()
def skip_step(scan_id: str, step_id: str) -> str:
    """Saute step_id s'il est RUNNING pour scan_id, sans arrêter le reste du scan."""
    return json.dumps({"skipped": _request_skip(scan_id, step_id)})


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
