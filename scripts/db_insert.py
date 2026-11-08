"""Shim de compatibilité : re-exporte depuis penforge.db.*"""
from penforge.db.connection import (  # noqa: F401
    MAX_REPORT_BYTES, REPORTS_ROOT, ensure_database, resolve_report_path,
)
from penforge.db.scans import (  # noqa: F401
    start_scan, finish_scan, append_logs, create_job, stop_scan, resume_scan,
    tally_latest_statuses, finish_job_for_scan, fail_job_for_scan,
    refresh_finished_counts, get_findings, insert_findings,
)
from penforge.db.steps import (  # noqa: F401
    mark_step_running, finish_step, stop_requested, request_skip, skip_requested,
    begin_rerun, fail_dangling_running_step, recover_crashed_steps,
)
from penforge.db.tor import register_tor_ports, acquire_tor_port, release_tor_port  # noqa: F401
