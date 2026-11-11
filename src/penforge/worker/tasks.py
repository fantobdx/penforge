import os

from celery.signals import worker_ready

from penforge import config
from penforge.worker.app import app
from penforge.pentest.proxy import is_local_target, set_proxy_conf
from penforge.pentest.tor import write_proxychains_conf, start_tor_pool
from penforge.pentest.runner import execute_step, log_error
from penforge.pentest.steps import STEP_LABEL
from penforge.db import scans as _db_scans
from penforge.db import steps as _db_steps
from penforge.db import tor as _db_tor
from penforge.ioc.extract import write_report as _ioc_write_report
import penforge.pentest.proxy as _proxy

_redis_client = None
_TOR_READY_KEY = "penforge:tor_ready"


def _get_redis():
    global _redis_client
    if _redis_client is None:
        import redis
        _redis_client = redis.from_url(config.CELERY_BROKER_URL, decode_responses=True)
    return _redis_client

try:
    from penforge.osint import OSINT_ROOT as _OSINT_ROOT
    from penforge.osint.username import run_username as _run_username
    from penforge.osint.phone import run_phone as _run_phone
    from penforge.osint.email_lookup import run_email as _run_email
    from penforge.osint.image import run_image as _run_image
    from penforge.osint.domain import run_domain as _run_domain
    _osint_available = True
except ImportError:
    _osint_available = False


@worker_ready.connect
def _on_worker_ready(**_kwargs):
    try:
        _get_redis().delete(_TOR_READY_KEY)
    except Exception:
        pass
    try:
        _db_steps.recover_crashed_steps()
    except Exception as exc:
        log_error(f"recover_crashed_steps a échoué (schéma DB manquant ?) : {exc}")
    available = start_tor_pool()
    if not available:
        log_error("Instances Tor non disponibles. Scans pentest désactivés. OSINT opérationnel.")
    try:
        _get_redis().set(_TOR_READY_KEY, "1" if available else "0", ex=86400)
    except Exception:
        pass


@app.task(bind=True, soft_time_limit=config.STEP_TIMEOUT,
          time_limit=config.STEP_TIMEOUT + config.STEP_KILL_GRACE)
def run_step_task(self, scan_id, domain, step_id):
    local = is_local_target(domain)
    _proxy.USE_TOR = not local

    if not local:
        try:
            tor_status = _get_redis().get(_TOR_READY_KEY)
        except Exception:
            tor_status = "1"
        if tor_status is None:
            # Bootstrap Tor en cours dans le MainProcess — réessayer dans 15s
            raise self.retry(countdown=15, max_retries=config.STEP_TIMEOUT // 30)
        if tor_status == "0":
            row_id = _db_steps.mark_step_running(scan_id, step_id, STEP_LABEL[step_id], self.request.id)
            if row_id is not None:
                _db_steps.finish_step(row_id, "FAIL", "", note="Tor non disponible au démarrage du worker.")
            return "TOR_UNAVAILABLE"

    port = None
    try:
        if not local:
            port = _db_tor.acquire_tor_port(self.request.id)
            if port is None:
                raise self.retry(countdown=30, max_retries=config.STEP_TIMEOUT // 30)
            _proxy.set_current_tor_port(port)

        scan_dir = os.path.join(config.SCANS_ROOT, str(scan_id))
        os.makedirs(scan_dir, exist_ok=True)
        conf_path = None
        if not local:
            conf_path = os.path.join(scan_dir, f".tor-{self.request.id}.conf")
            write_proxychains_conf(conf_path)
            set_proxy_conf(conf_path)

        step_row_id = _db_steps.mark_step_running(scan_id, step_id, STEP_LABEL[step_id], self.request.id)
        try:
            if step_row_id is None:
                return "STOPPED"
            old_cwd = os.getcwd()
            try:
                os.chdir(scan_dir)
                return execute_step(scan_id, domain, step_id, step_row_id)
            finally:
                os.chdir(old_cwd)
        finally:
            if conf_path and os.path.exists(conf_path):
                os.remove(conf_path)
    finally:
        _proxy.set_current_tor_port(None)
        if port is not None:
            _db_tor.release_tor_port(port)


@app.task
def finalize_scan(scan_id):
    _ioc_write_report(os.path.join(config.SCANS_ROOT, str(scan_id)))
    ok, fail, skip = _db_scans.tally_latest_statuses(scan_id)
    _db_scans.finish_scan(scan_id, ok, fail, skip)
    _db_scans.finish_job_for_scan(scan_id, "done")


@app.task
def recompute_counts(scan_id):
    _db_scans.refresh_finished_counts(scan_id)


@app.task
def fail_scan(request, exc, traceback, scan_id):  # noqa: ARG001
    _db_scans.fail_job_for_scan(scan_id)
    _db_steps.fail_dangling_running_step(scan_id, str(exc))


@app.task(bind=True, soft_time_limit=240, time_limit=270, name="osint_scan")
def run_osint(self, target_type, target, uuid):  # noqa: ARG001
    if not _osint_available:
        raise RuntimeError("Module osint non disponible dans ce worker.")
    outdir = os.path.join(_OSINT_ROOT, uuid)
    os.makedirs(outdir, exist_ok=True)
    fn = {
        "username": _run_username,
        "phone": _run_phone,
        "email": _run_email,
        "image": _run_image,
        "domain": _run_domain,
    }[target_type]
    output = fn(target, outdir)
    return {"output": output}
