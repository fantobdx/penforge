"""Tâches Celery : exécution des étapes de pentest.py et orchestration d'un scan.

Un scan = un chord() Celery : un group() d'une tâche run_step_task par étape restante, soumises
ensemble au broker (donc parallèles, bornées par `celery worker --concurrency`), puis
finalize_scan en callback une fois toutes terminées. Seules deux dépendances réelles entre
étapes existent (STEP_DEPENDENCIES ci-dessous : whatweb produit le rapport que lisent
sploitctl_lookup/metasploit, katana produit crawl-urls.txt que lisent wfuzz/trufflehog_web/
sqlmap) ; _schedule_for les respecte via une sous-chain(parent, group(enfants)) à l'intérieur du
group principal, tout le reste tournant sans contrainte d'ordre. La concurrence entre *et au
sein des* scans est bornée par `celery worker --concurrency`, qui remplace la notion de "slot"
de l'ancien worker. Elle doit rester égale au nombre de lignes de tor_instances (peuplée par
pentest.start_tor_pool via db_insert.register_tor_ports) : une étape active = un port Tor loué
pour sa durée (sauf cible locale, voir pentest.is_local_target -- Tor contourné, pas de port
loué, donc pas de limite via le pool pour ces cibles-là).

Arrêter un scan ne passe jamais par app.control.revoke(terminate=True) : la doc Celery dit
explicitement de ne jamais l'appeler programmatiquement (il cible un PID de process worker, pas
une tâche — avec le pool prefork, ce PID peut déjà exécuter une autre tâche au moment où le
signal arrive). L'arrêt est coopératif, via Postgres (voir db_insert.stop_requested/stop_scan et
pentest.run()).
"""

import os

from celery import Celery, chain, chord, group
from celery.signals import worker_ready

import db_insert
import ioc_extract
import pentest

app = Celery(
    "pentest",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/1"),
)
app.conf.update(
    worker_prefetch_multiplier=1,  # tâches longues et hétérogènes : pas de bachotage.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)


@worker_ready.connect
def _on_worker_ready(**_kwargs):
    """Au démarrage du worker : nettoie l'état laissé par un crash précédent (étapes restées
    RUNNING), puis démarre le pool Tor et l'enregistre dans tor_instances."""
    db_insert.recover_crashed_steps()
    if not pentest.start_tor_pool():
        pentest.log_error("Impossible de démarrer les instances Tor : worker arrêté.")
        raise SystemExit(1)


@app.task(bind=True, soft_time_limit=pentest.STEP_TIMEOUT,
          time_limit=pentest.STEP_TIMEOUT + pentest.STEP_KILL_GRACE)
def run_step_task(self, scan_id, domain, step_id):
    # Cible locale (lab) : ni port Tor ni proxychains, car Tor ne résout ni ne route le réseau
    # Docker interne du lab. USE_TOR est réglé à chaque tâche (process worker réutilisé par le
    # pool prefork) pour que run() route correctement selon la cible courante.
    local = pentest.is_local_target(domain)
    pentest.USE_TOR = not local

    port = None
    if not local:
        port = db_insert.acquire_tor_port(self.request.id)
        if port is None:
            # Tous les ports Tor sont occupés : self.retry() relève la tâche entière plus tard
            # (re-passera ici), tant qu'aucun port ne se libère entre-temps.
            raise self.retry(countdown=2, max_retries=pentest.STEP_TIMEOUT // 2)

    scan_dir = os.path.join(pentest.SCANS_ROOT, str(scan_id))
    os.makedirs(scan_dir, exist_ok=True)
    conf_path = None
    if not local:
        conf_path = os.path.join(scan_dir, f".tor-{self.request.id}.conf")
        pentest.write_proxychains_conf(conf_path)
        pentest.set_proxy_conf(conf_path)

    step_row_id = db_insert.mark_step_running(scan_id, step_id, pentest.STEP_LABEL[step_id], self.request.id)
    try:
        if step_row_id is None:
            return "STOPPED"  # arrêt demandé entre deux étapes de la chaîne : rien à faire.
        old_cwd = os.getcwd()
        try:
            os.chdir(scan_dir)
            return pentest.execute_step(scan_id, domain, step_id, step_row_id)
        finally:
            os.chdir(old_cwd)
    finally:
        if conf_path and os.path.exists(conf_path):
            os.remove(conf_path)
        if port is not None:
            db_insert.release_tor_port(port)


@app.task
def finalize_scan(scan_id):
    ioc_extract.write_report(os.path.join(pentest.SCANS_ROOT, str(scan_id)))
    ok, fail, skip = db_insert.tally_latest_statuses(scan_id)
    db_insert.finish_scan(scan_id, ok, fail, skip)
    db_insert.finish_job_for_scan(scan_id, "done")


@app.task
def recompute_counts(scan_id):
    db_insert.refresh_finished_counts(scan_id)


@app.task
def fail_scan(request, exc, traceback, scan_id):  # noqa: ARG001 - signature imposée par on_error
    db_insert.fail_job_for_scan(scan_id)
    db_insert.fail_dangling_running_step(scan_id, str(exc))


# Dépendances réelles entre étapes (fichier produit par le parent, lu par les enfants -- voir
# pentest.whatweb_terms et step_wfuzz/step_trufflehog_web/step_sqlmap) : tout le reste de
# pentest.STEPS est indépendant et peut tourner en parallèle sans égard à l'ordre.
STEP_DEPENDENCIES = {
    "whatweb": ("sploitctl_lookup", "metasploit"),
    "katana": ("wfuzz", "trufflehog_web", "sqlmap"),
    # wpscan produit wpscan-report.txt lu par wp_bruteforce (users) ;
    # wp_bruteforce doit terminer avant credential_spray (findings en DB).
    "wpscan": ("wp_bruteforce",),
    "wp_bruteforce": ("credential_spray",),
}


def _schedule_for(scan_id, domain, step_ids, tail):
    """Signature Celery pour step_ids (restants à exécuter) : un group() parallèle, sauf les
    couples de STEP_DEPENDENCIES, gardés en chain(parent, group(enfants présents)) à l'intérieur
    du group principal -- si le parent n'est pas dans step_ids (déjà OK, cas d'un resume après
    coup), ses enfants déjà débloqués rejoignent le group principal comme n'importe quelle autre
    étape indépendante. tail (finalize_scan ou recompute_counts) ne se lance qu'une fois tout le
    group terminé (chord), quel que soit le statut individuel de chaque étape (un échec d'outil
    est un retour normal de run_step_task, pas une exception -- voir pentest.execute_step)."""
    remaining = list(step_ids)
    sig = lambda step_id: run_step_task.si(scan_id, domain, step_id)  # noqa: E731
    branches, handled = [], set()
    for parent, children in STEP_DEPENDENCIES.items():
        present_children = [c for c in children if c in remaining]
        if parent in remaining and present_children:
            branches.append(chain(sig(parent), group(*(sig(c) for c in present_children))))
            handled.update([parent, *present_children])
        elif parent in remaining:
            branches.append(sig(parent))
            handled.add(parent)
        else:
            # parent déjà fait (resume) : ses enfants déjà débloqués tournent comme n'importe
            # quelle autre étape indépendante, ci-dessous.
            pass
    branches += [sig(step_id) for step_id in remaining if step_id not in handled]
    return chord(group(*branches), tail.si(scan_id)).on_error(fail_scan.s(scan_id))


def _steps_for(domain, with_msf=True):
    """Liste des étapes d'un scan : pentest.STEPS, plus metasploit-auto en dernier (sauf si
    with_msf est False). metasploit n'est jamais dans pentest.STEPS car l'étape se connecte en
    direct (hors Tor, run(proxy=False)) ; on l'ajoute ici pour toute cible, locale ou non."""
    steps = list(pentest.STEPS)
    if with_msf:
        steps.append("metasploit")
    return steps


def start_scan(domain, with_msf=True, excluded_steps=None):
    """Démarre un nouveau scan complet (pentest.STEPS, plus metasploit-auto en fin sauf si
    with_msf est False). excluded_steps : step_id à ne jamais exécuter pour ce scan — enregistrés
    SKIP tout de suite (db_insert.start_scan) et jamais mis dans la chaîne Celery, à distinguer
    du skip en cours d'exécution (db_insert.request_skip/pentest.StepSkipped)."""
    all_steps = _steps_for(domain, with_msf)
    excluded = set(excluded_steps or []) & set(all_steps)
    scan_id = db_insert.start_scan(domain, excluded=[(s, pentest.STEP_LABEL[s]) for s in excluded])
    db_insert.create_job(domain, scan_id)
    remaining = [step_id for step_id in all_steps if step_id not in excluded]
    _schedule_for(scan_id, domain, remaining, finalize_scan).apply_async()
    return scan_id


def resume_scan(scan_id):
    """Relance uniquement les step_id pas encore OK/FAIL/SKIP (y compris une éventuelle étape
    STOPPED, qui n'est pas "déjà passée"). False si le scan n'est pas reprenable."""
    result = db_insert.resume_scan(scan_id)
    if result is None:
        return False
    domain, done = result
    missing = [step_id for step_id in _steps_for(domain) if step_id not in done]
    _schedule_for(scan_id, domain, missing, finalize_scan).apply_async()
    return True


def rerun_step(scan_id, step_id):
    """Relance un seul step_id (scan terminé ou arrêté). False si une étape de ce scan est
    déjà active."""
    domain = db_insert.begin_rerun(scan_id)
    if domain is None:
        return False
    chain(run_step_task.si(scan_id, domain, step_id), recompute_counts.si(scan_id)).apply_async()
    return True
