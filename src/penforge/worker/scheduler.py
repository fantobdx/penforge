from celery import chain, chord, group

from penforge.pentest.steps import STEPS, STEP_LABEL
from penforge.db import scans as _db_scans
from penforge.worker.tasks import run_step_task, finalize_scan, recompute_counts, fail_scan

# Phase 1 : reconnaissance passive/réseau, doit se terminer avant les outils web
PHASE1_STEPS = frozenset({"subfinder", "nmap", "whois", "theharvester"})

STEP_DEPENDENCIES = {
    "whatweb": ("sploitctl_lookup", "metasploit"),
    "katana": ("wfuzz", "trufflehog_web", "sqlmap"),
    "wpscan": ("wp_bruteforce",),
    "wp_bruteforce": ("credential_spray",),
    "httpx": ("dirsearch", "nikto", "nuclei", "dirb"),
}


def _celery_priority(db_priority):
    """Convertit la priorité DB (1=urgent → 9=bg) en priorité Celery Redis (9=max → 1=min)."""
    return 10 - max(1, min(9, db_priority))


def _build_branch(start, remaining, handled, sig):
    chain_sigs = [sig(start)]
    handled.add(start)
    current_children = [c for c in STEP_DEPENDENCIES.get(start, ()) if c in remaining and c not in handled]
    while len(current_children) == 1:
        child = current_children[0]
        chain_sigs.append(sig(child))
        handled.add(child)
        current_children = [c for c in STEP_DEPENDENCIES.get(child, ()) if c in remaining and c not in handled]
    if current_children:
        handled.update(current_children)
        return chain(*chain_sigs, group(*(sig(c) for c in current_children)))
    return chain_sigs[0] if len(chain_sigs) == 1 else chain(*chain_sigs)


def _build_web_branches(step_ids, sig):
    """Branches parallèles pour une liste de steps, en respectant STEP_DEPENDENCIES."""
    remaining = set(step_ids)
    branches, handled = [], set()
    dep_children = {c for children in STEP_DEPENDENCIES.values() for c in children}
    for parent in STEP_DEPENDENCIES:
        if parent in handled or parent not in remaining:
            continue
        if parent in dep_children:
            if any(parent in STEP_DEPENDENCIES.get(p, ()) and p in remaining for p in STEP_DEPENDENCIES):
                continue
        branches.append(_build_branch(parent, remaining, handled, sig))
    branches += [sig(s) for s in remaining if s not in handled]
    return branches


def _schedule_for(scan_id, domain, step_ids, tail, priority=5):
    cp = _celery_priority(priority)
    sig = lambda step_id: run_step_task.si(scan_id, domain, step_id).set(priority=cp)  # noqa: E731
    p1 = [s for s in step_ids if s in PHASE1_STEPS]
    p2 = [s for s in step_ids if s not in PHASE1_STEPS]

    if p2:
        p2_body = chord(
            group(*_build_web_branches(p2, sig)),
            tail.si(scan_id),
        ).on_error(fail_scan.s(scan_id))
    else:
        p2_body = tail.si(scan_id)

    if p1:
        return chord(
            group(*(sig(s) for s in p1)),
            p2_body,
        ).on_error(fail_scan.s(scan_id))

    return p2_body


def _steps_for(domain, with_msf=True):
    steps = list(STEPS)
    if with_msf:
        steps.append("metasploit")
    return steps


def start_scan(domain, with_msf=True, excluded_steps=None, priority=5):
    all_steps = _steps_for(domain, with_msf)
    excluded = set(excluded_steps or []) & set(all_steps)
    scan_id = _db_scans.start_scan(domain, excluded=[(s, STEP_LABEL[s]) for s in excluded], priority=priority)
    _db_scans.create_job(domain, scan_id)
    remaining = [step_id for step_id in all_steps if step_id not in excluded]
    _schedule_for(scan_id, domain, remaining, finalize_scan, priority=priority).apply_async()
    return scan_id


def resume_scan(scan_id):
    result = _db_scans.resume_scan(scan_id)
    if result is None:
        return False
    domain, done = result
    priority = _db_scans.get_scan_priority(scan_id)
    missing = [step_id for step_id in _steps_for(domain) if step_id not in done]
    _schedule_for(scan_id, domain, missing, finalize_scan, priority=priority).apply_async()
    return True


def rerun_step(scan_id, step_id):
    domain = _db_scans.begin_rerun(scan_id)
    if domain is None:
        return False
    priority = _db_scans.get_scan_priority(scan_id)
    cp = _celery_priority(priority)
    chain(
        run_step_task.si(scan_id, domain, step_id).set(priority=cp),
        recompute_counts.si(scan_id),
    ).apply_async()
    return True
