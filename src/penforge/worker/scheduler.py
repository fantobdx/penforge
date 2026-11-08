from celery import chain, chord, group

from penforge.pentest.steps import STEPS, STEP_LABEL
from penforge.db import scans as _db_scans
from penforge.worker.tasks import run_step_task, finalize_scan, recompute_counts, fail_scan

STEP_DEPENDENCIES = {
    "whatweb": ("sploitctl_lookup", "metasploit"),
    "katana": ("wfuzz", "trufflehog_web", "sqlmap"),
    "wpscan": ("wp_bruteforce",),
    "wp_bruteforce": ("credential_spray",),
}


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


def _schedule_for(scan_id, domain, step_ids, tail):
    remaining = set(step_ids)
    sig = lambda step_id: run_step_task.si(scan_id, domain, step_id)  # noqa: E731
    branches, handled = [], set()
    dep_children = {c for children in STEP_DEPENDENCIES.values() for c in children}
    for parent in STEP_DEPENDENCIES:
        if parent in handled or parent not in remaining:
            continue
        if parent in dep_children:
            if any(parent in STEP_DEPENDENCIES.get(p, ()) and p in remaining for p in STEP_DEPENDENCIES):
                continue
        branches.append(_build_branch(parent, remaining, handled, sig))
    branches += [sig(step_id) for step_id in remaining if step_id not in handled]
    return chord(group(*branches), tail.si(scan_id)).on_error(fail_scan.s(scan_id))


def _steps_for(domain, with_msf=True):
    steps = list(STEPS)
    if with_msf:
        steps.append("metasploit")
    return steps


def start_scan(domain, with_msf=True, excluded_steps=None):
    all_steps = _steps_for(domain, with_msf)
    excluded = set(excluded_steps or []) & set(all_steps)
    scan_id = _db_scans.start_scan(domain, excluded=[(s, STEP_LABEL[s]) for s in excluded])
    _db_scans.create_job(domain, scan_id)
    remaining = [step_id for step_id in all_steps if step_id not in excluded]
    _schedule_for(scan_id, domain, remaining, finalize_scan).apply_async()
    return scan_id


def resume_scan(scan_id):
    result = _db_scans.resume_scan(scan_id)
    if result is None:
        return False
    domain, done = result
    missing = [step_id for step_id in _steps_for(domain) if step_id not in done]
    _schedule_for(scan_id, domain, missing, finalize_scan).apply_async()
    return True


def rerun_step(scan_id, step_id):
    domain = _db_scans.begin_rerun(scan_id)
    if domain is None:
        return False
    chain(run_step_task.si(scan_id, domain, step_id), recompute_counts.si(scan_id)).apply_async()
    return True
