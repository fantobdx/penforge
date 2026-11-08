import sys

import click

from penforge.pentest.runner import log_error, log_ok, log_info, banner, parse_domains


@click.group()
def cli():
    """PenForge — orchestrateur de pentest automatisé."""


@cli.command()
@click.option("-d", "--domain", default=None, help="Démarre un scan sur ce domaine.")
@click.option("-f", "--file", "file_path", default=None, type=click.Path(exists=True),
              help="Démarre un scan par domaine de ce fichier (un par ligne).")
@click.option("--no-msf", is_flag=True, help="Ne pas ajouter l'étape Metasploit en fin de scan.")
@click.option("--exclude", "excluded_steps", multiple=True, help="Étapes à exclure (répétable).")
def scan(domain, file_path, no_msf, excluded_steps):
    """Démarre un ou plusieurs scans via la file Celery."""
    if not domain and not file_path:
        raise click.UsageError("Fournir --domain ou --file.")
    if domain:
        text = domain
    else:
        with open(file_path, encoding="utf-8") as fh:
            text = fh.read()
    domains, invalid = parse_domains(text)
    if invalid:
        log_error(f"domaines invalides ignorés : {', '.join(invalid)}")
    if not domains:
        log_error("aucun domaine valide à ajouter.")
        sys.exit(1)
    from penforge.worker.scheduler import start_scan
    scan_ids = [start_scan(d, with_msf=not no_msf, excluded_steps=list(excluded_steps)) for d in domains]
    log_ok(f"{len(scan_ids)} scan(s) démarré(s) (scans {', '.join(map(str, scan_ids))}).")
    log_info("Exécutés par le worker Celery.")
    sys.exit(1 if invalid else 0)


@cli.command()
@click.argument("scan_id", type=int)
def resume(scan_id):
    """Reprend un scan interrompu."""
    from penforge.worker.scheduler import resume_scan
    if resume_scan(scan_id):
        log_ok(f"Scan {scan_id} repris.")
    else:
        log_error(f"Scan {scan_id} non repris (inexistant ou déjà actif).")
        sys.exit(1)


@cli.command("metasploit-auto")
@click.argument("target")
@click.option("--no-launch", is_flag=True, help="Lister les modules candidats sans les lancer.")
@click.option("--min-rank", default="great", help="Rang minimal des modules (défaut : great).")
@click.option("--ports", default=None, help="Ports db_nmap (ex. 1-1000).")
def metasploit_auto(target, no_launch, min_rank, ports):
    """Mode metasploit-auto : db_nmap + matching ciblé par techno/version."""
    import signal
    from penforge.pentest.steps.metasploit import run_metasploit_auto

    def _handler(sig, frame):
        sys.exit(0)
    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

    sys.exit(run_metasploit_auto(target, launch=not no_launch, min_rank=min_rank, ports=ports))
