# penforge

Automated penetration testing framework based on BlackArch or Parrot OS Docker containers. Orchestrates 20+ security tools in a single scan, stores results in Postgres and exposes them via a web viewer.

### Number Of Modules
   - Whois domain analyzer
   - Nuclei
   - TheHarvester
   - Metagoofil
   - Dirb
   - Wafw00f
   - Nikto
   - XSSZypheron
   - XSStrike
   - WhatWeb
   - Wapiti
   - WPscan
   - Joomscan
   - Droopescan ( CMS Vulnerability Scanner WordPress, Joomla, Silverstripe, Drupal, And Moodle)
   - SSLScan
   - SSLyze
   - A2SV
   - WFuzz
   - Metasploit (mode `metasploit-auto` : db_nmap + matching ciblé par techno/version, pour un lab local)

### Features

   - Intel gathering & OSINT
   - Vulnerability analysis
   - Security auditing
   - System enumeration
   - Fuzzing
   - CMS auditing (WordPress, Joomla, Drupal, Silverstripe, Moodle)
   - SSL/TLS security auditing
   - WAF detection
   - Postgres storage + web viewer for scan history
   - Optional Metasploit auto-matching (lab use)
   - MCP servers for Claude Code integration

## How to run it

Create a docker volume to store your automated pentest reports

```

▶ docker volume create pentest-reports

```

### Build and run locally

```


▶ git clone https://github.com/fantobdx/penforge.git && cd penforge &&
  docker build -t=localhost/pentest . &&
  docker run -d --name pentest -d -v pentest-reports:/src -it localhost/pentest


```

### Build it on Arch Linux (BlackArch) instead of Parrot

An equivalent `Dockerfile.archlinux` is provided, based on `blackarchlinux/blackarch`
(Arch Linux with the BlackArch pentest-tools repository already enabled) instead of
`parrotsec/core`. Same tools, same `pentest.py`, just `pacman` instead of `apt`.

```

▶ git clone https://github.com/fantobdx/penforge.git && cd penforge &&
  docker build -t=localhost/pentest -f Dockerfile.archlinux . &&
  docker run -d --name pentest -d -v pentest-reports:/src -it localhost/pentest

```

### Store results in Postgres and browse them from a web page

`docker-compose.yml` starts 3 services together: `db` (Postgres), `pentest` (this
container) and `web` (a small Flask app reading the same database).

```

▶ docker compose up --build

```

Then open `http://localhost:8080` and run a scan from the `pentest` container:

```

▶ docker compose exec pentest ./pentest.py -d example.com

```

Each tool's result (status, report content or a link to it) is written to Postgres as
soon as it finishes and shows up on the web page without needing to re-run anything.
This is entirely optional: running `pentest.py` without `PGHOST` set (e.g. with the plain
`docker run` commands above) works exactly as before, with no database involved.

The default Postgres password (`pentest`) is for local use only — override `PGPASSWORD`
(and `PGUSER`/`PGDATABASE`) via a `.env` file next to `docker-compose.yml` before using
this anywhere beyond your own machine.

### Mode `metasploit-auto` (matching ciblé, pour un lab local)

`db_nmap` remplit la base Metasploit (audit trail, pivot manuel possible ensuite), puis un script
msfconsole recherche des modules d'exploit correspondant aux couples techno/version déjà identifiés
par whatweb (ceux qu'utilise aussi `sploitctl_lookup`), **vérifie** chaque module candidat avec son
`check` (quand il en a un) et ne **lance** que ceux que ce check juge vulnérables/probables/détectés
— pas de tir aveugle sur tout port ouvert (voir les commentaires au-dessus de `step_metasploit` dans
`pentest.py` pour le détail : c'est l'approche `db_autopwn`, abandonnée, qu'il remplace). C'est un
mode synchrone dédié, **hors chaîne Celery et hors Tor** (le trafic va directement à la cible, pas
via proxychains) — prévu pour un lab local isolé et volontairement vulnérable, jamais pour une cible
distante.

Le conteneur `pentest` doit être sur le réseau du lab. Un override est fourni pour l'y rattacher
sans coupler la stack de base ; démarrer le lab d'abord :

```
▶ cd ../vuln-lab && docker compose up -d
▶ cd ../penforge && docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d
```

Deux façons de le déclencher :

1. **Automatique en fin de scan.** Un scan normal (`-d`/`-f`) ajoute metasploit-auto comme
   **dernière étape**, après les 24 outils web, pour **toute cible** (locale ou distante).
   Contrairement aux outils web, cette étape se connecte **toujours en direct, hors Tor** (le
   matching ciblé et les shells inverses ne passent pas par proxychains) : sur une cible distante,
   l'IP réelle du scanner est exposée, et les modules jugés vulnérables par leur `check` sont
   **réellement lancés**. Désactivable avec `--no-msf` :

   ```
   ▶ docker compose exec pentest ./pentest.py -d dvwa.lab.local
   ▶ docker compose exec pentest ./pentest.py -d dvwa.lab.local --no-msf   # sans metasploit
   ```

2. **Manuel, sur une cible/CIDR précise** (lister ET lancer, par défaut) :

   ```
   ▶ docker compose exec pentest ./pentest.py --metasploit-auto 172.20.0.0/24
   ```

Options du mode manuel : `--no-launch` (lister les candidats et leur verdict `check`, sans lancer),
`--min-rank great` (rang minimal des modules, défaut `great` ; valeurs possibles : `manual`, `low`,
`average`, `normal`, `good`, `great`, `excellent`), `--ports 1-1000` (ports db_nmap). Le résultat
est enregistré
dans `scan_steps` et visible sur `http://localhost:8080` comme n'importe quelle étape, avec le
rapport `metasploit-report.txt`.

Contournement de Tor pour le lab (étapes **web** uniquement) : le mode normal route les outils web
via Tor/proxychains, qui ne résout ni ne route le réseau Docker interne du lab. Pour une cible
locale (`*.lab.local`, IP/CIDR privé, `localhost`), la chaîne détecte la cible (`is_local_target`)
et contourne Tor automatiquement ; une cible distante reste routée via Tor pour ces outils. L'étape
metasploit-auto, elle, se connecte **toujours en direct** (hors Tor), indépendamment de la cible.

Metasploit s'appuie sur une base Postgres dédiée `msf` (créée automatiquement sur le service `db`,
séparée de la base applicative `pentest`).

Note de build : le paquet `metasploit` est volumineux (~2 Go, tire Ruby) ; `docker compose build
pentest` est donc nettement plus long qu'avant.

### MCP servers (Claude Code)

Both are bound to `127.0.0.1` only and have no application-level authentication.

| Service | Port | Purpose |
|---|---|---|
| `pentest-mcp` | 8766 | Read-only access to scans and their reports (`pentest_mcp.py`) |
| `blackarch-mcp` | 8765 | BlackArch tool inventory; every run is approval-gated (L0ced/blackarch-mcp) |

`blackarch-mcp` joins the lab network when started with `-f docker-compose.yml -f docker-compose.lab.yml`,
so approved runs can reach `*.lab.local` targets.

```
claude mcp add --transport http blackarch-mcp http://127.0.0.1:8765/mcp
```

### Execute the pentest script inside the container like below:

```yaml

▶ docker exec -it pentest bash

┌─[root@299c024d07ef]─[/src]
└──╼ #./pentest.py --help

usage: pentest.py [-h] -d DOMAIN

Automated pentest orchestrator.

options:
  -h, --help           show this help message and exit
  -d, --domain DOMAIN  Domaine cible à scanner.

┌─[root@299c024d07ef]─[/src]
└──╼ #./pentest.py -d example.com

```

## Accéder aux rapports

Les rapports sont générés dans `/src` à l'intérieur du container. Sur Linux, le volume est accessible directement :

```
▶ docker volume inspect pentest-reports
```

Le chemin réel est `/var/lib/docker/volumes/pentest-reports/_data`.


## Legal disclaimer:

Usage of this automated pentest for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
