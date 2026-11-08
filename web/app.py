#!/usr/bin/env python3
"""Interface web pentest : historique des scans, file d'attente, lancement et logs en direct.

Connexion via psycopg2.connect() sans argument : lit nativement PGHOST/PGPORT/PGDATABASE/
PGUSER/PGPASSWORD, les mêmes variables que db_insert.py et pentest.py. Le volume
pentest-reports est monté en lecture seule sous /reports (comme dans le conteneur pentest) pour
servir les rapports, y compris ceux de type répertoire (wapiti, dirbuster).

Authentification HTTP Basic obligatoire : WEB_PASSWORD doit être défini, WEB_USER vaut admin
par défaut. Servie par gunicorn en HTTPS (voir web/Dockerfile).
"""

import collections
import hmac
import json
import logging
import os
import re
import socket as _socket
import threading
import time
import uuid as _uuid_mod
from urllib.parse import quote as _url_quote, unquote as _url_unquote

import markupsafe

try:
    import docker as docker_sdk
except ImportError:
    docker_sdk = None

import psycopg2
import psycopg2.extras
import redis
from flask import Flask, Response, abort, redirect, render_template, request, send_file, url_for

import db_insert
import pentest
import tasks

WEB_USER = os.environ.get("WEB_USER", "admin")
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
if not WEB_PASSWORD:
    raise RuntimeError("WEB_PASSWORD requis : l'interface n'est pas démarrée sans authentification.")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 Mo : batch d'images OSINT


@app.template_filter("linkify")
def linkify_filter(text):
    """Transforme les URLs http(s) en balises <a> cliquables dans un texte pré-formaté."""
    if not text:
        return markupsafe.Markup("")
    escaped = str(markupsafe.escape(text))
    result = re.sub(
        r'(https?://[^\s<>"\']+)',
        r'<a href="\1" target="_blank" rel="noopener noreferrer">\1</a>',
        escaped,
    )
    return markupsafe.Markup(result)


def get_conn():
    return psycopg2.connect()


# --- Mesures Redis / Celery pour la page /queues ----------------------------------------------
# Un thread relève la file toutes les 2 s : compteurs, contenu (nom et arguments de chaque
# tâche) et journal des changements d'état entre deux relevés. Tout est en mémoire du process,
# borné par des deque. gunicorn tourne avec --workers 1 (web/Dockerfile) : un seul échantillonneur.
SAMPLE_INTERVAL_S = 2
SAMPLE_WINDOW = 1800
EVENTS_WINDOW = 500
SNAPSHOT_LIMIT = 200
QUEUE_NAME = "celery"  # file par défaut de Celery (aucune route ni priorité dans tasks.py)
UNACKED_KEY = "unacked"  # hash Kombu : tag -> [message brut, exchange, routing_key] des tâches livrées non acquittées

redis_client = redis.Redis.from_url(tasks.app.conf.broker_url)
samples = collections.deque(maxlen=SAMPLE_WINDOW)
events = collections.deque(maxlen=EVENTS_WINDOW)
current_tasks = {"pending": [], "unacked": []}
samples_lock = threading.Lock()
log = logging.getLogger(__name__)


def task_info(raw):
    headers = raw.get("headers", {})
    return {"id": headers.get("id"), "task": headers.get("task"), "args": headers.get("argsrepr", "")}


def read_queue():
    """Retourne (en attente, non acquittées), chacun indexé par id de tâche."""
    pending = {}
    for item in redis_client.lrange(QUEUE_NAME, 0, -1):
        info = task_info(json.loads(item))
        pending[info["id"]] = info
    unacked = {}
    for value in redis_client.hvals(UNACKED_KEY):
        info = task_info(json.loads(value)[0])
        unacked[info["id"]] = info
    return pending, unacked


def take_server_metrics():
    memory = redis_client.info("memory")["used_memory"]
    clients = redis_client.info("clients")["connected_clients"]
    capacity, busy = 0, 0
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*), count(locked_by_task_id) FROM tor_instances")
            capacity, busy = cur.fetchone()
    except psycopg2.errors.UndefinedTable:
        pass
    return {
        "busy": busy,
        "capacity": capacity,
        "memory_mb": round(memory / 1024 / 1024, 2),
        "clients": clients,
    }


def diff_events(before_pending, before_unacked, pending, unacked, now):
    """Décrit les changements d'état de tâches entre deux relevés consécutifs."""
    found = []

    def add(label, info):
        found.append({"t": now, "event": label, "task": info["task"], "args": info["args"]})

    for tid, info in pending.items():
        if tid not in before_pending and tid not in before_unacked:
            add("en file", info)
    for tid, info in unacked.items():
        if tid not in before_unacked:
            add("prise par un worker", info)
    for tid, info in before_unacked.items():
        if tid not in unacked:
            add("remise en file" if tid in pending else "acquittée", info)
    for tid, info in before_pending.items():
        if tid not in pending and tid not in unacked:
            add("retirée de la file", info)
    return found


def sample_loop():
    before_pending, before_unacked = {}, {}
    while True:
        try:
            pending, unacked = read_queue()
            now = int(time.time() * 1000)
            sample = {"t": now, "pending": len(pending), "unacked": len(unacked), **take_server_metrics()}
            new_events = diff_events(before_pending, before_unacked, pending, unacked, now)
            with samples_lock:
                samples.append(sample)
                events.extend(new_events)
                current_tasks["pending"] = list(pending.values())[:SNAPSHOT_LIMIT]
                current_tasks["unacked"] = list(unacked.values())[:SNAPSHOT_LIMIT]
            before_pending, before_unacked = pending, unacked
        except Exception:
            log.exception("Échec de l'échantillonnage Redis/Postgres")
        time.sleep(SAMPLE_INTERVAL_S)


threading.Thread(target=sample_loop, daemon=True, name="queue-sampler").start()


# --- Métriques Docker / disque pour la page /system ------------------------------------------
DOCKER_INTERVAL_S = 5
DOCKER_SAMPLE_WINDOW = 720  # 1 h à 5 s/sample
docker_samples: collections.deque = collections.deque(maxlen=DOCKER_SAMPLE_WINDOW)
docker_lock = threading.Lock()


def _calc_cpu_percent(stats: dict) -> float:
    try:
        cpu_delta = (stats["cpu_stats"]["cpu_usage"]["total_usage"]
                     - stats["precpu_stats"]["cpu_usage"]["total_usage"])
        sys_delta = (stats["cpu_stats"]["system_cpu_usage"]
                     - stats["precpu_stats"].get("system_cpu_usage", 0))
        ncpu = (stats["cpu_stats"].get("online_cpus")
                or len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage", [None])))
        if sys_delta > 0 and cpu_delta >= 0:
            return round((cpu_delta / sys_delta) * ncpu * 100, 1)
    except (KeyError, TypeError, ZeroDivisionError):
        pass
    return 0.0


def _calc_mem_mb(stats: dict) -> float:
    try:
        usage = stats["memory_stats"]["usage"]
        st = stats["memory_stats"].get("stats", {})
        # cgroups v1 : cache ; cgroups v2 : total_inactive_file
        cache = st.get("cache", st.get("total_inactive_file", 0))
        return round(max(0, usage - cache) / 1024 / 1024, 1)
    except (KeyError, TypeError):
        return 0.0


def _disk_usage() -> dict:
    try:
        sv = os.statvfs("/reports")
        total = sv.f_blocks * sv.f_frsize
        free = sv.f_bavail * sv.f_frsize
        return {"used_gb": round((total - free) / 1024 ** 3, 2), "total_gb": round(total / 1024 ** 3, 2)}
    except OSError:
        return {"used_gb": 0, "total_gb": 0}


def _calc_blkio(stats: dict, container_id: str = "") -> tuple:
    r = w = 0
    for e in (stats.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []:
        op, v = e.get("op", ""), e.get("value", 0)
        if op == "Read":
            r += v
        elif op == "Write":
            w += v
    # Fallback cgroups v2 : blkio_stats est vide sur les kernels récents
    if r == 0 and w == 0 and container_id:
        try:
            path = f"/host/cgroup/system.slice/docker-{container_id}.scope/io.stat"
            with open(path) as f:
                for line in f:
                    parts = line.split()
                    if not parts:
                        continue
                    major = int(parts[0].split(":")[0])
                    if major in (252, 253):  # exclure device mapper (double-comptage)
                        continue
                    kv = dict(item.split("=") for item in parts[1:] if "=" in item)
                    r += int(kv.get("rbytes", 0))
                    w += int(kv.get("wbytes", 0))
        except OSError:
            pass
    return r, w


def _calc_net(stats: dict) -> tuple:
    rx = tx = 0
    for iface in ((stats.get("networks") or {}).values()):
        rx += iface.get("rx_bytes", 0)
        tx += iface.get("tx_bytes", 0)
    return rx, tx


_prev_cumul: dict = {}  # container_name -> {blkio_r, blkio_w, net_rx, net_tx, t}


def docker_sample_loop():
    client = None
    while True:
        try:
            if docker_sdk is None:
                time.sleep(DOCKER_INTERVAL_S)
                continue
            if client is None:
                client = docker_sdk.from_env()
            containers = {}
            t_now = time.time()
            for c in client.containers.list():
                try:
                    s = c.stats(stream=False)
                    name = c.name
                    prev = _prev_cumul.get(name, {})
                    blkio_r, blkio_w = _calc_blkio(s, c.id)
                    net_rx, net_tx = _calc_net(s)
                    dt = max(t_now - prev.get("t", t_now - DOCKER_INTERVAL_S), 1)
                    containers[name] = {
                        "cpu": _calc_cpu_percent(s),
                        "mem_mb": _calc_mem_mb(s),
                        "disk_r": round(max(0, blkio_r - prev.get("blkio_r", blkio_r)) / dt / 1024, 1),
                        "disk_w": round(max(0, blkio_w - prev.get("blkio_w", blkio_w)) / dt / 1024, 1),
                        "net_rx": round(max(0, net_rx - prev.get("net_rx", net_rx)) / dt / 1024, 1),
                        "net_tx": round(max(0, net_tx - prev.get("net_tx", net_tx)) / dt / 1024, 1),
                    }
                    _prev_cumul[name] = {"blkio_r": blkio_r, "blkio_w": blkio_w,
                                         "net_rx": net_rx, "net_tx": net_tx, "t": t_now}
                except Exception:
                    pass
            sample = {
                "t": int(t_now * 1000),
                "containers": containers,
                "disk_r": round(sum(v["disk_r"] for v in containers.values()), 1),
                "disk_w": round(sum(v["disk_w"] for v in containers.values()), 1),
                "net_rx": round(sum(v["net_rx"] for v in containers.values()), 1),
                "net_tx": round(sum(v["net_tx"] for v in containers.values()), 1),
                **_disk_usage(),
            }
            with docker_lock:
                docker_samples.append(sample)
        except Exception:
            log.exception("Échec de l'échantillonnage Docker")
            client = None
        time.sleep(DOCKER_INTERVAL_S)


threading.Thread(target=docker_sample_loop, daemon=True, name="docker-sampler").start()


# --- Connexions TCP par conteneur pour la page /system ---------------------------------------
_CONN_ORDER = {"ESTAB": 0, "SYN_SENT": 1, "CLOSE_WAIT": 2, "FIN_WAIT1": 3,
               "FIN_WAIT2": 4, "TIME_WAIT": 5, "LISTEN": 6}
_TCP_STATES_HEX = {
    "01": "ESTAB", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

# Script Python exécuté dans les conteneurs qui l'ont (pentest, web, wapiti…)
_PROBE_PY = (
    "import os,socket,json\n"
    "def h4(h):return socket.inet_ntop(socket.AF_INET,bytes.fromhex(h)[::-1])\n"
    "def h6(h):\n"
    " b=bytes.fromhex(h);b=b[0:4][::-1]+b[4:8][::-1]+b[8:12][::-1]+b[12:16][::-1]\n"
    " ip=socket.inet_ntop(socket.AF_INET6,b);return ip[7:]if ip.startswith('::ffff:')else ip\n"
    "ST={'01':'ESTAB','02':'SYN_SENT','03':'SYN_RECV','04':'FIN_WAIT1','05':'FIN_WAIT2',"
    "'06':'TIME_WAIT','07':'CLOSE','08':'CLOSE_WAIT','09':'LAST_ACK','0A':'LISTEN','0B':'CLOSING'}\n"
    "inodes={}\n"
    "for pid in os.listdir('/proc'):\n"
    " if not pid.isdigit():continue\n"
    " try:\n"
    "  comm=open(f'/proc/{pid}/comm').read().strip()\n"
    "  for fd in os.listdir(f'/proc/{pid}/fd'):\n"
    "   try:\n"
    "    l=os.readlink(f'/proc/{pid}/fd/{fd}')\n"
    "    if l.startswith('socket:['):inodes[l[8:-1]]=f'{comm}({pid})'\n"
    "   except:pass\n"
    " except:pass\n"
    "rows=[];seen=set()\n"
    "for path,v6 in[('/proc/net/tcp',False),('/proc/net/tcp6',True)]:\n"
    " try:\n"
    "  for line in open(path):\n"
    "   p=line.split()\n"
    "   if len(p)<10 or not p[0][0].isdigit():continue\n"
    "   lh,lp=p[1].split(':');rh,rp=p[2].split(':')\n"
    "   st=ST.get(p[3].upper(),p[3]);inode=p[9]\n"
    "   la=h6(lh)if v6 else h4(lh);ra=h6(rh)if v6 else h4(rh)\n"
    "   k=(st,f'{la}:{int(lp,16)}',f'{ra}:{int(rp,16)}')\n"
    "   if k not in seen:seen.add(k);rows.append({'s':st,'l':k[1],'r':k[2],'p':inodes.get(inode,'')})\n"
    " except:pass\n"
    "print(json.dumps(rows))\n"
)

# Fallback shell pour les conteneurs sans Python (postgres:alpine, redis:alpine…)
_INODE_SH = (
    "for p in /proc/[0-9]*; do "
    "  c=$(cat \"$p/comm\" 2>/dev/null)||continue; pid=\"${p##*/}\"; "
    "  for f in \"$p/fd/\"*; do [ -L \"$f\" ]||continue; "
    "    l=$(readlink \"$f\" 2>/dev/null)||continue; "
    "    case \"$l\" in socket:\\[*) i=\"${l#socket:[}\"; printf '%s\\t%s(%s)\\n' \"${i%]}\" \"$c\" \"$pid\";; esac; "
    "  done; "
    "done 2>/dev/null"
)


def _parse_proc_tcp(raw: str, inodes: dict) -> list:
    rows = []
    seen: set = set()
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 10 or not parts[0][0].isdigit():
            continue
        lh, lp = parts[1].split(":")
        rh, rp = parts[2].split(":")
        state = _TCP_STATES_HEX.get(parts[3].upper(), parts[3])
        inode = parts[9]
        try:
            if len(lh) == 8:
                la = _socket.inet_ntop(_socket.AF_INET, bytes.fromhex(lh)[::-1])
                ra = _socket.inet_ntop(_socket.AF_INET, bytes.fromhex(rh)[::-1])
            else:
                lb = bytes.fromhex(lh)
                lb = lb[0:4][::-1] + lb[4:8][::-1] + lb[8:12][::-1] + lb[12:16][::-1]
                la = _socket.inet_ntop(_socket.AF_INET6, lb)
                if la.startswith("::ffff:"): la = la[7:]
                rb = bytes.fromhex(rh)
                rb = rb[0:4][::-1] + rb[4:8][::-1] + rb[8:12][::-1] + rb[12:16][::-1]
                ra = _socket.inet_ntop(_socket.AF_INET6, rb)
                if ra.startswith("::ffff:"): ra = ra[7:]
            k = (state, f"{la}:{int(lp, 16)}", f"{ra}:{int(rp, 16)}")
            if k not in seen:
                seen.add(k)
                rows.append({"state": state, "local": k[1], "remote": k[2],
                             "proc": inodes.get(inode, "")})
        except Exception:
            pass
    return rows


def _collect_container(container) -> list:
    name = re.sub(r"^(penforge|lab)-", "", container.name)
    name = re.sub(r"-\d+$", "", name)
    # Essai Python
    try:
        r = container.exec_run(["python3", "-c", _PROBE_PY], demux=False, user="root")
        if r.exit_code == 0 and r.output:
            conns = json.loads(r.output.decode("utf-8", errors="replace").strip())
            return [{"container": name, "state": c["s"], "local": c["l"],
                     "remote": c["r"], "proc": c["p"]} for c in conns]
    except Exception:
        pass
    # Fallback shell
    try:
        raw_r = container.exec_run(
            ["sh", "-c", "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null"],
            demux=False, user="root")
        inode_r = container.exec_run(["sh", "-c", _INODE_SH], demux=False, user="root")
        inodes = {}
        if inode_r.output:
            for line in inode_r.output.decode("utf-8", errors="replace").splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    inodes[parts[0].strip()] = parts[1].strip()
        raw = raw_r.output.decode("utf-8", errors="replace") if raw_r.output else ""
        return [{"container": name, **r} for r in _parse_proc_tcp(raw, inodes)]
    except Exception:
        pass
    return []


_conn_containers: list = []
_conn_containers_lock = threading.Lock()


def conn_refresh_loop():
    while True:
        try:
            if docker_sdk is None:
                time.sleep(5)
                continue
            client = docker_sdk.from_env()
            all_conns = []
            for c in client.containers.list():
                all_conns.extend(_collect_container(c))
            all_conns.sort(key=lambda c: (c["container"], _CONN_ORDER.get(c["state"], 9), c["remote"]))
            with _conn_containers_lock:
                _conn_containers[:] = all_conns[:500]
        except Exception:
            log.exception("Échec refresh connexions conteneurs")
        time.sleep(5)


threading.Thread(target=conn_refresh_loop, daemon=True, name="conn-sampler").start()


# --- Processus par conteneur pour la page /system --------------------------------------------
_PROBE_PS_PY = (
    "import os,json\n"
    "def uid2name(uid):\n"
    " try:\n"
    "  for l in open('/etc/passwd'):\n"
    "   p=l.split(':');\n"
    "   if p[2]==uid:return p[0]\n"
    " except:pass\n"
    " return uid\n"
    "procs=[]\n"
    "for pid in os.listdir('/proc'):\n"
    " if not pid.isdigit():continue\n"
    " try:\n"
    "  comm=open(f'/proc/{pid}/comm').read().strip()\n"
    "  status={k.strip():v.strip() for line in open(f'/proc/{pid}/status') for k,v in [line.split(':',1)]}\n"
    "  raw_cmd=open(f'/proc/{pid}/cmdline').read().replace('\\x00',' ').strip()\n"
    "  cmd=(raw_cmd or comm)[:120]\n"
    "  ppid=int(status.get('PPid','0'))\n"
    "  uid=status.get('Uid','0 0 0 0').split()[1]\n"
    "  rss=int(status.get('VmRSS','0 kB').split()[0])\n"
    "  procs.append({'pid':int(pid),'ppid':ppid,'user':uid2name(uid),'rss':rss,'cmd':cmd})\n"
    " except:pass\n"
    "procs.sort(key=lambda p:p['pid'])\n"
    "print(json.dumps(procs))\n"
)

_PROBE_PS_SH = "ps -eo pid,ppid,user,rss,args --no-headers 2>/dev/null | head -200"

_proc_cache: list = []
_proc_lock = threading.Lock()


def _collect_procs(container) -> list:
    name = re.sub(r"^(penforge|lab)-", "", container.name)
    name = re.sub(r"-\d+$", "", name)
    try:
        r = container.exec_run(["python3", "-c", _PROBE_PS_PY], demux=False, user="root")
        if r.exit_code == 0 and r.output:
            procs = json.loads(r.output.decode("utf-8", errors="replace").strip())
            return [{"container": name, **p} for p in procs]
    except Exception:
        pass
    try:
        r = container.exec_run(["sh", "-c", _PROBE_PS_SH], demux=False, user="root")
        if r.exit_code == 0 and r.output:
            procs = []
            for line in r.output.decode("utf-8", errors="replace").splitlines():
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    procs.append({
                        "pid": int(parts[0]) if parts[0].isdigit() else 0,
                        "ppid": int(parts[1]) if parts[1].isdigit() else 0,
                        "user": parts[2],
                        "rss": int(parts[3]) if parts[3].isdigit() else 0,
                        "cmd": parts[4] if len(parts) > 4 else "",
                    })
            return [{"container": name, **p} for p in procs]
    except Exception:
        pass
    return []


def proc_refresh_loop():
    while True:
        try:
            if docker_sdk is None:
                time.sleep(10)
                continue
            client = docker_sdk.from_env()
            all_procs = []
            for c in client.containers.list():
                all_procs.extend(_collect_procs(c))
            with _proc_lock:
                _proc_cache[:] = all_procs
        except Exception:
            log.exception("Échec refresh processus conteneurs")
        time.sleep(10)


threading.Thread(target=proc_refresh_loop, daemon=True, name="proc-sampler").start()


@app.before_request
def require_auth():
    auth = request.authorization
    if (
        auth is None
        or not hmac.compare_digest((auth.username or "").encode(), WEB_USER.encode())
        or not hmac.compare_digest((auth.password or "").encode(), WEB_PASSWORD.encode())
    ):
        return Response("Authentification requise.", 401, {"WWW-Authenticate": 'Basic realm="pentest"'})
    # Basic auth est renvoyé par le navigateur même pour un POST venant d'un autre site :
    # on refuse les POST dont l'origine n'est pas cette interface (protection CSRF).
    origin = request.headers.get("Origin")
    if request.method == "POST" and origin is not None and origin != request.host_url.rstrip("/"):
        abort(403)


def parse_domains(text):
    """Retourne (domaines valides dédupliqués, lignes invalides). Ignore lignes vides et #."""
    valid, invalid = [], []
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        if DOMAIN_RE.match(line):
            valid.append(line)
        else:
            invalid.append(line)
    return list(dict.fromkeys(valid)), invalid


@app.route("/")
def index():
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT j.id, j.domain, j.status, j.scan_id, s.current_step
            FROM jobs j
            LEFT JOIN scans s ON s.id = j.scan_id
            WHERE j.status IN ('queued', 'running')
            ORDER BY j.id
            """
        )
        jobs = cur.fetchall()
        cur.execute(
            """
            SELECT id, domain, started_at, finished_at, ok_count, fail_count, skip_count
            FROM scans ORDER BY started_at DESC
            """
        )
        scans = cur.fetchall()
    return render_template("index.html", scans=scans, jobs=jobs)


@app.route("/system")
def system():
    return render_template("system.html")


@app.route("/system/connections")
def system_connections():
    with _conn_containers_lock:
        return {"connections": list(_conn_containers)}


@app.route("/system/processes")
def system_processes():
    with _proc_lock:
        return {"processes": list(_proc_cache)}


@app.route("/system/metrics")
def system_metrics():
    since = request.args.get("since", "0")
    since = int(since) if since.isdigit() else 0
    with docker_lock:
        recent = [s for s in docker_samples if s["t"] > since]
    return {"samples": recent}


@app.route("/stats")
def stats():
    return render_template("stats.html")


@app.route("/stats/counters")
def stats_counters():
    """Compteurs cumulés de la base : sessions ouvertes, transactions validées, lignes de logs."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT d.sessions, d.xact_commit, t.n_tup_ins
            FROM pg_stat_database d, pg_stat_user_tables t
            WHERE d.datname = current_database() AND t.relname = 'scan_logs'
            """
        )
        sessions, xact_commit, log_rows = cur.fetchone()
    return {"sessions": sessions, "xact_commit": xact_commit, "log_rows": log_rows}


@app.route("/queues")
def queues():
    return render_template("queues.html")


@app.route("/queues/metrics")
def queues_metrics():
    """Échantillons et événements postérieurs à `since` (epoch ms, 0 = tout l'historique borné),
    plus le contenu courant de la file (tâches en attente et en cours)."""
    since = request.args.get("since", "0")
    since = int(since) if since.isdigit() else 0
    with samples_lock:
        recent_samples = [s for s in samples if s["t"] > since]
        recent_events = [e for e in events if e["t"] > since]
        tasks_now = {"pending": list(current_tasks["pending"]), "unacked": list(current_tasks["unacked"])}
    return {"samples": recent_samples, "events": recent_events, "tasks": tasks_now}


@app.route("/jobs/new")
def new_job():
    return render_template("new.html", invalid=[], domains_text="", steps=pentest.excludable_steps())


@app.route("/jobs", methods=["POST"])
def create_jobs():
    text = request.form.get("domains", "")
    upload = request.files.get("file")
    if upload is not None and upload.filename:
        text += "\n" + upload.read().decode("utf-8", errors="replace")

    domains, invalid = parse_domains(text)
    if invalid or not domains:
        return render_template(
            "new.html", invalid=invalid, domains_text=text, no_domain=not domains,
            steps=pentest.excludable_steps(),
        ), 400

    valid_step_ids = {step_id for step_id, _ in pentest.excludable_steps()}
    excluded_steps = set(request.form.getlist("exclude_steps")) & valid_step_ids
    for domain in domains:
        tasks.start_scan(domain, excluded_steps=excluded_steps)
    return redirect(url_for("index"))


@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM scans WHERE id = %s", (scan_id,))
        scan = cur.fetchone()
        if scan is None:
            abort(404)
        cur.execute(
            "SELECT * FROM scan_steps WHERE scan_id = %s ORDER BY recorded_at", (scan_id,)
        )
        steps = cur.fetchall()
        cur.execute(
            "SELECT EXISTS(SELECT 1 FROM scan_steps WHERE scan_id = %s AND status = 'RUNNING') AS running",
            (scan_id,),
        )
        running = cur.fetchone()["running"]
    for step in steps:
        step["has_file"] = db_insert.resolve_report_path(step["report_path"]) is not None
        # Rejouable seulement si l'étape appartient à la chaîne Celery (même garde que la route
        # /rerun). Les étapes hors chaîne (ex. metasploit-auto, synchrone) ne le sont pas.
        step["rerunnable"] = step["step_id"] in pentest.STEP_FUNCS
    resumable = scan["finished_at"] is None and not running
    return render_template("scan.html", scan=scan, steps=steps, running=running, resumable=resumable)


@app.route("/scan/<int:scan_id>/stop", methods=["POST"])
def scan_stop(scan_id):
    db_insert.stop_scan(scan_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/step/<step_id>/skip", methods=["POST"])
def scan_skip(scan_id, step_id):
    """Saute step_id s'il est RUNNING, sans arrêter le reste du scan (db_insert.request_skip, lu
    par pentest.run() dans l'étape active) — à distinguer de /stop, qui arrête tout le scan.
    Ciblé par step_id (et non plus par scan_id seul) depuis que plusieurs étapes indépendantes
    peuvent être RUNNING en même temps pour un même scan (tasks._schedule_for)."""
    db_insert.request_skip(scan_id, step_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/resume", methods=["POST"])
def scan_resume(scan_id):
    tasks.resume_scan(scan_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/step/<step_id>/rerun", methods=["POST"])
def step_rerun(scan_id, step_id):
    if step_id not in pentest.STEP_FUNCS:
        abort(404)
    tasks.rerun_step(scan_id, step_id)
    return redirect(url_for("scan_detail", scan_id=scan_id))


@app.route("/scan/<int:scan_id>/live")
def scan_live(scan_id):
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, domain, finished_at FROM scans WHERE id = %s", (scan_id,))
        scan = cur.fetchone()
    if scan is None:
        abort(404)
    return render_template("live.html", scan=scan)


@app.route("/scan/<int:scan_id>/logs")
def scan_logs(scan_id):
    """Flux Server-Sent Events : envoie les lignes de scan_logs au fil de leur écriture,
    et se termine quand le scan est fini et que tout a été envoyé."""
    last_id = request.headers.get("Last-Event-ID", "0")
    cursor_id = int(last_id) if last_id.isdigit() else 0

    def stream():
        nonlocal cursor_id
        while True:
            with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT finished_at IS NOT NULL AS finished FROM scans WHERE id = %s", (scan_id,))
                state = cur.fetchone()
                if state is None:
                    yield "event: end\ndata: scan introuvable\n\n"
                    return
                finished = state["finished"]
                cur.execute(
                    "SELECT id, line FROM scan_logs WHERE scan_id = %s AND id > %s ORDER BY id LIMIT 500",
                    (scan_id, cursor_id),
                )
                rows = cur.fetchall()
            for row in rows:
                cursor_id = row["id"]
                yield f"id: {row['id']}\ndata: {json.dumps(row['line'], ensure_ascii=False)}\n\n"
            if finished and not rows:
                yield "event: end\ndata: fin\n\n"
                return
            time.sleep(1)

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
def scan_delete(scan_id):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
        if cur.rowcount == 0:
            abort(404)
    return redirect(url_for("index"))


def get_step_or_404(scan_id, step_id):
    with get_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT * FROM scan_steps WHERE scan_id = %s AND step_id = %s ORDER BY id DESC LIMIT 1",
            (scan_id, step_id),
        )
        step = cur.fetchone()
    if step is None:
        abort(404)
    real = db_insert.resolve_report_path(step["report_path"])
    if real is None:
        abort(404)
    return step, real


@app.route("/scan/<int:scan_id>/step/<step_id>/file")
@app.route("/scan/<int:scan_id>/step/<step_id>/file/<path:subpath>")
def step_file(scan_id, step_id, subpath=""):
    step, base_real = get_step_or_404(scan_id, step_id)
    target = os.path.realpath(os.path.join(base_real, subpath)) if subpath else base_real
    if os.path.commonpath([target, base_real]) != base_real:
        abort(404)
    if os.path.isdir(target):
        entries = sorted(os.listdir(target))
        return render_template(
            "listing.html",
            scan_id=scan_id,
            step_id=step_id,
            label=step["label"],
            subpath=subpath,
            entries=entries,
        )
    if os.path.isfile(target):
        return send_file(target)
    abort(404)


# --- Module OSINT standalone -----------------------------------------------------------------
OSINT_ROOT = "/osint"
_OSINT_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".heic", ".heif", ".raw", ".cr2", ".nef", ".arw"}
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,100}$")
_PHONE_RE = re.compile(r"^[\d\s+\-().]{4,30}$")


@app.route("/osint")
def osint():
    return render_template("osint.html", error=None)


@app.route("/osint/submit", methods=["POST"])
def osint_submit():
    target_type = request.form.get("target_type", "")
    if target_type not in ("username", "phone", "email", "image"):
        abort(400)

    if target_type == "image":
        uploads = [f for f in request.files.getlist("image") if f and f.filename]
        if not uploads:
            return render_template("osint.html", error="Aucune image fournie.", active_tab="image"), 400
        task_ids, names = [], []
        for upload in uploads:
            ext = os.path.splitext(upload.filename)[1].lower()
            if ext not in _OSINT_IMAGE_EXTS:
                continue
            uid = str(_uuid_mod.uuid4())
            outdir = os.path.join(OSINT_ROOT, uid)
            os.makedirs(outdir, exist_ok=True)
            image_path = os.path.join(outdir, f"input{ext}")
            upload.save(image_path)
            task_ids.append(tasks.run_osint.delay("image", image_path, uid).id)
            names.append(upload.filename)
        if not task_ids:
            return render_template("osint.html", error="Aucun format supporté. Formats acceptés : JPG, PNG, GIF, BMP, TIFF, WEBP, HEIC, RAW.", active_tab="image"), 400
        return redirect("/osint/batch?ids={}&names={}".format(
            ",".join(task_ids),
            ",".join(_url_quote(n, safe="") for n in names),
        ))

    uid = str(_uuid_mod.uuid4())
    target = (request.form.get("target") or "").strip()
    if not target:
        return render_template("osint.html", error="Cible vide.", active_tab=target_type), 400
    if target_type == "username" and not _USERNAME_RE.match(target):
        return render_template("osint.html", error="Nom d'utilisateur invalide (alphanumérique, . _ - uniquement, 1-100 caractères).", active_tab=target_type), 400
    if target_type == "phone" and not _PHONE_RE.match(target):
        return render_template("osint.html", error="Numéro de téléphone invalide.", active_tab=target_type), 400
    if target_type == "email" and "@" not in target:
        return render_template("osint.html", error="Adresse email invalide.", active_tab=target_type), 400

    result = tasks.run_osint.delay(target_type, target, uid)
    return redirect(url_for("osint_result", task_id=result.id))


@app.route("/osint/result/<task_id>")
def osint_result(task_id):
    result = tasks.run_osint.AsyncResult(task_id)
    output = None
    error = None
    if result.state == "SUCCESS":
        data = result.result or {}
        output = data.get("output", "")
    elif result.state == "FAILURE":
        error = str(result.result)
    return render_template(
        "osint_result.html",
        task_id=task_id,
        state=result.state,
        output=output,
        error=error,
    )


@app.route("/osint/batch")
def osint_batch():
    ids_raw = request.args.get("ids", "")
    names_raw = request.args.get("names", "")
    task_ids = [t.strip() for t in ids_raw.split(",") if t.strip()]
    names = [_url_unquote(n) for n in names_raw.split(",") if n.strip()]
    if not task_ids:
        abort(400)

    results = []
    all_done = True
    for i, tid in enumerate(task_ids):
        r = tasks.run_osint.AsyncResult(tid)
        if r.state in ("PENDING", "STARTED"):
            all_done = False
        item = {
            "task_id": tid,
            "state": r.state,
            "output": None,
            "error": None,
            "name": names[i] if i < len(names) else f"Image {i + 1}",
        }
        if r.state == "SUCCESS":
            item["output"] = (r.result or {}).get("output", "")
        elif r.state == "FAILURE":
            item["error"] = str(r.result)
        results.append(item)

    return render_template(
        "osint_result.html",
        batch=results,
        all_done=all_done,
        ids_raw=ids_raw,
        names_raw=names_raw,
    )
