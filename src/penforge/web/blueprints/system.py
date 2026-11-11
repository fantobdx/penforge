import collections
import json
import logging
import os
import re
import socket as _socket
import threading
import time

try:
    import docker as docker_sdk
except ImportError:
    docker_sdk = None

import psycopg2
import redis
from flask import Blueprint, render_template, request

from penforge.worker.app import app as _celery_app

bp = Blueprint("system", __name__)
log = logging.getLogger(__name__)

SAMPLE_INTERVAL_S = 2
SAMPLE_WINDOW = 1800
EVENTS_WINDOW = 500
SNAPSHOT_LIMIT = 200
QUEUE_NAME = "celery"
UNACKED_KEY = "unacked"
_PRIORITY_SEPARATOR = "\x06\x16"
_MAX_PRIORITY = _celery_app.conf.task_queue_max_priority or 0
_QUEUE_KEYS = (
    [QUEUE_NAME]
    if not _MAX_PRIORITY
    else [QUEUE_NAME] + [f"{QUEUE_NAME}{_PRIORITY_SEPARATOR}{p}" for p in range(_MAX_PRIORITY + 1)]
)

DOCKER_INTERVAL_S = 5
DOCKER_SAMPLE_WINDOW = 720

_redis_client = redis.Redis.from_url(_celery_app.conf.broker_url)
_samples: collections.deque = collections.deque(maxlen=SAMPLE_WINDOW)
_events: collections.deque = collections.deque(maxlen=EVENTS_WINDOW)
_current_tasks: dict = {"pending": [], "unacked": []}
_samples_lock = threading.Lock()

_docker_samples: collections.deque = collections.deque(maxlen=DOCKER_SAMPLE_WINDOW)
_docker_lock = threading.Lock()

_conn_containers: list = []
_conn_containers_lock = threading.Lock()

_proc_cache: list = []
_proc_lock = threading.Lock()

_prev_cumul: dict = {}
_prev_tor_rotations: int = 0

_CONN_ORDER = {"ESTAB": 0, "SYN_SENT": 1, "CLOSE_WAIT": 2, "FIN_WAIT1": 3,
               "FIN_WAIT2": 4, "TIME_WAIT": 5, "LISTEN": 6}
_TCP_STATES_HEX = {
    "01": "ESTAB", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

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

_INODE_SH = (
    "for p in /proc/[0-9]*; do "
    "  c=$(cat \"$p/comm\" 2>/dev/null)||continue; pid=\"${p##*/}\"; "
    "  for f in \"$p/fd/\"*; do [ -L \"$f\" ]||continue; "
    "    l=$(readlink \"$f\" 2>/dev/null)||continue; "
    "    case \"$l\" in socket:\\[*) i=\"${l#socket:[}\"; printf '%s\\t%s(%s)\\n' \"${i%]}\" \"$c\" \"$pid\";; esac; "
    "  done; "
    "done 2>/dev/null"
)

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


def _get_conn():
    return psycopg2.connect()


def _task_info(raw):
    headers = raw.get("headers", {})
    return {"id": headers.get("id"), "task": headers.get("task"), "args": headers.get("argsrepr", "")}


def _read_queue():
    pending = {}
    for key in _QUEUE_KEYS:
        for item in _redis_client.lrange(key, 0, -1):
            info = _task_info(json.loads(item))
            if info["id"]:
                pending[info["id"]] = info
    unacked = {}
    for value in _redis_client.hvals(UNACKED_KEY):
        info = _task_info(json.loads(value)[0])
        unacked[info["id"]] = info
    return pending, unacked


def _take_server_metrics():
    global _prev_tor_rotations
    memory = _redis_client.info("memory")["used_memory"]
    clients = _redis_client.info("clients")["connected_clients"]
    capacity, busy = 0, 0
    try:
        with _get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*), count(locked_by_task_id) FROM tor_instances")
            capacity, busy = cur.fetchone()
    except psycopg2.errors.UndefinedTable:
        pass
    rotations_delta = 0
    try:
        val = _redis_client.get("penforge:tor_rotations")
        total = int(val) if val else 0
        rotations_delta = max(0, total - _prev_tor_rotations)
        _prev_tor_rotations = total
    except Exception:
        pass
    return {
        "busy": busy,
        "capacity": capacity,
        "memory_mb": round(memory / 1024 / 1024, 2),
        "clients": clients,
        "tor_rotations": rotations_delta,
    }


def _diff_events(before_pending, before_unacked, pending, unacked, now):
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


def _calc_cpu_percent(stats):
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


def _calc_mem_mb(stats):
    try:
        usage = stats["memory_stats"]["usage"]
        st = stats["memory_stats"].get("stats", {})
        cache = st.get("cache", st.get("total_inactive_file", 0))
        return round(max(0, usage - cache) / 1024 / 1024, 1)
    except (KeyError, TypeError):
        return 0.0


def _disk_usage():
    try:
        sv = os.statvfs("/reports")
        total = sv.f_blocks * sv.f_frsize
        free = sv.f_bavail * sv.f_frsize
        return {"used_gb": round((total - free) / 1024 ** 3, 2), "total_gb": round(total / 1024 ** 3, 2)}
    except OSError:
        return {"used_gb": 0, "total_gb": 0}


def _calc_blkio(stats, container_id=""):
    r = w = 0
    for e in (stats.get("blkio_stats") or {}).get("io_service_bytes_recursive") or []:
        op, v = e.get("op", ""), e.get("value", 0)
        if op == "Read":
            r += v
        elif op == "Write":
            w += v
    if r == 0 and w == 0 and container_id:
        try:
            path = f"/host/cgroup/system.slice/docker-{container_id}.scope/io.stat"
            with open(path) as f:
                for line in f:
                    parts = line.split()
                    if not parts:
                        continue
                    major = int(parts[0].split(":")[0])
                    if major in (252, 253):
                        continue
                    kv = dict(item.split("=") for item in parts[1:] if "=" in item)
                    r += int(kv.get("rbytes", 0))
                    w += int(kv.get("wbytes", 0))
        except OSError:
            pass
    return r, w


def _calc_net(stats):
    rx = tx = 0
    for iface in ((stats.get("networks") or {}).values()):
        rx += iface.get("rx_bytes", 0)
        tx += iface.get("tx_bytes", 0)
    return rx, tx


def _parse_proc_tcp(raw, inodes):
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
                rows.append({"state": state, "local": k[1], "remote": k[2], "proc": inodes.get(inode, "")})
        except Exception:
            pass
    return rows


def _collect_container(container):
    name = re.sub(r"^(penforge|lab)-", "", container.name)
    name = re.sub(r"-\d+$", "", name)
    try:
        r = container.exec_run(["python3", "-c", _PROBE_PY], demux=False, user="root")
        if r.exit_code == 0 and r.output:
            conns = json.loads(r.output.decode("utf-8", errors="replace").strip())
            return [{"container": name, "state": c["s"], "local": c["l"],
                     "remote": c["r"], "proc": c["p"]} for c in conns]
    except Exception:
        pass
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


def _collect_procs(container):
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


def _sample_loop():
    before_pending, before_unacked = {}, {}
    while True:
        try:
            pending, unacked = _read_queue()
            now = int(time.time() * 1000)
            sample = {"t": now, "pending": len(pending), "unacked": len(unacked), **_take_server_metrics()}
            new_events = _diff_events(before_pending, before_unacked, pending, unacked, now)
            with _samples_lock:
                _samples.append(sample)
                _events.extend(new_events)
                _current_tasks["pending"] = list(pending.values())[:SNAPSHOT_LIMIT]
                _current_tasks["unacked"] = list(unacked.values())[:SNAPSHOT_LIMIT]
            before_pending, before_unacked = pending, unacked
        except Exception:
            log.exception("Échec de l'échantillonnage Redis/Postgres")
        time.sleep(SAMPLE_INTERVAL_S)


def _docker_sample_loop():
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
            with _docker_lock:
                _docker_samples.append(sample)
        except Exception:
            log.exception("Échec de l'échantillonnage Docker")
            client = None
        time.sleep(DOCKER_INTERVAL_S)


def _conn_refresh_loop():
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


def _proc_refresh_loop():
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


def start_background_threads():
    threading.Thread(target=_sample_loop, daemon=True, name="queue-sampler").start()
    threading.Thread(target=_docker_sample_loop, daemon=True, name="docker-sampler").start()
    threading.Thread(target=_conn_refresh_loop, daemon=True, name="conn-sampler").start()
    threading.Thread(target=_proc_refresh_loop, daemon=True, name="proc-sampler").start()


@bp.route("/system")
def system():
    return render_template("system.html")


@bp.route("/system/connections")
def system_connections():
    with _conn_containers_lock:
        return {"connections": list(_conn_containers)}


@bp.route("/system/processes")
def system_processes():
    with _proc_lock:
        return {"processes": list(_proc_cache)}


@bp.route("/system/metrics")
def system_metrics():
    since = request.args.get("since", "0")
    since = int(since) if since.isdigit() else 0
    with _docker_lock:
        recent = [s for s in _docker_samples if s["t"] > since]
    return {"samples": recent}


@bp.route("/stats")
def stats():
    return render_template("stats.html")


@bp.route("/stats/counters")
def stats_counters():
    with _get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT d.sessions, d.xact_commit, t.n_tup_ins
            FROM pg_stat_database d, pg_stat_user_tables t
            WHERE d.datname = current_database() AND t.relname = 'scan_logs'
            """
        )
        sessions, xact_commit, log_rows = cur.fetchone()
    return {"sessions": sessions, "xact_commit": xact_commit, "log_rows": log_rows}


@bp.route("/queues")
def queues():
    return render_template("queues.html")


@bp.route("/queues/metrics")
def queues_metrics():
    since = request.args.get("since", "0")
    since = int(since) if since.isdigit() else 0
    with _samples_lock:
        recent_samples = [s for s in _samples if s["t"] > since]
        recent_events = [e for e in _events if e["t"] > since]
        tasks_now = {"pending": list(_current_tasks["pending"]), "unacked": list(_current_tasks["unacked"])}
    return {"samples": recent_samples, "events": recent_events, "tasks": tasks_now}
