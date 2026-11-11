import os
import re

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

# Binaires et wordlists
XSSZYPHERON_BIN = os.environ.get("XSSZYPHERON_BIN", "/src/XSSZypheron/XSSZypheron")
XSSTRIKE_BIN = os.environ.get("XSSTRIKE_BIN", "/src/XSStrike/xsstrike.py")
A2SV_BIN = os.environ.get("A2SV_BIN", "/src/a2sv/a2sv.py")
FFUF_WORDLIST = os.environ.get("FFUF_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/common.txt")
FFUF_DIR_WORDLIST = os.environ.get("FFUF_DIR_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/big.txt")
FFUF_THREADS = int(os.environ.get("FFUF_THREADS", "10"))
FFUF_RATE = int(os.environ.get("FFUF_RATE", "20"))
WP_BRUTEFORCE_WORDLIST = os.environ.get(
    "WP_BRUTEFORCE_WORDLIST",
    "/usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt",
)
DIRBUSTER_WORDLIST = os.environ.get("DIRBUSTER_WORDLIST", "/usr/share/dirb/wordlists/big.txt")
NUCLEI_TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")

# Limites de crawl
FFUF_MAX_URLS = int(os.environ.get("FFUF_MAX_URLS", "20"))
SQLMAP_MAX_URLS = int(os.environ.get("SQLMAP_MAX_URLS", "60"))
TRUFFLEHOG_MAX_URLS = int(os.environ.get("TRUFFLEHOG_MAX_URLS", "100"))
SPLOITCTL_MAX_TERMS = int(os.environ.get("SPLOITCTL_MAX_TERMS", "1000"))

# Credentials HTTP optionnels pour le backup scanner
BACKUP_HTTP_USER = os.environ.get("BACKUP_HTTP_USER", "")
BACKUP_HTTP_PASS = os.environ.get("BACKUP_HTTP_PASS", "")
BACKUP_MIN_SIZE = int(os.environ.get("BACKUP_MIN_SIZE", "1024"))

# Tor / concurrence
TOR_BASE_PORT = int(os.environ.get("TOR_BASE_PORT", "9050"))
TOR_BOOTSTRAP_TIMEOUT = int(os.environ.get("TOR_BOOTSTRAP_TIMEOUT", "180"))
TOR_CONTROL_PORT_OFFSET = int(os.environ.get("TOR_CONTROL_PORT_OFFSET", "100"))
TOR_NEWNYM_COOLDOWN = int(os.environ.get("TOR_NEWNYM_COOLDOWN", "10"))
SCAN_WORKERS = int(os.environ.get("SCAN_WORKERS", "3"))
MAX_CONCURRENT_TASKS_PER_DOMAIN = int(os.environ.get("MAX_CONCURRENT_TASKS_PER_DOMAIN", "2"))

# Stockage
SCANS_ROOT = os.environ.get("SCANS_ROOT", "/reports/scans")
OSINT_ROOT = os.environ.get("OSINT_ROOT", "/osint")

# Exécution des étapes
LOG_FLUSH_INTERVAL = 1
LOG_BATCH_SIZE = 100
STEP_TIMEOUT = int(os.environ.get("STEP_TIMEOUT", "3000"))
STEP_KILL_GRACE = 10

# Metasploit
MSF_MAX_TERMS = int(os.environ.get("MSF_MAX_TERMS", "40"))
MSF_MAX_MODULES_PER_TERM = int(os.environ.get("MSF_MAX_MODULES_PER_TERM", "5"))

# Celery
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/1")

# Web
WEB_USER = os.environ.get("WEB_USER", "admin")
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")

# Wapiti endpoint
WAPITI_ENDPOINT_IP = os.environ.get("WAPITI_ENDPOINT_IP", "")

# SauceNAO (optionnel — 200 req/jour avec un compte gratuit)
SAUCENAO_API_KEY = os.environ.get("SAUCENAO_API_KEY", "")

