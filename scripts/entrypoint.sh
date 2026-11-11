#!/bin/sh
# SecLists : clone au premier démarrage, skip si déjà présent
if [ ! -d /usr/share/seclists/.git ]; then
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
fi

# Fix ownership des volumes montés (tourne en root)
chown -R pentest:pentest /reports /osint 2>/dev/null || true

# Créer le home de pentest (useradd -M ne le crée pas) pour que les outils
# (wpscan, nuclei, subfinder…) puissent écrire leur cache/config
mkdir -p /home/pentest/.cache /home/pentest/.config /home/pentest/.msf4
chown -R pentest:pentest /home/pentest

# Créer la DB msf si elle n'existe pas
python3 -c "
import psycopg2, os
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
try:
    conn = psycopg2.connect(host=os.environ['PGHOST'], port=os.environ.get('PGPORT',5432),
                            user=os.environ['PGUSER'], password=os.environ['PGPASSWORD'],
                            dbname=os.environ.get('PGDATABASE','pentest'))
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    cur.execute(\"SELECT 1 FROM pg_database WHERE datname='msf'\")
    if not cur.fetchone():
        cur.execute('CREATE DATABASE msf')
    conn.close()
except Exception as e:
    print('MSF DB warning:', e)
" || true

# Générer la config DB Metasploit
cat > /home/pentest/.msf4/database.yml << EOF
production:
  adapter: postgresql
  database: msf
  username: ${PGUSER:-pentest}
  password: ${PGPASSWORD}
  host: ${PGHOST:-db}
  port: ${PGPORT:-5432}
  pool: 5
  timeout: 5
EOF
chown pentest:pentest /home/pentest/.msf4/database.yml

# Copie pour root (msfconsole lancé via docker exec)
mkdir -p /root/.msf4
cp /home/pentest/.msf4/database.yml /root/.msf4/database.yml

setpriv --reuid=pentest --regid=pentest --init-groups -- \
    env HOME=/home/pentest sh -c 'python -m penforge.mcp.server >> /tmp/pentest-mcp.log 2>&1' &

exec setpriv --reuid=pentest --regid=pentest --init-groups -- \
    env HOME=/home/pentest celery -A penforge.worker.app worker --concurrency="${SCAN_WORKERS:-3}" --loglevel=info -Ofair
