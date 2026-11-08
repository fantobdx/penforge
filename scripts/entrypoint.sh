#!/bin/sh
# Fix ownership des volumes montés (tourne en root)
chown -R pentest:pentest /reports /osint /usr/share/exploits /var/lib/blackarch-mcp 2>/dev/null || true

# Créer le home de pentest (useradd -M ne le crée pas) pour que les outils
# (wpscan, nuclei, subfinder…) puissent écrire leur cache/config
mkdir -p /home/pentest/.cache /home/pentest/.config
chown -R pentest:pentest /home/pentest

EXPLOITS_DIR=/usr/share/exploits
if [ -z "$(ls -A "$EXPLOITS_DIR" 2>/dev/null)" ]; then
    echo "[entrypoint] Première exécution : téléchargement des bases d'exploits en arrière-plan..."
    setpriv --reuid=pentest --regid=pentest --init-groups -- \
        env HOME=/home/pentest sh -c 'sploitctl -f 0 -XR >> /tmp/sploitctl.log 2>&1' &
else
    echo "[entrypoint] Bases d'exploits déjà présentes dans $EXPLOITS_DIR."
fi

setpriv --reuid=pentest --regid=pentest --init-groups -- \
    env HOME=/home/pentest sh -c 'cd /opt/blackarch-mcp && python3 -m blackarch_mcp.server --host 0.0.0.0 --port 8765 >> /tmp/blackarch-mcp.log 2>&1' &

exec setpriv --reuid=pentest --regid=pentest --init-groups -- \
    env HOME=/home/pentest celery -A penforge.worker.app worker --concurrency="${SCAN_WORKERS:-3}" --loglevel=info
