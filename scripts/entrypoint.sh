#!/bin/sh
# Télécharge les bases d'exploits sploitctl au premier démarrage (volume vide).
# Lance le téléchargement en arrière-plan pour ne pas bloquer celery.
EXPLOITS_DIR=/usr/share/exploits

if [ -z "$(ls -A "$EXPLOITS_DIR" 2>/dev/null)" ]; then
    echo "[entrypoint] Première exécution : téléchargement des bases d'exploits en arrière-plan..."
    sploitctl -f 0 -XR >> /tmp/sploitctl.log 2>&1 &
else
    echo "[entrypoint] Bases d'exploits déjà présentes dans $EXPLOITS_DIR."
fi

exec celery -A tasks worker --concurrency="${SCAN_WORKERS:-3}" --loglevel=info
