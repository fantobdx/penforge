#!/usr/bin/env bash
# ============================================================================
#  lab.sh — helper pour le lab vulnérable local (Traefik + labs *.lab.local)
#
#  Usage :
#    ./lab.sh up      -> ajoute les entrées /etc/hosts + docker compose up -d
#    ./lab.sh down    -> arrête la stack (garde les hosts)
#    ./lab.sh hosts   -> ajoute seulement les entrées /etc/hosts
#    ./lab.sh unhosts -> retire les entrées /etc/hosts
#    ./lab.sh urls    -> affiche les URLs des labs
#    ./lab.sh doctor  -> vérifie l'état de la stack
#
#  Les services du lab sont définis dans le docker-compose.yml à la racine du
#  projet (profile "lab"). Ce script pointe vers ce compose racine.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

DOMAINS=(
  traefik.lab.local
  juice.lab.local
  dvwa.lab.local
  vampi.lab.local
  webgoat.lab.local
  mutillidae.lab.local
)
MARKER="# >>> vuln-lab <<<"
HOSTS=/etc/hosts

# docker compose (v2) ou docker-compose (v1), pointant vers la racine du projet
if docker compose version >/dev/null 2>&1; then
  DC="docker compose -f $PROJECT_ROOT/docker-compose.yml"
else
  DC="docker-compose -f $PROJECT_ROOT/docker-compose.yml"
fi

add_hosts() {
  if grep -q "$MARKER" "$HOSTS"; then
    echo "[=] Entrées /etc/hosts déjà présentes."
    return
  fi
  echo "[+] Ajout des entrées dans $HOSTS (sudo requis)…"
  {
    echo ""
    echo "$MARKER"
    for d in "${DOMAINS[@]}"; do echo "127.0.0.1 $d"; done
    echo "# <<< vuln-lab >>>"
  } | sudo tee -a "$HOSTS" >/dev/null
  echo "[+] OK."
}

remove_hosts() {
  echo "[-] Suppression des entrées /etc/hosts (sudo requis)…"
  sudo sed -i "/# >>> vuln-lab <<</,/# <<< vuln-lab >>>/d" "$HOSTS"
  echo "[-] OK."
}

print_urls() {
  cat <<'EOF'

  ┌────────────────────────────────────────────────────────────┐
  │  Labs disponibles                                          │
  ├────────────────────────────────────────────────────────────┤
  │  Juice Shop    http://juice.lab.local                      │
  │  DVWA          http://dvwa.lab.local     (admin/password)  │
  │  VAmPI (API)   http://vampi.lab.local                      │
  │  WebGoat       http://webgoat.lab.local/WebGoat            │
  │  WebWolf       http://webgoat.lab.local/WebWolf            │
  │  Mutillidae    http://mutillidae.lab.local                 │
  │  Dashboard TK  http://traefik.lab.local  (ou :8081)        │
  └────────────────────────────────────────────────────────────┘

  DVWA : au 1er lancement -> /setup.php -> "Create / Reset Database"
EOF
}

doctor() {
  echo "=== 1) Conteneurs ==="
  $DC ps
  echo
  echo "=== 2) /etc/hosts ==="
  grep -E "lab.local" "$HOSTS" || echo "  ⚠️  AUCUNE entrée *.lab.local -> lance: ./lab.sh hosts"
  echo
  echo "=== 3) Traefik répond ? ==="
  curl -s -o /dev/null -w "  dashboard :8081 -> HTTP %{http_code}\n" http://127.0.0.1:8081/ || echo "  ⚠️  Traefik injoignable"
  echo
  echo "=== 4) Routage par Host header (bypass DNS) ==="
  for h in juice.lab.local dvwa.lab.local vampi.lab.local webgoat.lab.local mutillidae.lab.local; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $h" http://127.0.0.1/ || echo "ERR")
    echo "  Host: $h -> HTTP $code"
  done
  echo
  echo "  Lecture :"
  echo "   • 200/301/302 = OK (le routage marche)."
  echo "   • 404 ici     = Traefik ne voit pas le conteneur (réseau/labels)."
  echo "   • 502/503     = conteneur pas encore prêt, réessaie dans 30s."
  echo "   • Si le curl marche mais PAS le navigateur -> problème /etc/hosts."
}

case "${1:-}" in
  up)      add_hosts; echo "[*] Pull + démarrage…"; $DC --profile lab pull; $DC --profile lab up -d; echo "[*] Attente du démarrage (~20s)…"; sleep 20; print_urls ;;
  down)    $DC --profile lab down ;;
  doctor)  doctor ;;
  hosts)   add_hosts ;;
  unhosts) remove_hosts ;;
  urls)    print_urls ;;
  *) echo "Usage: $0 {up|down|doctor|hosts|unhosts|urls}"; exit 1 ;;
esac
