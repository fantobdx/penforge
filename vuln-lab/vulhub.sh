#!/usr/bin/env bash
# ============================================================================
#  vulhub.sh — ajoute des CVE réelles (Vulhub) comme cibles nuclei du lab.
#
#  Chaque env Vulhub tourne avec SON compose (Vulhub le build), puis on le
#  connecte au réseau Docker du lab. nuclei le scanne par IP interne : pas de
#  Traefik/dnsmasq à reconfigurer. Le navigateur y accède via les ports que
#  Vulhub expose déjà sur localhost.
#
#  ⚠️  STRICTEMENT LOCAL. Ces CVE sont de vraies vulnérabilités exploitables.
#
#  Usage :
#    ./vulhub.sh list                # cibles disponibles
#    ./vulhub.sh up   grafana        # démarre + connecte au réseau du lab
#    ./vulhub.sh scan grafana        # httpx + nuclei sur la cible
#    ./vulhub.sh down grafana        # arrête l'env
#    ./vulhub.sh browse grafana      # rappelle l'URL localhost à ouvrir
# ============================================================================
set -euo pipefail

VULHUB_DIR="${VULHUB_DIR:-./vulhub}"
RECON_IMAGE="six2dez/reconftw:main"

# clé -> chemin Vulhub | port(s) navigateur localhost | note
declare -A PATHS=(
  [grafana]="grafana/CVE-2021-43798"
  [apache]="httpd/CVE-2021-41773"
  [confluence]="confluence/CVE-2022-26134"
  [spring4shell]="spring/CVE-2022-22965"
  [log4shell]="log4j/CVE-2021-44228"
)
declare -A LOCALPORT=(
  [grafana]=3000
  [apache]=8080
  [confluence]=8090
  [spring4shell]=8080
  [log4shell]=8983
)
declare -A NOTE=(
  [grafana]="Path traversal — nuclei fire direct (CVE-2021-43798)"
  [apache]="Path traversal/RCE httpd 2.4.49 — nuclei fire direct (CVE-2021-41773)"
  [confluence]="OGNL RCE — nuclei fire direct. Image lourde (~1 Go, démarrage lent)"
  [spring4shell]="Spring RCE — nuclei fire (CVE-2022-22965)"
  [log4shell]="Log4Shell — needs OOB/interactsh : nuclei NE fire PAS en réseau isolé. Env présent pour exploitation manuelle"
)

# ports candidats sondés côté réseau interne pour trouver le service web
PROBE_PORTS="80 8080 8090 8983 3000 8000 8888 9090 7001 443"

lab_net() {
  docker inspect lab-traefik \
    -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null
}

need_lab() {
  local n; n="$(lab_net || true)"
  [ -n "$n" ] || { echo "❌ Lab non démarré. Lance d'abord: ./lab.sh up"; exit 1; }
  echo "$n"
}

clone() {
  if [ ! -d "$VULHUB_DIR/.git" ]; then
    echo "[*] Clone de Vulhub (une fois)…"
    git clone --depth 1 https://github.com/vulhub/vulhub.git "$VULHUB_DIR"
  fi
}

check_key() {
  [ -n "${PATHS[$1]:-}" ] || { echo "❌ Cible inconnue: $1"; list; exit 1; }
}

list() {
  echo "Cibles Vulhub disponibles :"
  for k in "${!PATHS[@]}"; do
    printf "  %-13s %-28s %s\n" "$k" "${PATHS[$k]}" "${NOTE[$k]}"
  done | sort
}

up() {
  local key="$1"; check_key "$key"; clone
  local net; net="$(need_lab)"
  local dir="$VULHUB_DIR/${PATHS[$key]}"
  echo "[*] Démarrage: ${PATHS[$key]}"
  ( cd "$dir" && docker compose up -d --build )
  echo "[*] Connexion des conteneurs au réseau du lab ($net)…"
  ( cd "$dir" && docker compose ps -q ) | while read -r cid; do
    [ -n "$cid" ] && docker network connect "$net" "$cid" 2>/dev/null || true
  done
  echo "[+] '$key' prêt. Navigateur: http://localhost:${LOCALPORT[$key]}   |   Scan: ./vulhub.sh scan $key"
  echo "    Note: ${NOTE[$key]}"
}

# renvoie les 'ip:port' candidats (IP interne des conteneurs de l'env)
candidates() {
  local key="$1"; local net="$2"
  local dir="$VULHUB_DIR/${PATHS[$key]}"
  ( cd "$dir" && docker compose ps -q ) | while read -r cid; do
    [ -z "$cid" ] && continue
    ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$cid" 2>/dev/null || true)
    [ -z "$ip" ] && continue
    for p in $PROBE_PORTS; do echo "$ip:$p"; done
  done
}

scan() {
  local key="$1"; check_key "$key"
  local net; net="$(need_lab)"; mkdir -p Recon
  local cands; cands="$(candidates "$key" "$net")"
  [ -n "$cands" ] || { echo "❌ Aucun conteneur connecté. Fais d'abord: ./vulhub.sh up $key"; exit 1; }
  echo "[*] Détection du service web + nuclei sur '$key'…"
  printf '%s\n' "$cands" | docker run --rm -i --network "$net" \
    -v "$PWD/Recon:/out" --entrypoint sh "$RECON_IMAGE" -c '
      cat > /tmp/cand.txt
      httpx -l /tmp/cand.txt -silent -sc -title -o /tmp/live.txt 2>/dev/null
      echo "== Services web vivants =="; cat /tmp/live.txt
      echo; echo "== nuclei =="
      nuclei -l /tmp/live.txt -silent -o /out/vulhub-'"$key"'.txt 2>/dev/null || true
      cat /out/vulhub-'"$key"'.txt 2>/dev/null
    '
  echo "[+] Rapport: ./Recon/vulhub-$key.txt"
}

down() {
  local key="$1"; check_key "$key"
  local dir="$VULHUB_DIR/${PATHS[$key]}"
  ( cd "$dir" && docker compose down -v )
  echo "[+] '$key' arrêté."
}

browse() {
  local key="$1"; check_key "$key"
  echo "http://localhost:${LOCALPORT[$key]}   (${NOTE[$key]})"
}

case "${1:-}" in
  list)   list ;;
  up)     up "${2:?clé requise, ex: grafana}" ;;
  scan)   scan "${2:?clé requise}" ;;
  down)   down "${2:?clé requise}" ;;
  browse) browse "${2:?clé requise}" ;;
  *) echo "Usage: $0 {list|up <clé>|scan <clé>|down <clé>|browse <clé>}"; echo; list ;;
esac
