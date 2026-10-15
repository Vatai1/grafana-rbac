# Shared helpers for the e2e checks (source it). Env: GRAFANA_URL, GF_ADMIN_PASSWORD; user passwords in e2e/pw.txt.
P=$(dirname "${BASH_SOURCE[0]}")/pw.txt
G=${GRAFANA_URL:-http://localhost:3001}
A="admin:${GF_ADMIN_PASSWORD:-admin}"
FAILED=0
pw() { grep "user $1 " "$P" | awk '{print $NF}'; }
id() { curl -s -u "$A" "$G/api/users/lookup?loginOrEmail=$1" | jq .id; }
# check <description> <want> <got>
check() { if [ "$2" = "$3" ]; then echo "ok    $1 ($3)"; else FAILED=1; echo "FAIL  $1: want $2, got $3"; fi; }
# eventually <description> <want> <command...>: retries for up to 70s, Grafana caches permissions for 30-60s
eventually() {
  local desc=$1 want=$2 got
  shift 2
  for _ in $(seq 35); do
    got=$("$@")
    [ "$got" = "$want" ] && break
    sleep 2
  done
  check "$desc" "$want" "$got"
}
finish() { if [ $FAILED = 0 ]; then echo "PASS $(basename "$0")"; else echo "FAILED $(basename "$0")"; exit 1; fi; }
