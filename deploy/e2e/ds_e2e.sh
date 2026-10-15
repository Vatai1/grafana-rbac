#!/usr/bin/env bash
# e2e: per-datasource permissions (plan step 2). Exits 1 on any failed check.
. "$(dirname "$0")/lib.sh"
ACME=$(curl -s -u "$A" $G/api/orgs/name/Acme | jq .id)
adm() { curl -s -u "$A" -H Content-Type:application/json -H "X-Grafana-Org-Id: $ACME" "$@"; }
DS=$(adm $G/api/datasources/name/sales-db | jq -r '.uid // empty')
[ -n "$DS" ] || DS=$(adm $G/api/datasources -d '{"name":"sales-db","type":"grafana-testdata-datasource","access":"proxy"}' | jq -r '.datasource.uid')
q() { # user [datasource uid]
  curl -s -o /dev/null -w '%{http_code}' -u "$1:$(pw $1)" -H "X-Grafana-Org-Id: $ACME" -H Content-Type:application/json $G/api/ds/query \
    -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"${2:-$DS}\"},\"scenarioId\":\"random_walk\"}],\"from\":\"now-1h\",\"to\":\"now\"}"
}
listed() { curl -s -u "$1:$(pw $1)" -H "X-Grafana-Org-Id: $ACME" $G/api/datasources | jq -c '[.[]?.name] | index("sales-db") != null'; }

adm $G/api/access-control/datasources/$DS -d "{\"permissions\":[{\"userId\":$(id bob),\"permission\":\"Query\"},{\"userId\":$(id carol),\"permission\":\"\"},{\"builtInRole\":\"Viewer\",\"permission\":\"\"},{\"builtInRole\":\"Editor\",\"permission\":\"\"}]}" >/dev/null
eventually "bob (granted Query) can query" 200 q bob
eventually "carol (no permission) cannot query" 403 q carol
check "carol does not see sales-db in the list" false "$(listed carol)"
check "carol cannot grant herself access" 403 "$(curl -s -o /dev/null -w '%{http_code}' -u "carol:$(pw carol)" -H "X-Grafana-Org-Id: $ACME" -H Content-Type:application/json $G/api/access-control/datasources/$DS/users/$(id carol) -d '{"permission":"Admin"}')"

adm $G/api/access-control/datasources/$DS/users/$(id carol) -d '{"permission":"Query"}' >/dev/null
check "carol can query right after a grant" 200 "$(q carol)"
check "carol sees sales-db after a grant" true "$(listed carol)"
adm $G/api/access-control/datasources/$DS/users/$(id carol) -d '{"permission":""}' >/dev/null
check "carol cannot query right after a revoke" 403 "$(q carol)"

# a new datasource is open to Viewers by default, like upstream Grafana
NEW=$(adm $G/api/datasources -d "{\"name\":\"e2e-tmp-$RANDOM\",\"type\":\"grafana-testdata-datasource\",\"access\":\"proxy\"}" | jq -r .datasource.uid)
eventually "Viewer can query a new datasource" 200 q carol "$NEW"
adm -X DELETE $G/api/datasources/uid/$NEW >/dev/null
finish
