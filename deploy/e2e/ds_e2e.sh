#!/usr/bin/env bash
# e2e check for plan step 2 (datasource permissions)
P=$(dirname "$0")/pw.txt
pw() { grep "user $1 " "$P" | awk '{print $NF}'; }
G=localhost:3001
adm() { curl -s -u admin:${GF_ADMIN_PASSWORD:-admin} -H Content-Type:application/json -H "X-Grafana-Org-Id: $ACME" "$@"; }
ACME=$(curl -s -u admin:${GF_ADMIN_PASSWORD:-admin} $G/api/orgs/name/Acme | jq .id)
DS=$(adm $G/api/datasources/name/sales-db | jq -r '.uid // empty')
[ -n "$DS" ] || DS=$(adm $G/api/datasources -d '{"name":"sales-db","type":"grafana-testdata-datasource","access":"proxy"}' | jq -r '.datasource.uid')
echo "ds: $DS"
q() { curl -s -o /dev/null -w '%{http_code}' -u "$1:$(pw $1)" -H "X-Grafana-Org-Id: $ACME" -H Content-Type:application/json $G/api/ds/query \
  -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS\"},\"scenarioId\":\"random_walk\"}],\"from\":\"now-1h\",\"to\":\"now\"}"; }
id() { curl -s -u admin:${GF_ADMIN_PASSWORD:-admin} "$G/api/users/lookup?loginOrEmail=$1" | jq .id; }
echo "perms: $(adm $G/api/access-control/datasources/$DS | jq -c '[.[]|{builtInRole,userLogin,permission}]')"
echo "default: carol=$(q carol) bob=$(q bob)"
adm $G/api/access-control/datasources/$DS -d "{\"permissions\":[{\"userId\":$(id bob),\"permission\":\"Query\"},{\"userId\":$(id carol),\"permission\":\"\"},{\"builtInRole\":\"Viewer\",\"permission\":\"\"},{\"builtInRole\":\"Editor\",\"permission\":\"\"}]}" | jq -c .
echo "only bob: carol=$(q carol) bob=$(q bob)"
echo "carol sees ds list: $(curl -s -u "carol:$(pw carol)" -H "X-Grafana-Org-Id: $ACME" $G/api/datasources | jq -c '[.[]?.name]')"
echo "carol self-grant: $(curl -s -o /dev/null -w '%{http_code}' -u "carol:$(pw carol)" -H "X-Grafana-Org-Id: $ACME" -H Content-Type:application/json $G/api/access-control/datasources/$DS/users/$(id carol) -d '{"permission":"Admin"}')"
adm $G/api/access-control/datasources/$DS/users/$(id carol) -d '{"permission":"Query"}' | jq -c .
echo "carol granted: carol=$(q carol)"
adm $G/api/access-control/datasources/$DS/users/$(id carol) -d '{"permission":""}' | jq -c .
echo "carol revoked: carol=$(q carol) list=$(curl -s -u "carol:$(pw carol)" -H "X-Grafana-Org-Id: $ACME" $G/api/datasources | jq -c '[.[]?.name]')"
