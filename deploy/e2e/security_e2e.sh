#!/usr/bin/env bash
# Security probe (plan step 7): every way to reach a datasource as a user WITHOUT access to it.
# Expectation: no 2xx anywhere. Needs ./setup.sh > e2e/pw.txt and the sales-db datasource from ds_e2e.sh.
P=$(dirname "$0")/pw.txt
pw() { grep "user $1 " "$P" | awk '{print $NF}'; }
G=localhost:3001
A="admin:${GF_ADMIN_PASSWORD:-admin}"
ACME=$(curl -s -u "$A" $G/api/orgs/name/Acme | jq .id)
DS=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" $G/api/datasources/name/sales-db | jq -r .uid)
ID=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" $G/api/datasources/name/sales-db | jq -r .id)
U=carol
C=$(curl -s -u "$A" "$G/api/users/lookup?loginOrEmail=$U" | jq .id)
# make sure carol has no access to sales-db (neither directly nor via Viewer)
curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" -H Content-Type:application/json $G/api/access-control/datasources/$DS \
  -d "{\"permissions\":[{\"userId\":$C,\"permission\":\"\"},{\"builtInRole\":\"Viewer\",\"permission\":\"\"}]}" >/dev/null
Q="{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS\"},\"scenarioId\":\"random_walk\"}],\"from\":\"now-1h\",\"to\":\"now\"}"
fail=0
probe() {
  local path=$1; shift
  local code body
  body=$(curl -s -w '\n%{http_code}' -u "$U:$(pw $U)" -H "X-Grafana-Org-Id: $ACME" -H Content-Type:application/json "$@" "$G$path")
  code=${body##*$'\n'}
  case $code in 2*) fail=1; echo "LEAK  $code $path :: $(head -c 120 <<<"${body%$'\n'*}" | tr '\n' ' ')" ;; *) echo "ok    $code $path" ;; esac
}
probe /api/datasources/uid/$DS
probe /api/datasources/name/sales-db
echo "info      /api/datasources/id/sales-db -> $(curl -s -u "$U:$(pw $U)" -H "X-Grafana-Org-Id: $ACME" $G/api/datasources/id/sales-db) (name->id lookup, granted to Viewer upstream too)"
probe /api/datasources/$ID
probe /api/datasources/uid/$DS/health
probe /api/datasources/$ID/health
probe /api/datasources/uid/$DS/resources/scenarios
probe /api/datasources/$ID/resources/scenarios
probe /api/datasources/proxy/uid/$DS/
probe /api/datasources/proxy/$ID/
probe /api/ds/query -X POST -d "$Q"
probe "/api/ds/query?expression=true" -X POST -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS\"},\"scenarioId\":\"random_walk\"},{\"refId\":\"B\",\"datasource\":{\"type\":\"__expr__\",\"uid\":\"__expr__\"},\"type\":\"math\",\"expression\":\"\$A\"}],\"from\":\"now-1h\",\"to\":\"now\"}"
probe /apis/grafana-testdata-datasource.datasource.grafana.app/v0alpha1/namespaces/org-$ACME/datasources/$DS
probe /apis/grafana-testdata-datasource.datasource.grafana.app/v0alpha1/namespaces/org-$ACME/datasources/$DS/health
probe /apis/grafana-testdata-datasource.datasource.grafana.app/v0alpha1/namespaces/org-$ACME/datasources/$DS/query -X POST -d "$Q"
probe /apis/grafana-testdata-datasource.datasource.grafana.app/v0alpha1/namespaces/org-$ACME/datasources/$DS/resource/scenarios
probe /apis/query.grafana.app/v0alpha1/namespaces/org-$ACME/query -X POST -d "{\"queries\":[{\"refId\":\"A\",\"datasource\":{\"type\":\"grafana-testdata-datasource\",\"uid\":\"$DS\"},\"scenarioId\":\"random_walk\"}],\"from\":\"now-1h\",\"to\":\"now\"}"

echo "--- privilege escalation / isolation"
GLOBEX=$(curl -s -u "$A" $G/api/orgs/name/Globex | jq .id)
GDS=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $GLOBEX" -H Content-Type:application/json $G/api/datasources/name/globex-db | jq -r '.uid // empty')
[ -n "$GDS" ] || GDS=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $GLOBEX" -H Content-Type:application/json $G/api/datasources -d '{"name":"globex-db","type":"grafana-testdata-datasource","access":"proxy"}' | jq -r .datasource.uid)
id() { curl -s -u "$A" "$G/api/users/lookup?loginOrEmail=$1" | jq .id; }
TEAM=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" "$G/api/teams/search?name=finance-team" | jq '.teams[0].id // 0')
GTEAM=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $GLOBEX" -H Content-Type:application/json $G/api/teams -d '{"name":"globex-team"}' | jq '.teamId // empty')
[ -n "$GTEAM" ] || GTEAM=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $GLOBEX" "$G/api/teams/search?name=globex-team" | jq '.teams[0].id')
role() { jq -nc --arg u "$1" --arg a "$2" --arg s "$3" '{uid:$u,name:$u,permissions:[{action:$a,scope:$s}]}'; }
# expect <code> <description> <user> <org> curl-args...
expect() {
  local want=$1 desc=$2 who=$3 org=$4; shift 4
  local cred=$A; [ "$who" != admin ] && cred="$who:$(pw $who)"
  local got; got=$(curl -s -o /dev/null -w '%{http_code}' -u "$cred" -H "X-Grafana-Org-Id: $org" -H Content-Type:application/json "$@")
  if [ "$got" = "$want" ]; then echo "ok    $got $desc"; else fail=1; echo "FAIL  $got (want $want) $desc"; fi
}
R=$G/api/access-control
# org admin (alice, Acme) must not grant beyond her own permissions
expect 403 "org admin: role with scope * (dashboards:read)"        alice $ACME -X POST $R/roles -d "$(role e1 dashboards:read '*')"
expect 403 "org admin: role with server-admin action users:create" alice $ACME -X POST $R/roles -d "$(role e2 users:create '')"
expect 403 "org admin: role with orgs:create"                      alice $ACME -X POST $R/roles -d "$(role e3 orgs:create '')"
expect 403 "org admin: role with global users scope"               alice $ACME -X POST $R/roles -d "$(role e4 users:write 'global.users:*')"
expect 403 "org admin: role with provisioning:reload"              alice $ACME -X POST $R/roles -d "$(role e5 provisioning:reload 'provisioners:*')"
expect 200 "org admin: role within her permissions (datasources:*)" alice $ACME -X POST $R/roles -d "$(role ok1 datasources:query 'datasources:*')"
curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" -H Content-Type:application/json -X POST $R/roles -d "$(role adminonly users:create '')" >/dev/null
expect 403 "org admin: update a role to keep users:create"         alice $ACME -X PUT $R/roles/adminonly -d "$(role adminonly users:create '')"
expect 403 "org admin: assign a role with users:create"            alice $ACME -X POST $R/users/$(id carol)/roles -d '{"roleUid":"adminonly"}'
expect 403 "org admin: PUT role set with users:create"             alice $ACME -X PUT $R/users/$(id carol)/roles -d '{"roleUids":["adminonly"]}'
expect 403 "org admin: assign it to a team"                        alice $ACME -X PUT $R/teams/$TEAM/roles -d '{"roleUids":["adminonly"]}'
expect 403 "org admin: provisioning reload"                        alice $ACME -X POST $G/api/admin/provisioning/access-control/reload
# editor / viewer have no role management at all
expect 403 "editor: create role"                                   bob   $ACME -X POST $R/roles -d "$(role e6 dashboards:read 'dashboards:*')"
expect 403 "editor: give himself a role"                           bob   $ACME -X PUT $R/users/$(id bob)/roles -d '{"roleUids":["ok1"]}'
expect 403 "editor: team role change"                              bob   $ACME -X PUT $R/teams/$TEAM/roles -d '{"roleUids":["ok1"]}'
expect 403 "editor: grant himself Admin on a datasource"           bob   $ACME -X POST $R/datasources/$DS/users/$(id bob) -d '{"permission":"Admin"}'
expect 403 "viewer: grant herself Query on a datasource"           carol $ACME -X POST $R/datasources/$DS/users/$(id carol) -d '{"permission":"Query"}'
expect 403 "viewer: list roles"                                    carol $ACME $R/roles
# cross-org isolation (alice is admin in Acme only)
expect 404 "cross-org: Acme admin sets perms on a Globex datasource" alice $ACME -X POST $R/datasources/$GDS/users/$(id carol) -d '{"permission":"Query"}'
expect 404 "cross-org: assign Acme role to a Globex-only user"     alice $ACME -X PUT $R/users/$(id dave)/roles -d '{"roleUids":["ok1"]}'
expect 404 "cross-org: assign Acme role to a Globex team"          alice $ACME -X PUT $R/teams/$GTEAM/roles -d '{"roleUids":["ok1"]}'
expect 403 "cross-org: targetOrgId for a non Grafana admin"        alice $ACME -X PUT "$R/users/$(id carol)/roles?targetOrgId=$GLOBEX" -d '{"roleUids":[]}'
expect 403 "cross-org: switch org header to Globex"                alice $GLOBEX $R/roles
# built-in roles cannot be touched through the custom roles API
MANAGED=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" "$G/api/access-control/user/permissions" >/dev/null; echo eg19nl584m0hse)
expect 404 "admin: delete a managed role via custom API"           admin $ACME -X DELETE $R/roles/$MANAGED
expect 404 "admin: update a fixed role via custom API"             admin 1     -X PUT $R/roles/fixed_oCqNwlVHLOpw7-jAlwp4HzYqwGY -d "$(role x users:create '')"
expect 404 "admin: assign a fixed role to a user"                  admin $ACME -X PUT $R/users/$(id carol)/roles -d '{"roleUids":["fixed_oCqNwlVHLOpw7-jAlwp4HzYqwGY"]}'
# input validation / injection
expect 400 "injection: role name with quotes"                      admin $ACME -X POST $R/roles -d "$(jq -nc '{name:"x'"'"' OR 1=1 --",permissions:[]}')"
expect 400 "injection: bad uid"                                    admin $ACME -X POST $R/roles -d "$(jq -nc '{uid:"../x",name:"x",permissions:[]}')"
expect 400 "injection: invalid scope wildcard"                     admin $ACME -X POST $R/roles -d "$(role x2 dashboards:read 'dash*boards:x')"
expect 400 "injection: non-numeric user id"                        admin $ACME -X PUT "$R/users/1%20OR%201=1/roles" -d '{"roleUids":[]}'
expect 400 "dos: users roles search with 1001 ids"                  admin $ACME -X POST $R/users/roles/search -d "$(jq -nc '{userIds:[range(1001)]}')"
# anonymous
for path in /roles /roles/ok1/assignments /users/1/roles; do
  got=$(curl -s -o /dev/null -w '%{http_code}' "$R$path"); [ "$got" = 401 ] && echo "ok    401 anonymous $path" || { fail=1; echo "FAIL  $got anonymous $path"; }
done
# removing a user from an org drops their custom roles there
curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" -X PUT -H Content-Type:application/json $R/users/$(id carol)/roles -d '{"roleUids":["ok1"]}' >/dev/null
curl -s -u "$A" -X DELETE $G/api/orgs/$ACME/users/$(id carol) >/dev/null
curl -s -u "$A" -X POST -H Content-Type:application/json $G/api/orgs/$ACME/users -d '{"loginOrEmail":"carol","role":"Viewer"}' >/dev/null
left=$(curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" $R/users/$(id carol)/roles | jq length)
[ "$left" = 0 ] && echo "ok    org removal dropped custom roles" || { fail=1; echo "FAIL  carol kept $left custom roles after leaving the org"; }
for r in ok1 adminonly; do curl -s -u "$A" -H "X-Grafana-Org-Id: $ACME" -X DELETE $R/roles/$r >/dev/null; done
[ $fail = 0 ] && echo "PASS: no leaks or escalations" || { echo "FAIL: see FAIL/LEAK lines"; exit 1; }
