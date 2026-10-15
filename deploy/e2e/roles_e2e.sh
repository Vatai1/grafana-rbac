#!/usr/bin/env bash
# e2e: custom roles end to end (plan steps 3-5): a role granted to a user or a team really opens a folder,
# and unassigning / deleting it closes it again. API edge cases are covered by customroles/api_test.go.
. "$(dirname "$0")/lib.sh"
ACME=$(curl -s -u "$A" $G/api/orgs/name/Acme | jq .id)
GLOBEX=$(curl -s -u "$A" $G/api/orgs/name/Globex | jq .id)
adm() { local o=$1; shift; curl -s -u "$A" -H Content-Type:application/json -H "X-Grafana-Org-Id: $o" "$@"; }
R=$G/api/access-control
FIN=$(adm $ACME $G/api/folders | jq -r '.[]|select(.title=="Finance").uid')
finance() { curl -s -o /dev/null -w '%{http_code}' -u "carol:$(pw carol)" -H "X-Grafana-Org-Id: $ACME" $G/api/folders/$FIN; }
C=$(id carol)
TEAM=$(adm $ACME $G/api/teams -d '{"name":"e2e-team"}' | jq -r '.teamId // empty')
[ -n "$TEAM" ] || TEAM=$(adm $ACME "$G/api/teams/search?name=e2e-team" | jq '.teams[0].id')
adm $ACME -X DELETE $R/roles/e2e-fin >/dev/null
adm $ACME -X DELETE $G/api/teams/$TEAM/members/$C >/dev/null

eventually "carol cannot open Finance without a role" 403 finance
ROLE=$(jq -nc --arg f "folders:uid:$FIN" '{uid:"e2e-fin",name:"e2e-finance-reader",permissions:[{action:"folders:read",scope:$f},{action:"dashboards:read",scope:$f}]}')
check "create role" '"custom:e2e-finance-reader"' "$(adm $ACME $R/roles -d "$ROLE" | jq -c .name)"

adm $ACME $R/users/$C/roles -d '{"roleUid":"e2e-fin"}' >/dev/null
eventually "role on carol opens Finance" 200 finance
adm $ACME -X DELETE $R/users/$C/roles/e2e-fin >/dev/null
eventually "unassigned role closes Finance" 403 finance

adm $ACME $G/api/teams/$TEAM/members -d "{\"userId\":$C}" >/dev/null
adm $ACME -X PUT $R/teams/$TEAM/roles -d '{"roleUids":["e2e-fin"]}' >/dev/null
eventually "role on carol's team opens Finance" 200 finance
check "role assignments list the team" '["e2e-team"]' "$(adm $ACME $R/roles/e2e-fin/assignments | jq -c '[.teams[].name]')"
adm $ACME -X PUT $R/teams/$TEAM/roles -d '{"roleUids":[]}' >/dev/null
eventually "role removed from the team closes Finance" 403 finance

adm $ACME -X PUT $R/users/$C/roles -d '{"roleUids":["e2e-fin"]}' >/dev/null
check "PUT replaces the role set" '["e2e-fin"]' "$(adm $ACME $R/users/$C/roles | jq -c '[.[].uid]')"
check "search returns roles per user" '["e2e-fin"]' "$(adm $ACME $R/users/roles/search -d "{\"userIds\":[$C]}" | jq -c ".\"$C\" | map(.uid)")"
eventually "PUT-assigned role opens Finance" 200 finance
adm $ACME -X DELETE $R/roles/e2e-fin >/dev/null
eventually "deleted role closes Finance" 403 finance
check "deleted role leaves no assignments" '[]' "$(adm $ACME $R/users/$C/roles | jq -c '[.[].uid]')"

# YAML provisioning (deploy/provisioning/access-control/roles.yaml): globex-ds-reader on dave
adm $GLOBEX -X POST $G/api/admin/provisioning/access-control/reload >/dev/null
check "YAML role assigned to dave" '["globex-ds-reader"]' "$(adm $GLOBEX $R/users/$(id dave)/roles | jq -c '[.[].uid]')"

adm $ACME -X DELETE $G/api/teams/$TEAM >/dev/null
finish
