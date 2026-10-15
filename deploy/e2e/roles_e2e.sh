#!/usr/bin/env bash
# e2e check for plan step 3 (custom roles API)
P=$(dirname "$0")/pw.txt
pw() { grep "user $1 " "$P" | awk '{print $NF}'; }
G=localhost:3001
ACME=$(curl -s -u admin:${GF_ADMIN_PASSWORD:-admin} $G/api/orgs/name/Acme | jq .id)
GLOBEX=$(curl -s -u admin:${GF_ADMIN_PASSWORD:-admin} $G/api/orgs/name/Globex | jq .id)
as() { local u=$1 o=$2; shift 2; local cred="admin:${GF_ADMIN_PASSWORD:-admin}"; [ "$u" != admin ] && cred="$u:$(pw $u)"; curl -s -u "$cred" -H Content-Type:application/json -H "X-Grafana-Org-Id: $o" "$@"; }
code() { as "$@" -o /dev/null -w '%{http_code}'; }
id() { curl -s -u admin:${GF_ADMIN_PASSWORD:-admin} "$G/api/users/lookup?loginOrEmail=$1" | jq .id; }
sees() { echo "Finance=$(code $1 $ACME $G/api/folders/$FIN)"; }
FIN=$(as admin $ACME $G/api/folders | jq -r '.[]|select(.title=="Finance").uid')
as admin $ACME -X DELETE $G/api/access-control/roles/finreader >/dev/null
echo "carol before: $(sees carol)"
ROLE=$(jq -nc --arg f "folders:uid:$FIN" '{uid:"finreader",name:"finance-reader",permissions:[{action:"folders:read",scope:$f},{action:"dashboards:read",scope:$f}]}')
echo "create role: $(as admin $ACME $G/api/access-control/roles -d "$ROLE" | jq -c '{uid,name,n:(.permissions|length)}')"
echo "assign carol: $(as admin $ACME $G/api/access-control/users/$(id carol)/roles -d '{"roleUid":"finreader"}' | jq -c .)"
echo "carol roles: $(as admin $ACME $G/api/access-control/users/$(id carol)/roles | jq -c '[.[].name]')"
echo "carol with role: $(sees carol)"
echo "unassign: $(as admin $ACME -X DELETE $G/api/access-control/users/$(id carol)/roles/finreader | jq -c .)"
echo "carol after unassign: $(sees carol)"
echo "viewer creates role: $(code carol $ACME $G/api/access-control/roles -d '{"name":"x","permissions":[]}')"
echo "org admin escalation (users:create): $(code alice $ACME $G/api/access-control/roles -d '{"name":"esc","permissions":[{"action":"users:create"}]}')"
AROLE=$(jq -nc --arg f "folders:uid:$FIN" '{uid:"alicerole",name:"alice-role",permissions:[{action:"folders:read",scope:$f}]}')
echo "org admin creates allowed role: $(code alice $ACME $G/api/access-control/roles -d "$AROLE")"
echo "cross-org get (Globex): $(code admin $GLOBEX $G/api/access-control/roles/finreader)"
echo "cross-org assign dave (not in Acme): $(code admin $ACME $G/api/access-control/users/$(id dave)/roles -d '{"roleUid":"finreader"}')"
TEAM=$(as admin $ACME $G/api/teams -d '{"name":"finance-team"}' | jq -r '.teamId // empty'); [ -n "$TEAM" ] || TEAM=$(as admin $ACME "$G/api/teams/search?name=finance-team" | jq '.teams[0].id')
as admin $ACME $G/api/teams/$TEAM/members -d "{\"userId\":$(id carol)}" >/dev/null
echo "assign team: $(as admin $ACME $G/api/access-control/teams/$TEAM/roles -d '{"roleUid":"finreader"}' | jq -c .)"
as carol $ACME "$G/api/access-control/user/permissions?reloadcache=true" >/dev/null
echo "carol via team: $(sees carol)"
as admin $ACME -X DELETE $G/api/access-control/roles/alicerole >/dev/null
# role picker endpoints (PUT replaces the set, search feeds the users table)
echo "put carol [finreader]: $(as admin $ACME -X PUT $G/api/access-control/users/$(id carol)/roles -d '{"roleUids":["finreader"]}' | jq -c .) -> $(as admin $ACME $G/api/access-control/users/$(id carol)/roles | jq -c '[.[].uid]')"
SEARCH=$(jq -nc --argjson c "$(id carol)" --argjson b "$(id bob)" --argjson o "$ACME" '{userIds:[$c,$b],orgId:$o}')
echo "search users roles: $(as admin $ACME $G/api/access-control/users/roles/search -d "$SEARCH" | jq -c 'map_values([.[].uid])')"
echo "assignments: $(as admin $ACME $G/api/access-control/roles/finreader/assignments | jq -c '{users:[.users[].login],teams:[.teams[].name]}')"
echo "put carol []: $(as admin $ACME -X PUT $G/api/access-control/users/$(id carol)/roles -d '{"roleUids":[]}' | jq -c .) -> $(as admin $ACME $G/api/access-control/users/$(id carol)/roles | jq -c '[.[].uid]')"
ESC=$(jq -nc '{uid:"escrole",name:"esc-role",permissions:[{action:"users:create"}]}')
as admin $ACME $G/api/access-control/roles -d "$ESC" >/dev/null
echo "alice delegatable sees escrole: $(as alice $ACME "$G/api/access-control/roles?delegatable=true" | jq -c '[.[].uid] | index("escrole") != null')"
echo "alice PUT escrole to carol (escalation): $(code alice $ACME -X PUT $G/api/access-control/users/$(id carol)/roles -d '{"roleUids":["escrole"]}')"
echo "alice targetOrgId=Globex: $(code alice $ACME "$G/api/access-control/users/$(id carol)/roles?targetOrgId=$GLOBEX")"
as admin $ACME -X DELETE $G/api/access-control/roles/escrole >/dev/null
echo "delete role: $(as admin $ACME -X DELETE $G/api/access-control/roles/finreader | jq -c .)"
as carol $ACME "$G/api/access-control/user/permissions?reloadcache=true" >/dev/null
echo "carol after role deleted: $(sees carol)"
