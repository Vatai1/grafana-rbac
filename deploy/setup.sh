#!/usr/bin/env bash
# Syncs access.json into Grafana. Re-run after every edit; safe to repeat.
#   workspace = Grafana org (users never see orgs they are not in)
#   users     = login -> org role (Admin|Editor|Viewer)
#   folders   = folder -> {login: View|Edit|Admin}; ONLY listed users see it (org Admins see all)
#   datasources = datasource -> {login | team:<name> | role:Viewer|Editor: Query|Edit|Admin}; ONLY listed ones can use it
# Users from access.json are removed from orgs they're no longer listed in.
# Users not in access.json (e.g. admin) are never touched.
set -euo pipefail
G=${GRAFANA_URL:-http://localhost:3001}
AUTH=admin:${GF_ADMIN_PASSWORD:-admin}
CFG=${1:-access.json}

get() { curl -s ${CURL_FLAGS:-} -u "$AUTH" ${2:+-H "X-Grafana-Org-Id: $2"} "$G$1"; }
api() { # method path [json] [orgId]
  curl -s ${CURL_FLAGS:-} --fail-with-body -u "$AUTH" -X "$1" -H 'Content-Type: application/json' \
    ${4:+-H "X-Grafana-Org-Id: $4"} "$G$2" ${3:+-d "$3"}
}
uri() { jq -rn --arg s "$1" '$s|@uri'; }
org_id() { get "/api/orgs/name/$(uri "$1")" | jq -r '.id // empty'; }

# 1. users: create missing ones with a random password, collect login -> id
ids='{}'
while read -r login; do
  id=$(get "/api/users/lookup?loginOrEmail=$(uri "$login")" | jq -r '.id // empty')
  if [ -z "$id" ]; then
    pw=$(openssl rand -base64 15)
    id=$(api POST /api/admin/users "$(jq -nc --arg l "$login" --arg p "$pw" '{login:$l,name:$l,password:$p}')" | jq -r .id)
    echo "created user $login  password: $pw"
  fi
  ids=$(jq -c --arg l "$login" --argjson id "$id" '.[$l]=$id' <<<"$ids")
done < <(jq -r '[.workspaces[].users | keys[]] | unique[]' "$CFG")

# 2. workspaces: make sure each org exists
while read -r ws; do
  [ -n "$(org_id "$ws")" ] || api POST /api/orgs "$(jq -nc --arg n "$ws" '{name:$n}')" >/dev/null
done < <(jq -r '.workspaces | keys[]' "$CFG")

# 3. memberships: in every org, add/update/remove managed users (add first so nobody ends up org-less)
while read -r oid name; do
  members=$(get "/api/orgs/$oid/users")
  while read -r login id; do
    want=$(jq -r --arg ws "$name" --arg l "$login" '.workspaces[$ws].users[$l] // empty' "$CFG")
    have=$(jq -r --arg l "$login" '.[] | select(.login==$l) | .role' <<<"$members")
    if [ -n "$want" ] && [ -z "$have" ]; then
      api POST "/api/orgs/$oid/users" "$(jq -nc --arg l "$login" --arg r "$want" '{loginOrEmail:$l,role:$r}')" >/dev/null
    elif [ -n "$want" ] && [ "$want" != "$have" ]; then
      api PATCH "/api/orgs/$oid/users/$id" "{\"role\":\"$want\"}" >/dev/null
    elif [ -z "$want" ] && [ -n "$have" ]; then
      api DELETE "/api/orgs/$oid/users/$id" >/dev/null
    fi
  done < <(jq -r 'to_entries[] | "\(.key) \(.value)"' <<<"$ids")
done < <(get /api/orgs | jq -r 'sort_by(.name != "Main Org.") | reverse[] | "\(.id) \(.name)"')

# 4. folders: create missing, then REPLACE permissions (drops default "all Viewers/Editors" access)
while read -r ws; do
  oid=$(org_id "$ws")
  while read -r f; do
    [ -n "$f" ] || continue
    fuid=$(get "/api/folders?limit=1000" "$oid" | jq -r --arg t "$f" '.[] | select(.title==$t) | .uid' | head -1)
    [ -n "$fuid" ] || fuid=$(api POST /api/folders "$(jq -nc --arg t "$f" '{title:$t}')" "$oid" | jq -r .uid)
    body=$(jq -c --arg ws "$ws" --arg f "$f" --argjson ids "$ids" \
      '{items: [.workspaces[$ws].folders[$f] | to_entries[] | {userId: $ids[.key], permission: {View:1,Edit:2,Admin:4}[.value]}]}' "$CFG")
    api POST "/api/folders/$fuid/permissions" "$body" "$oid" >/dev/null
  done < <(jq -r --arg ws "$ws" '.workspaces[$ws].folders // {} | keys[]' "$CFG")
done < <(jq -r '.workspaces | keys[]' "$CFG")

# 5. datasources: {name: {subject: Query|Edit|Admin}}, subject = login | team:<name> | role:Viewer|Editor.
#    Listed subjects get exactly that level; every other directly granted (managed) access is removed.
#    Org Admins always keep access; access coming from custom roles is managed by the roles themselves.
subject() { # orgId subject -> JSON permission target, empty if unknown
  case $2 in
    role:*) jq -nc --arg r "${2#role:}" '{builtInRole:$r}' ;;
    team:*) get "/api/teams/search?name=$(uri "${2#team:}")" "$1" | jq -c '.teams[0].id // empty | {teamId:.}' ;;
    *)      get "/api/users/lookup?loginOrEmail=$(uri "$2")" | jq -c '.id // empty | {userId:.}' ;;
  esac
}
while read -r ws; do
  oid=$(org_id "$ws")
  while read -r ds; do
    [ -n "$ds" ] || continue
    duid=$(get "/api/datasources/name/$(uri "$ds")" "$oid" | jq -r '.uid // empty')
    if [ -z "$duid" ]; then echo "skip datasource $ws/$ds: not found" >&2; continue; fi
    want='[]'
    while IFS=$'\t' read -r subj level; do
      t=$(subject "$oid" "$subj")
      if [ -z "$t" ]; then echo "skip $ws/$ds subject $subj: not found" >&2; continue; fi
      want=$(jq -c --argjson t "$t" --arg l "$level" '. + [$t + {permission:$l}]' <<<"$want")
    done < <(jq -r --arg ws "$ws" --arg ds "$ds" '.workspaces[$ws].datasources[$ds] | to_entries[] | "\(.key)\t\(.value)"' "$CFG")
    # revoke managed grants that are not wanted (basic role Admin is left alone)
    body=$(get "/api/access-control/datasources/$duid" "$oid" | jq -c --argjson want "$want" '
      [.[] | select(.isManaged) | select(.builtInRole != "Admin")
       | if .userId then {userId} elif .teamId then {teamId} else {builtInRole} end] | unique
      | map(select(. as $c | $want | map(del(.permission)) | index($c) | not) + {permission:""})
      | {permissions: (. + $want)}')
    api POST "/api/access-control/datasources/$duid" "$body" "$oid" >/dev/null
  done < <(jq -r --arg ws "$ws" '.workspaces[$ws].datasources // {} | keys[]' "$CFG")
done < <(jq -r '.workspaces | keys[]' "$CFG")

# 6. custom roles from provisioning/access-control/*.yaml (re-applied now that users and orgs exist)
api POST /api/admin/provisioning/access-control/reload >/dev/null
echo "done"
