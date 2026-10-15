package customroles_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/accesscontrol/actest"
	"github.com/grafana/grafana/pkg/services/accesscontrol/customroles"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util/testutil"
	"github.com/grafana/grafana/pkg/web/webtest"
)

const (
	acme, globex     = int64(2), int64(3)
	carol, dave      = int64(11), int64(12) // carol is in Acme, dave only in Globex
	acmeTeam, gxTeam = int64(20), int64(21)
)

// roleAdminPerms can manage roles and holds a few resource permissions it may delegate.
var roleAdminPerms = map[string][]string{
	customroles.ActionRolesRead: {}, customroles.ActionRolesWrite: {}, customroles.ActionRolesDelete: {},
	customroles.ActionUsersRolesRead: {}, customroles.ActionUsersRolesAdd: {}, customroles.ActionUsersRolesRemove: {},
	customroles.ActionTeamsRolesRead: {}, customroles.ActionTeamsRolesAdd: {}, customroles.ActionTeamsRolesRemove: {},
	"datasources:query": {"datasources:*"},
	"folders:read":      {"folders:*"},
}

type apiClient struct {
	t      *testing.T
	server *webtest.Server
}

func (c apiClient) do(usr *user.SignedInUser, method, url string, body any) (int, []byte) {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(c.t, err)
		r = bytes.NewReader(b)
	}
	req := c.server.NewRequest(method, url, r)
	req.Header.Set("Content-Type", "application/json")
	webtest.RequestWithSignedInUser(req, usr)
	res, err := c.server.Send(req)
	require.NoError(c.t, err)
	defer func() { require.NoError(c.t, res.Body.Close()) }()
	out, err := io.ReadAll(res.Body)
	require.NoError(c.t, err)
	return res.StatusCode, out
}

func setupAPI(t *testing.T) (apiClient, db.DB) {
	t.Helper()
	sql := db.NewTestStore(t)
	now := time.Now()
	userTable := sql.GetDialect().Quote("user")
	require.NoError(t, sql.WithDbSession(context.Background(), func(sess *db.Session) error {
		stmts := [][]any{
			{"INSERT INTO org (id, name, version, created, updated) VALUES (?, 'Acme', 1, ?, ?)", acme, now, now},
			{"INSERT INTO org (id, name, version, created, updated) VALUES (?, 'Globex', 1, ?, ?)", globex, now, now},
			{"INSERT INTO team (id, uid, name, org_id, created, updated) VALUES (?, 'acme-team', 'acme-team', ?, ?, ?)", acmeTeam, acme, now, now},
			{"INSERT INTO team (id, uid, name, org_id, created, updated) VALUES (?, 'gx-team', 'gx-team', ?, ?, ?)", gxTeam, globex, now, now},
			{"INSERT INTO org_user (org_id, user_id, role, created, updated) VALUES (?, ?, 'Viewer', ?, ?)", acme, carol, now, now},
			{"INSERT INTO org_user (org_id, user_id, role, created, updated) VALUES (?, ?, 'Viewer', ?, ?)", globex, dave, now, now},
			// a built-in role that must stay out of reach of this API
			{"INSERT INTO role (org_id, version, uid, name, created, updated) VALUES (?, 1, 'managed-uid', 'managed:users:11:permissions', ?, ?)", acme, now, now},
		}
		for _, u := range []struct {
			id    int64
			login string
		}{{carol, "carol"}, {dave, "dave"}} {
			stmts = append(stmts, []any{"INSERT INTO " + userTable +
				" (id, uid, login, email, name, org_id, version, is_admin, is_disabled, is_service_account, email_verified, help_flags1, created, updated, last_seen_at)" +
				" VALUES (?, ?, ?, ?, ?, ?, 0, false, false, false, false, 0, ?, ?, ?)", u.id, u.login, u.login, u.login + "@x", u.login, acme, now, now, now})
		}
		for _, s := range stmts {
			if _, err := sess.Exec(s...); err != nil {
				return fmt.Errorf("%s: %w", s[0], err)
			}
		}
		return nil
	}))
	router := routing.NewRouteRegister()
	customroles.RegisterAPI(router, sql, acimpl.ProvideAccessControlTest(), actest.FakeService{}, localcache.New(time.Minute, time.Minute), t.TempDir())
	return apiClient{t: t, server: webtest.NewServer(t, router)}, sql
}

func signedIn(orgID int64, perms map[string][]string) *user.SignedInUser {
	return &user.SignedInUser{UserID: 1, OrgID: orgID, Permissions: map[int64]map[string][]string{orgID: perms}}
}

func uids(t *testing.T, body []byte) []string {
	t.Helper()
	var roles []customroles.Role
	require.NoError(t, json.Unmarshal(body, &roles))
	out := []string{}
	for _, r := range roles {
		out = append(out, r.UID)
	}
	return out
}

func TestIntegrationCustomRolesAPI(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)
	c, sql := setupAPI(t)
	admin := signedIn(acme, roleAdminPerms)
	viewer := signedIn(acme, map[string][]string{"folders:read": {"folders:uid:x"}})
	reader := map[string]any{"uid": "reader", "name": "ds-reader", "permissions": []customroles.Permission{{Action: "datasources:query", Scope: "datasources:uid:abc"}}}

	t.Run("only role managers can create roles", func(t *testing.T) {
		code, _ := c.do(viewer, http.MethodPost, "/api/access-control/roles", reader)
		require.Equal(t, http.StatusForbidden, code)
		code, body := c.do(admin, http.MethodPost, "/api/access-control/roles", reader)
		require.Equal(t, http.StatusOK, code, string(body))
		var r customroles.Role
		require.NoError(t, json.Unmarshal(body, &r))
		require.Equal(t, "custom:ds-reader", r.Name)
		code, _ = c.do(admin, http.MethodPost, "/api/access-control/roles", reader)
		require.Equal(t, http.StatusConflict, code, "duplicate uid/name")
	})

	t.Run("cannot grant permissions the caller lacks", func(t *testing.T) {
		for _, p := range []customroles.Permission{
			{Action: "users:create"},                           // action not held at all
			{Action: "datasources:query", Scope: "*"},          // broader scope than datasources:*
			{Action: "dashboards:read", Scope: "dashboards:*"}, // not held
		} {
			code, _ := c.do(admin, http.MethodPost, "/api/access-control/roles",
				map[string]any{"name": "esc", "permissions": []customroles.Permission{p}})
			require.Equal(t, http.StatusForbidden, code, "%+v", p)
		}
	})

	t.Run("input is validated", func(t *testing.T) {
		for _, body := range []map[string]any{
			{"name": "bad name!"},
			{"uid": "../x", "name": "x"},
			{"name": "x", "permissions": []customroles.Permission{{Action: "dashboards:read", Scope: "dash*boards"}}},
			{"name": "x", "permissions": []customroles.Permission{{Scope: "folders:*"}}},
		} {
			code, _ := c.do(admin, http.MethodPost, "/api/access-control/roles", body)
			require.Equal(t, http.StatusBadRequest, code, "%v", body)
		}
	})

	// a role the org admin may not delegate, created by someone holding users:create
	superAdmin := signedIn(acme, map[string][]string{customroles.ActionRolesWrite: {}, "users:create": {}})
	code, body := c.do(superAdmin, http.MethodPost, "/api/access-control/roles",
		map[string]any{"uid": "adminonly", "name": "adminonly", "permissions": []customroles.Permission{{Action: "users:create"}}})
	require.Equal(t, http.StatusOK, code, string(body))

	t.Run("delegatable hides roles beyond the caller's permissions", func(t *testing.T) {
		_, body := c.do(admin, http.MethodGet, "/api/access-control/roles", nil)
		require.ElementsMatch(t, []string{"reader", "adminonly"}, uids(t, body))
		_, body = c.do(admin, http.MethodGet, "/api/access-control/roles?delegatable=true", nil)
		require.Equal(t, []string{"reader"}, uids(t, body))
	})

	t.Run("assign, replace and remove roles of a user", func(t *testing.T) {
		code, _ := c.do(admin, http.MethodPost, fmt.Sprintf("/api/access-control/users/%d/roles", carol), map[string]string{"roleUid": "reader"})
		require.Equal(t, http.StatusOK, code)
		_, body := c.do(admin, http.MethodGet, fmt.Sprintf("/api/access-control/users/%d/roles", carol), nil)
		require.Equal(t, []string{"reader"}, uids(t, body))

		code, _ = c.do(admin, http.MethodPut, fmt.Sprintf("/api/access-control/users/%d/roles", carol), map[string]any{"roleUids": []string{"adminonly"}})
		require.Equal(t, http.StatusForbidden, code, "replacing with a non-delegatable role")
		code, _ = c.do(admin, http.MethodPut, fmt.Sprintf("/api/access-control/users/%d/roles", carol), map[string]any{"roleUids": []string{}})
		require.Equal(t, http.StatusOK, code)
		_, body = c.do(admin, http.MethodGet, fmt.Sprintf("/api/access-control/users/%d/roles", carol), nil)
		require.Empty(t, uids(t, body))
	})

	t.Run("teams, assignments listing and search", func(t *testing.T) {
		code, _ := c.do(admin, http.MethodPut, fmt.Sprintf("/api/access-control/teams/%d/roles", acmeTeam), map[string]any{"roleUids": []string{"reader"}})
		require.Equal(t, http.StatusOK, code)
		code, _ = c.do(admin, http.MethodPost, fmt.Sprintf("/api/access-control/users/%d/roles", carol), map[string]string{"roleUid": "reader"})
		require.Equal(t, http.StatusOK, code)
		_, body := c.do(admin, http.MethodGet, "/api/access-control/roles/reader/assignments", nil)
		var a struct {
			Users []struct{ Login string } `json:"users"`
			Teams []struct{ ID int64 }     `json:"teams"`
		}
		require.NoError(t, json.Unmarshal(body, &a))
		require.Len(t, a.Users, 1)
		require.Equal(t, "carol", a.Users[0].Login)
		require.Len(t, a.Teams, 1)
		require.Equal(t, acmeTeam, a.Teams[0].ID)

		_, body = c.do(admin, http.MethodPost, "/api/access-control/users/roles/search", map[string]any{"userIds": []int64{carol}})
		var byUser map[string][]customroles.Role
		require.NoError(t, json.Unmarshal(body, &byUser))
		require.Len(t, byUser[fmt.Sprint(carol)], 1)

		code, _ = c.do(admin, http.MethodPost, "/api/access-control/users/roles/search", map[string]any{"userIds": make([]int64, 1001)})
		require.Equal(t, http.StatusBadRequest, code, "search is capped")
	})

	t.Run("organizations are isolated", func(t *testing.T) {
		code, _ := c.do(admin, http.MethodPut, fmt.Sprintf("/api/access-control/users/%d/roles", dave), map[string]any{"roleUids": []string{"reader"}})
		require.Equal(t, http.StatusNotFound, code, "user from another org")
		code, _ = c.do(admin, http.MethodPut, fmt.Sprintf("/api/access-control/teams/%d/roles", gxTeam), map[string]any{"roleUids": []string{"reader"}})
		require.Equal(t, http.StatusNotFound, code, "team from another org")

		globexAdmin := signedIn(globex, roleAdminPerms)
		code, _ = c.do(globexAdmin, http.MethodGet, "/api/access-control/roles/reader", nil)
		require.Equal(t, http.StatusNotFound, code, "role from another org")
		code, _ = c.do(globexAdmin, http.MethodDelete, "/api/access-control/roles/reader", nil)
		require.Equal(t, http.StatusNotFound, code)

		code, _ = c.do(admin, http.MethodGet, fmt.Sprintf("/api/access-control/users/%d/roles?targetOrgId=%d", dave, globex), nil)
		require.Equal(t, http.StatusForbidden, code, "targetOrgId needs a Grafana admin")
		serverAdmin := signedIn(acme, roleAdminPerms)
		serverAdmin.IsGrafanaAdmin = true
		code, _ = c.do(serverAdmin, http.MethodGet, fmt.Sprintf("/api/access-control/users/%d/roles?targetOrgId=%d", dave, globex), nil)
		require.Equal(t, http.StatusOK, code)
	})

	t.Run("built-in roles are out of reach", func(t *testing.T) {
		code, _ := c.do(admin, http.MethodGet, "/api/access-control/roles/managed-uid", nil)
		require.Equal(t, http.StatusNotFound, code)
		code, _ = c.do(admin, http.MethodDelete, "/api/access-control/roles/managed-uid", nil)
		require.Equal(t, http.StatusNotFound, code)
		code, _ = c.do(admin, http.MethodPut, fmt.Sprintf("/api/access-control/users/%d/roles", carol), map[string]any{"roleUids": []string{"managed-uid"}})
		require.Equal(t, http.StatusNotFound, code)
	})

	t.Run("deleting a role removes its assignments", func(t *testing.T) {
		code, _ := c.do(admin, http.MethodDelete, "/api/access-control/roles/reader", nil)
		require.Equal(t, http.StatusOK, code)
		var n int64
		require.NoError(t, sql.WithDbSession(context.Background(), func(sess *db.Session) error {
			_, err := sess.SQL("SELECT (SELECT COUNT(*) FROM user_role) + (SELECT COUNT(*) FROM team_role)" +
				" + (SELECT COUNT(*) FROM permission p INNER JOIN role r ON r.id = p.role_id WHERE r.uid = 'reader')").Get(&n)
			return err
		}))
		require.Zero(t, n)
	})
}
