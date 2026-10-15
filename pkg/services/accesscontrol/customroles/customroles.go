// Package customroles adds org-scoped custom roles (fork addition): roles built from arbitrary
// permissions and assigned to users or teams. They live in the existing role/permission/user_role/team_role
// tables under the "custom:" name prefix, which the OSS permission resolver reads alongside managed roles.
package customroles

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/localcache"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/web"
)

const RolePrefix = "custom:"

const (
	ActionRolesRead        = "roles:read"
	ActionRolesWrite       = "roles:write"
	ActionRolesDelete      = "roles:delete"
	ActionUsersRolesRead   = "users.roles:read"
	ActionUsersRolesAdd    = "users.roles:add"
	ActionUsersRolesRemove = "users.roles:remove"
	ActionTeamsRolesRead   = "teams.roles:read"
	ActionTeamsRolesAdd    = "teams.roles:add"
	ActionTeamsRolesRemove = "teams.roles:remove"
)

var FixedRoles = []ac.RoleRegistration{{
	Role: ac.RoleDTO{
		Name:        "fixed:roles:writer",
		DisplayName: "Custom roles writer",
		Description: "Create, update, delete and assign custom roles.",
		Group:       "Roles",
		Permissions: []ac.Permission{
			{Action: ActionRolesRead}, {Action: ActionRolesWrite}, {Action: ActionRolesDelete},
			{Action: ActionUsersRolesRead}, {Action: ActionUsersRolesAdd}, {Action: ActionUsersRolesRemove},
			{Action: ActionTeamsRolesRead}, {Action: ActionTeamsRolesAdd}, {Action: ActionTeamsRolesRemove},
		},
	},
	Grants: []string{string(org.RoleAdmin), ac.RoleGrafanaAdmin},
}}

var (
	validName       = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,150}$`)
	errNotFound     = errors.New("role not found")
	errConflict     = errors.New("role with this name or uid already exists")
	errNotInOrg     = errors.New("user or team not found in this organization")
	errAlreadyGiven = errors.New("role already assigned")
)

type Permission struct {
	Action string `json:"action"`
	Scope  string `json:"scope,omitempty"`
}

type Role struct {
	UID         string       `json:"uid"`
	Name        string       `json:"name"`
	DisplayName string       `json:"displayName"`
	Description string       `json:"description"`
	Group       string       `json:"group"`
	Version     int64        `json:"version"`
	Permissions []Permission `json:"permissions"`
}

type API struct {
	db    db.DB
	ac    ac.AccessControl
	svc   ac.Service
	cache *localcache.CacheService // acimpl's permission cache; team permissions are cached per team
}

func RegisterAPI(router routing.RouteRegister, sql db.DB, accessControl ac.AccessControl, service ac.Service,
	cache *localcache.CacheService, provisioningDir string) {
	a := &API{db: sql, ac: accessControl, svc: service, cache: cache}
	authorize := ac.Middleware(accessControl)
	router.Post("/api/admin/provisioning/access-control/reload",
		authorize(ac.EvalPermission(ActionProvisioningReload, ScopeProvisionersAccessControl)), routing.Wrap(a.reloadProvisioning(provisioningDir)))
	router.Group("/api/access-control", func(r routing.RouteRegister) {
		r.Get("/roles", authorize(ac.EvalPermission(ActionRolesRead)), routing.Wrap(a.listRoles))
		r.Post("/roles", authorize(ac.EvalPermission(ActionRolesWrite)), routing.Wrap(a.createRole))
		r.Get("/roles/:uid", authorize(ac.EvalPermission(ActionRolesRead)), routing.Wrap(a.getRole))
		r.Put("/roles/:uid", authorize(ac.EvalPermission(ActionRolesWrite)), routing.Wrap(a.updateRole))
		r.Delete("/roles/:uid", authorize(ac.EvalPermission(ActionRolesDelete)), routing.Wrap(a.deleteRole))
		r.Get("/roles/:uid/assignments", authorize(ac.EvalAll(ac.EvalPermission(ActionUsersRolesRead), ac.EvalPermission(ActionTeamsRolesRead))), routing.Wrap(a.getAssignments))

		r.Get("/users/:id/roles", authorize(ac.EvalPermission(ActionUsersRolesRead)), routing.Wrap(a.listAssigned(userTarget)))
		r.Post("/users/:id/roles", authorize(ac.EvalPermission(ActionUsersRolesAdd)), routing.Wrap(a.assign(userTarget)))
		r.Put("/users/:id/roles", authorize(ac.EvalAll(ac.EvalPermission(ActionUsersRolesAdd), ac.EvalPermission(ActionUsersRolesRemove))), routing.Wrap(a.setAssigned(userTarget)))
		r.Delete("/users/:id/roles/:uid", authorize(ac.EvalPermission(ActionUsersRolesRemove)), routing.Wrap(a.unassign(userTarget)))
		r.Post("/users/roles/search", authorize(ac.EvalPermission(ActionUsersRolesRead)), routing.Wrap(a.searchUsersRoles))
		r.Get("/teams/:id/roles", authorize(ac.EvalPermission(ActionTeamsRolesRead)), routing.Wrap(a.listAssigned(teamTarget)))
		r.Post("/teams/:id/roles", authorize(ac.EvalPermission(ActionTeamsRolesAdd)), routing.Wrap(a.assign(teamTarget)))
		r.Put("/teams/:id/roles", authorize(ac.EvalAll(ac.EvalPermission(ActionTeamsRolesAdd), ac.EvalPermission(ActionTeamsRolesRemove))), routing.Wrap(a.setAssigned(teamTarget)))
		r.Delete("/teams/:id/roles/:uid", authorize(ac.EvalPermission(ActionTeamsRolesRemove)), routing.Wrap(a.unassign(teamTarget)))
	})
}

// target describes an assignee kind: the table holding its assignments and how to check it belongs to the org.
type target struct {
	assignTable, idColumn, memberSQL string
}

var (
	userTarget = target{"user_role", "user_id", "SELECT 1 FROM org_user WHERE org_id = ? AND user_id = ?"}
	teamTarget = target{"team_role", "team_id", "SELECT 1 FROM team WHERE org_id = ? AND id = ?"}
)

type saveRoleCmd struct {
	UID         string       `json:"uid"`
	Name        string       `json:"name"`
	DisplayName string       `json:"displayName"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

type assignCmd struct {
	RoleUID string `json:"roleUid"`
}

func (a *API) listRoles(c *contextmodel.ReqContext) response.Response {
	var roles []Role
	err := a.db.WithDbSession(c.Req.Context(), func(sess *db.Session) error {
		var stored []ac.Role
		if err := sess.Where("org_id = ? AND name LIKE ?", c.GetOrgID(), RolePrefix+"%").Asc("name").Find(&stored); err != nil {
			return err
		}
		var err error
		roles, err = toDTOs(sess, stored)
		return err
	})
	if err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to list roles", err)
	}
	if c.QueryBool("delegatable") {
		delegatable := roles[:0]
		for _, r := range roles {
			if a.checkEscalation(c, r.Permissions) == nil {
				delegatable = append(delegatable, r)
			}
		}
		roles = delegatable
	}
	return response.JSON(http.StatusOK, roles)
}

func (a *API) getRole(c *contextmodel.ReqContext) response.Response {
	var out Role
	err := a.db.WithDbSession(c.Req.Context(), func(sess *db.Session) error {
		r, err := getRole(sess, c.GetOrgID(), web.Params(c.Req)[":uid"])
		if err != nil {
			return err
		}
		out, err = toDTO(sess, r)
		return err
	})
	if err != nil {
		return errResponse(err)
	}
	return response.JSON(http.StatusOK, out)
}

func (a *API) createRole(c *contextmodel.ReqContext) response.Response {
	var cmd saveRoleCmd
	if err := web.Bind(c.Req, &cmd); err != nil {
		return response.Error(http.StatusBadRequest, "Bad request data", err)
	}
	if cmd.UID == "" {
		cmd.UID = util.GenerateShortUID()
	}
	if resp := a.validate(c, cmd); resp != nil {
		return resp
	}
	now := time.Now()
	role := ac.Role{OrgID: c.GetOrgID(), Version: 1, UID: cmd.UID, Name: RolePrefix + cmd.Name, DisplayName: cmd.DisplayName,
		Description: cmd.Description, Group: "Custom", Created: now, Updated: now}
	var out Role
	err := a.db.WithTransactionalDbSession(c.Req.Context(), func(sess *db.Session) error {
		exists, err := sess.Table("role").Where("uid = ? OR (org_id = ? AND name = ?)", role.UID, role.OrgID, role.Name).Exist()
		if err != nil {
			return err
		}
		if exists {
			return errConflict
		}
		if _, err := sess.Insert(&role); err != nil {
			return err
		}
		if err := insertPermissions(sess, role.ID, cmd.Permissions, now); err != nil {
			return err
		}
		out, err = toDTO(sess, &role)
		return err
	})
	if err != nil {
		return errResponse(err)
	}
	return response.JSON(http.StatusOK, out)
}

func (a *API) updateRole(c *contextmodel.ReqContext) response.Response {
	var cmd saveRoleCmd
	if err := web.Bind(c.Req, &cmd); err != nil {
		return response.Error(http.StatusBadRequest, "Bad request data", err)
	}
	cmd.UID = web.Params(c.Req)[":uid"]
	if resp := a.validate(c, cmd); resp != nil {
		return resp
	}
	var out Role
	var users, teams []int64
	err := a.db.WithTransactionalDbSession(c.Req.Context(), func(sess *db.Session) error {
		r, err := getRole(sess, c.GetOrgID(), cmd.UID)
		if err != nil {
			return err
		}
		name := RolePrefix + cmd.Name
		if name != r.Name {
			taken, err := sess.Table("role").Where("org_id = ? AND name = ?", r.OrgID, name).Exist()
			if err != nil {
				return err
			}
			if taken {
				return errConflict
			}
		}
		now := time.Now()
		r.Name, r.DisplayName, r.Description, r.Version, r.Updated = name, cmd.DisplayName, cmd.Description, r.Version+1, now
		if _, err := sess.ID(r.ID).Cols("name", "display_name", "description", "version", "updated").Update(r); err != nil {
			return err
		}
		if _, err := sess.Exec("DELETE FROM permission WHERE role_id = ?", r.ID); err != nil {
			return err
		}
		if err := insertPermissions(sess, r.ID, cmd.Permissions, now); err != nil {
			return err
		}
		if users, teams, err = assignees(sess, r.ID); err != nil {
			return err
		}
		out, err = toDTO(sess, r)
		return err
	})
	if err != nil {
		return errResponse(err)
	}
	a.clearCache(c.GetOrgID(), users...)
	a.clearTeams(c.GetOrgID(), teams...)
	return response.JSON(http.StatusOK, out)
}

func (a *API) deleteRole(c *contextmodel.ReqContext) response.Response {
	var users, teams []int64
	err := a.db.WithTransactionalDbSession(c.Req.Context(), func(sess *db.Session) error {
		r, err := getRole(sess, c.GetOrgID(), web.Params(c.Req)[":uid"])
		if err != nil {
			return err
		}
		if users, teams, err = assignees(sess, r.ID); err != nil {
			return err
		}
		for _, q := range []string{"DELETE FROM user_role WHERE role_id = ?", "DELETE FROM team_role WHERE role_id = ?",
			"DELETE FROM permission WHERE role_id = ?", "DELETE FROM role WHERE id = ?"} {
			if _, err := sess.Exec(q, r.ID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return errResponse(err)
	}
	a.clearCache(c.GetOrgID(), users...)
	a.clearTeams(c.GetOrgID(), teams...)
	return response.Success("Role deleted")
}

type assignedUser struct {
	ID    int64  `json:"id" xorm:"id"`
	UID   string `json:"uid" xorm:"uid"`
	Login string `json:"login" xorm:"login"`
	Name  string `json:"name" xorm:"name"`
}

type assignedTeam struct {
	ID   int64  `json:"id" xorm:"id"`
	UID  string `json:"uid" xorm:"uid"`
	Name string `json:"name" xorm:"name"`
}

func (a *API) getAssignments(c *contextmodel.ReqContext) response.Response {
	out := struct {
		Users []assignedUser `json:"users"`
		Teams []assignedTeam `json:"teams"`
	}{Users: []assignedUser{}, Teams: []assignedTeam{}}
	err := a.db.WithDbSession(c.Req.Context(), func(sess *db.Session) error {
		r, err := getRole(sess, c.GetOrgID(), web.Params(c.Req)[":uid"])
		if err != nil {
			return err
		}
		if err := sess.SQL("SELECT u.id, u.uid, u.login, u.name FROM "+a.db.GetDialect().Quote("user")+" AS u"+
			" INNER JOIN user_role AS ur ON ur.user_id = u.id WHERE ur.role_id = ? AND ur.org_id = ? ORDER BY u.login",
			r.ID, r.OrgID).Find(&out.Users); err != nil {
			return err
		}
		return sess.SQL("SELECT t.id, t.uid, t.name FROM team AS t"+
			" INNER JOIN team_role AS tr ON tr.team_id = t.id WHERE tr.role_id = ? AND tr.org_id = ? ORDER BY t.name",
			r.ID, r.OrgID).Find(&out.Teams)
	})
	if err != nil {
		return errResponse(err)
	}
	return response.JSON(http.StatusOK, out)
}

// targetOrg is the org a role-assignment request applies to; only Grafana admins may act on another org.
func targetOrg(c *contextmodel.ReqContext, requested int64) (int64, response.Response) {
	if requested == 0 || requested == c.GetOrgID() {
		return c.GetOrgID(), nil
	}
	if !c.SignedInUser.GetIsGrafanaAdmin() {
		return 0, response.Error(http.StatusForbidden, "Only Grafana admins can manage roles in another organization", nil)
	}
	return requested, nil
}

func assignedRoles(sess *db.Session, t target, orgID, id int64) ([]Role, error) {
	var stored []ac.Role
	if err := sess.SQL("SELECT role.* FROM role INNER JOIN "+t.assignTable+" AS a ON a.role_id = role.id"+
		" WHERE a.org_id = ? AND a."+t.idColumn+" = ? AND role.name LIKE ? ORDER BY role.name",
		orgID, id, RolePrefix+"%").Find(&stored); err != nil {
		return nil, err
	}
	return toDTOs(sess, stored)
}

func (a *API) listAssigned(t target) func(c *contextmodel.ReqContext) response.Response {
	return func(c *contextmodel.ReqContext) response.Response {
		id, err := strconv.ParseInt(web.Params(c.Req)[":id"], 10, 64)
		if err != nil {
			return response.Error(http.StatusBadRequest, "Invalid id", err)
		}
		orgID, resp := targetOrg(c, c.QueryInt64("targetOrgId"))
		if resp != nil {
			return resp
		}
		var roles []Role
		err = a.db.WithDbSession(c.Req.Context(), func(sess *db.Session) error {
			roles, err = assignedRoles(sess, t, orgID, id)
			return err
		})
		if err != nil {
			return response.Error(http.StatusInternalServerError, "Failed to list roles", err)
		}
		return response.JSON(http.StatusOK, roles)
	}
}

type searchUsersRolesCmd struct {
	UserIDs []int64 `json:"userIds"`
	OrgID   int64   `json:"orgId"`
}

// searchUsersRoles returns custom roles per user, as used by the users list role column.
func (a *API) searchUsersRoles(c *contextmodel.ReqContext) response.Response {
	var cmd searchUsersRolesCmd
	if err := web.Bind(c.Req, &cmd); err != nil {
		return response.Error(http.StatusBadRequest, "Bad request data", err)
	}
	orgID, resp := targetOrg(c, cmd.OrgID)
	if resp != nil {
		return resp
	}
	out := make(map[int64][]Role, len(cmd.UserIDs))
	err := a.db.WithDbSession(c.Req.Context(), func(sess *db.Session) error {
		// ponytail: one query per user; fine for paged user lists, batch it if pages grow large
		for _, id := range cmd.UserIDs {
			roles, err := assignedRoles(sess, userTarget, orgID, id)
			if err != nil {
				return err
			}
			out[id] = roles
		}
		return nil
	})
	if err != nil {
		return response.Error(http.StatusInternalServerError, "Failed to search roles", err)
	}
	return response.JSON(http.StatusOK, out)
}

type setRolesCmd struct {
	RoleUIDs []string `json:"roleUids"`
}

// setAssigned replaces the custom roles of a user or team with the given set (role picker semantics).
func (a *API) setAssigned(t target) func(c *contextmodel.ReqContext) response.Response {
	return func(c *contextmodel.ReqContext) response.Response {
		id, err := strconv.ParseInt(web.Params(c.Req)[":id"], 10, 64)
		if err != nil {
			return response.Error(http.StatusBadRequest, "Invalid id", err)
		}
		orgID, resp := targetOrg(c, c.QueryInt64("targetOrgId"))
		if resp != nil {
			return resp
		}
		var cmd setRolesCmd
		if err := web.Bind(c.Req, &cmd); err != nil {
			return response.Error(http.StatusBadRequest, "Bad request data", err)
		}
		err = a.db.WithTransactionalDbSession(c.Req.Context(), func(sess *db.Session) error {
			member, err := sess.SQL(t.memberSQL, orgID, id).Exist()
			if err != nil {
				return err
			}
			if !member {
				return errNotInOrg
			}
			current, err := assignedRoles(sess, t, orgID, id)
			if err != nil {
				return err
			}
			have := map[string]bool{}
			for _, r := range current {
				have[r.UID] = true
			}
			want := map[string]bool{}
			for _, uid := range cmd.RoleUIDs {
				want[uid] = true
				if have[uid] {
					continue
				}
				r, err := getRole(sess, orgID, uid)
				if err != nil {
					return err
				}
				perms, err := rolePermissions(sess, r.ID)
				if err != nil {
					return err
				}
				if resp := a.checkEscalation(c, perms); resp != nil {
					return escalationErr{resp}
				}
				if err := assignOnce(sess, t, orgID, id, r.ID); err != nil {
					return err
				}
			}
			for _, r := range current {
				if want[r.UID] {
					continue
				}
				if _, err := sess.Exec("DELETE FROM "+t.assignTable+" WHERE org_id = ? AND "+t.idColumn+" = ? AND role_id = (SELECT id FROM role WHERE uid = ?)", orgID, id, r.UID); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return errResponse(err)
		}
		a.clearTarget(t, orgID, id)
		return response.Success("Roles updated")
	}
}

func (a *API) assign(t target) func(c *contextmodel.ReqContext) response.Response {
	return func(c *contextmodel.ReqContext) response.Response {
		id, err := strconv.ParseInt(web.Params(c.Req)[":id"], 10, 64)
		if err != nil {
			return response.Error(http.StatusBadRequest, "Invalid id", err)
		}
		var cmd assignCmd
		if err := web.Bind(c.Req, &cmd); err != nil {
			return response.Error(http.StatusBadRequest, "Bad request data", err)
		}
		orgID := c.GetOrgID()
		err = a.db.WithTransactionalDbSession(c.Req.Context(), func(sess *db.Session) error {
			r, err := getRole(sess, orgID, cmd.RoleUID)
			if err != nil {
				return err
			}
			perms, err := rolePermissions(sess, r.ID)
			if err != nil {
				return err
			}
			if resp := a.checkEscalation(c, perms); resp != nil {
				return escalationErr{resp}
			}
			member, err := sess.SQL(t.memberSQL, orgID, id).Exist()
			if err != nil {
				return err
			}
			if !member {
				return errNotInOrg
			}
			given, err := sess.Table(t.assignTable).Where("org_id = ? AND "+t.idColumn+" = ? AND role_id = ?", orgID, id, r.ID).Exist()
			if err != nil {
				return err
			}
			if given {
				return errAlreadyGiven
			}
			_, err = sess.Exec("INSERT INTO "+t.assignTable+" (org_id, "+t.idColumn+", role_id, created) VALUES (?, ?, ?, ?)", orgID, id, r.ID, time.Now())
			return err
		})
		if err != nil {
			return errResponse(err)
		}
		// ponytail: team assignments rely on the 60s team permission cache TTL; clear team members here if that lag matters
		a.clearTarget(t, orgID, id)
		return response.Success("Role assigned")
	}
}

func (a *API) unassign(t target) func(c *contextmodel.ReqContext) response.Response {
	return func(c *contextmodel.ReqContext) response.Response {
		id, err := strconv.ParseInt(web.Params(c.Req)[":id"], 10, 64)
		if err != nil {
			return response.Error(http.StatusBadRequest, "Invalid id", err)
		}
		orgID := c.GetOrgID()
		err = a.db.WithTransactionalDbSession(c.Req.Context(), func(sess *db.Session) error {
			r, err := getRole(sess, orgID, web.Params(c.Req)[":uid"])
			if err != nil {
				return err
			}
			_, err = sess.Exec("DELETE FROM "+t.assignTable+" WHERE org_id = ? AND "+t.idColumn+" = ? AND role_id = ?", orgID, id, r.ID)
			return err
		})
		if err != nil {
			return errResponse(err)
		}
		a.clearTarget(t, orgID, id)
		return response.Success("Role removed")
	}
}

type escalationErr struct{ resp response.Response }

func (e escalationErr) Error() string { return "permission escalation" }

func (a *API) validate(c *contextmodel.ReqContext, cmd saveRoleCmd) response.Response {
	if !validName.MatchString(cmd.Name) {
		return response.Error(http.StatusBadRequest, "Role name must match "+validName.String(), nil)
	}
	if !util.IsValidShortUID(cmd.UID) {
		return response.Error(http.StatusBadRequest, "Invalid role uid", nil)
	}
	for _, p := range cmd.Permissions {
		if p.Action == "" || (p.Scope != "" && !ac.ValidateScope(p.Scope)) {
			return response.Error(http.StatusBadRequest, "Invalid permission: action is required and scope may only end with *", nil)
		}
	}
	return a.checkEscalation(c, cmd.Permissions)
}

// checkEscalation refuses roles granting anything the caller does not hold themselves.
func (a *API) checkEscalation(c *contextmodel.ReqContext, perms []Permission) response.Response {
	for _, p := range perms {
		var scopes []string
		if p.Scope != "" {
			scopes = []string{p.Scope}
		}
		ok, err := a.ac.Evaluate(c.Req.Context(), c.SignedInUser, ac.EvalPermission(p.Action, scopes...))
		if err != nil {
			return response.Error(http.StatusInternalServerError, "Failed to evaluate permissions", err)
		}
		if !ok {
			return response.Error(http.StatusForbidden, "Cannot grant a permission you do not have: "+p.Action+" "+p.Scope, nil)
		}
	}
	return nil
}

func (a *API) clearCache(orgID int64, userIDs ...int64) {
	for _, id := range userIDs {
		a.svc.ClearUserPermissionCache(&user.SignedInUser{OrgID: orgID, UserID: id})
	}
}

func (a *API) clearTeams(orgID int64, teamIDs ...int64) {
	for _, id := range teamIDs {
		a.cache.ExclusiveDelete(ac.GetTeamPermissionCacheKey(id, orgID))
	}
}

func (a *API) clearTarget(t target, orgID, id int64) {
	if t == userTarget {
		a.clearCache(orgID, id)
	} else {
		a.clearTeams(orgID, id)
	}
}

func errResponse(err error) response.Response {
	var esc escalationErr
	switch {
	case errors.As(err, &esc):
		return esc.resp
	case errors.Is(err, errNotFound), errors.Is(err, errNotInOrg):
		return response.Error(http.StatusNotFound, err.Error(), nil)
	case errors.Is(err, errConflict), errors.Is(err, errAlreadyGiven):
		return response.Error(http.StatusConflict, err.Error(), nil)
	}
	return response.Error(http.StatusInternalServerError, "Custom role operation failed", err)
}

func getRole(sess *db.Session, orgID int64, uid string) (*ac.Role, error) {
	var r ac.Role
	has, err := sess.Where("org_id = ? AND uid = ? AND name LIKE ?", orgID, uid, RolePrefix+"%").Get(&r)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, errNotFound
	}
	return &r, nil
}

func rolePermissions(sess *db.Session, roleID int64) ([]Permission, error) {
	var stored []ac.Permission
	if err := sess.Where("role_id = ?", roleID).Asc("action", "scope").Find(&stored); err != nil {
		return nil, err
	}
	out := make([]Permission, 0, len(stored))
	for _, p := range stored {
		out = append(out, Permission{Action: p.Action, Scope: p.Scope})
	}
	return out, nil
}

func toDTO(sess *db.Session, r *ac.Role) (Role, error) {
	perms, err := rolePermissions(sess, r.ID)
	return Role{UID: r.UID, Name: r.Name, DisplayName: r.DisplayName, Description: r.Description, Group: r.Group, Version: r.Version, Permissions: perms}, err
}

func toDTOs(sess *db.Session, stored []ac.Role) ([]Role, error) {
	out := make([]Role, 0, len(stored))
	for i := range stored {
		r, err := toDTO(sess, &stored[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func insertPermissions(sess *db.Session, roleID int64, perms []Permission, now time.Time) error {
	seen := map[Permission]bool{}
	for _, p := range perms {
		if seen[p] {
			continue
		}
		seen[p] = true
		row := ac.Permission{RoleID: roleID, Action: p.Action, Scope: p.Scope, Created: now, Updated: now}
		row.Kind, row.Attribute, row.Identifier = row.SplitScope()
		if _, err := sess.Insert(&row); err != nil {
			return err
		}
	}
	return nil
}

// assignees returns the users and teams a role is directly assigned to.
func assignees(sess *db.Session, roleID int64) (users, teams []int64, err error) {
	if err = sess.Table("user_role").Where("role_id = ?", roleID).Cols("user_id").Find(&users); err != nil {
		return nil, nil, err
	}
	err = sess.Table("team_role").Where("role_id = ?", roleID).Cols("team_id").Find(&teams)
	return users, teams, err
}
