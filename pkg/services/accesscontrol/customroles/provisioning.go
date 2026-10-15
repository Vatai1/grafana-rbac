package customroles

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/infra/log"
	ac "github.com/grafana/grafana/pkg/services/accesscontrol"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/util"
)

const (
	ActionProvisioningReload       = "provisioning:reload"
	ScopeProvisionersAccessControl = "provisioners:accesscontrol"
)

var logger = log.New("customroles.provisioning")

// File is the provisioning/access-control/*.yaml format. roles and teams follow Grafana Enterprise;
// users and orgName are fork extensions.
type File struct {
	APIVersion int64        `yaml:"apiVersion"`
	Roles      []RoleConfig `yaml:"roles"`
	Teams      []AssignTo   `yaml:"teams"`
	Users      []AssignTo   `yaml:"users"`
}

type RoleConfig struct {
	UID         string       `yaml:"uid"`
	Name        string       `yaml:"name"`
	DisplayName string       `yaml:"displayName"`
	Description string       `yaml:"description"`
	Version     int64        `yaml:"version"`
	Global      bool         `yaml:"global"`
	OrgID       int64        `yaml:"orgId"`
	OrgName     string       `yaml:"orgName"`
	Permissions []Permission `yaml:"permissions"`
	State       string       `yaml:"state"`
}

type AssignTo struct {
	Name    string    `yaml:"name"`  // team name
	Login   string    `yaml:"login"` // user login
	OrgID   int64     `yaml:"orgId"`
	OrgName string    `yaml:"orgName"`
	Roles   []RoleRef `yaml:"roles"`
}

type RoleRef struct {
	UID    string `yaml:"uid"`
	Name   string `yaml:"name"`
	Global bool   `yaml:"global"`
	State  string `yaml:"state"`
}

// Provision applies every *.yaml/*.yml file in dir. Invalid files and references to missing
// orgs/users/teams are logged and skipped so one bad entry never blocks startup.
// It returns the users (per org) whose direct assignments changed, and how many entries failed.
func Provision(ctx context.Context, sql db.DB, dir string) (changedUsers map[int64][]int64, failed int) {
	changedUsers = map[int64][]int64{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.Error("Cannot read access-control provisioning directory", "path", dir, "error", err)
			failed++
		}
		return changedUsers, failed
	}
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		var f File
		raw, err := os.ReadFile(path)
		if err == nil {
			dec := yaml.NewDecoder(bytes.NewReader(raw))
			dec.KnownFields(true)
			err = dec.Decode(&f)
		}
		if err != nil {
			logger.Error("Invalid access-control provisioning file", "file", path, "error", err)
			failed++
			continue
		}
		failed += applyFile(ctx, sql, path, &f, changedUsers)
	}
	return changedUsers, failed
}

func applyFile(ctx context.Context, sql db.DB, path string, f *File, changedUsers map[int64][]int64) (failed int) {
	fail := func(msg string, err error, kv ...any) {
		logger.Error(msg, append([]any{"file", path, "error", err}, kv...)...)
		failed++
	}
	for _, rc := range f.Roles {
		err := sql.WithTransactionalDbSession(ctx, func(sess *db.Session) error {
			orgID, err := resolveOrg(sess, rc.OrgID, rc.OrgName)
			if err != nil {
				return err
			}
			return provisionRole(sess, orgID, rc)
		})
		if err != nil {
			fail("Failed to provision role", err, "role", rc.Name, "uid", rc.UID)
		}
	}
	for _, t := range []target{teamTarget, userTarget} {
		entries := f.Teams
		if t == userTarget {
			entries = f.Users
		}
		for _, a := range entries {
			var orgID, id int64
			err := sql.WithTransactionalDbSession(ctx, func(sess *db.Session) error {
				var err error
				if orgID, err = resolveOrg(sess, a.OrgID, a.OrgName); err != nil {
					return err
				}
				if id, err = resolveAssignee(sess, t, orgID, a); err != nil {
					return err
				}
				for _, ref := range a.Roles {
					r, err := findRole(sess, orgID, ref.UID, ref.Name)
					if err != nil {
						return err
					}
					if ref.State == "absent" {
						_, err = sess.Exec("DELETE FROM "+t.assignTable+" WHERE org_id = ? AND "+t.idColumn+" = ? AND role_id = ?", orgID, id, r.ID)
					} else {
						err = assignOnce(sess, t, orgID, id, r.ID)
					}
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				fail("Failed to provision role assignment", err, "team", a.Name, "login", a.Login)
				continue
			}
			if t == userTarget {
				changedUsers[orgID] = append(changedUsers[orgID], id)
			}
		}
	}
	return failed
}

func provisionRole(sess *db.Session, orgID int64, rc RoleConfig) error {
	name := RolePrefix + strings.TrimPrefix(rc.Name, RolePrefix)
	existing, err := findRole(sess, orgID, rc.UID, name)
	if err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	if rc.State == "absent" {
		if existing == nil {
			return nil
		}
		for _, q := range []string{"DELETE FROM user_role WHERE role_id = ?", "DELETE FROM team_role WHERE role_id = ?",
			"DELETE FROM permission WHERE role_id = ?", "DELETE FROM role WHERE id = ?"} {
			if _, err := sess.Exec(q, existing.ID); err != nil {
				return err
			}
		}
		return nil
	}
	if !validName.MatchString(strings.TrimPrefix(name, RolePrefix)) {
		return fmt.Errorf("invalid role name %q", rc.Name)
	}
	for _, p := range rc.Permissions {
		if p.Action == "" || (p.Scope != "" && !ac.ValidateScope(p.Scope)) {
			return fmt.Errorf("role %q: invalid permission %q %q", rc.Name, p.Action, p.Scope)
		}
	}
	now := time.Now()
	if existing == nil {
		uid := rc.UID
		if uid == "" {
			uid = util.GenerateShortUID()
		}
		if !util.IsValidShortUID(uid) {
			return fmt.Errorf("invalid role uid %q", uid)
		}
		if taken, err := sess.Table("role").Where("uid = ?", uid).Exist(); err != nil || taken {
			if err != nil {
				return err
			}
			return fmt.Errorf("role uid %q is already used by another org or role", uid)
		}
		existing = &ac.Role{OrgID: orgID, Version: 1, UID: uid, Name: name, DisplayName: rc.DisplayName,
			Description: rc.Description, Group: "Custom", Created: now, Updated: now}
		if _, err := sess.Insert(existing); err != nil {
			return err
		}
	} else {
		existing.Name, existing.DisplayName, existing.Description, existing.Version, existing.Updated = name, rc.DisplayName, rc.Description, existing.Version+1, now
		if _, err := sess.ID(existing.ID).Cols("name", "display_name", "description", "version", "updated").Update(existing); err != nil {
			return err
		}
		if _, err := sess.Exec("DELETE FROM permission WHERE role_id = ?", existing.ID); err != nil {
			return err
		}
	}
	return insertPermissions(sess, existing.ID, rc.Permissions, now)
}

func resolveOrg(sess *db.Session, orgID int64, orgName string) (int64, error) {
	if orgName != "" {
		var id int64
		found, err := sess.Table("org").Where("name = ?", orgName).Cols("id").Get(&id)
		if err != nil {
			return 0, err
		}
		if !found {
			return 0, fmt.Errorf("org %q not found", orgName)
		}
		return id, nil
	}
	if orgID == 0 {
		orgID = 1
	}
	found, err := sess.Table("org").Where("id = ?", orgID).Exist()
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("org %d not found", orgID)
	}
	return orgID, nil
}

func resolveAssignee(sess *db.Session, t target, orgID int64, a AssignTo) (int64, error) {
	var id int64
	var found bool
	var err error
	if t == teamTarget {
		found, err = sess.Table("team").Where("org_id = ? AND name = ?", orgID, a.Name).Cols("id").Get(&id)
	} else {
		found, err = sess.Table("user").Where("login = ?", a.Login).Cols("id").Get(&id)
		if err == nil && found {
			found, err = sess.SQL(t.memberSQL, orgID, id).Exist()
		}
	}
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("%w: team %q / user %q in org %d", errNotInOrg, a.Name, a.Login, orgID)
	}
	return id, nil
}

// findRole looks a custom role up by uid, or by name when uid is empty.
func findRole(sess *db.Session, orgID int64, uid, name string) (*ac.Role, error) {
	if uid != "" {
		return getRole(sess, orgID, uid)
	}
	var r ac.Role
	has, err := sess.Where("org_id = ? AND name = ?", orgID, RolePrefix+strings.TrimPrefix(name, RolePrefix)).Get(&r)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, fmt.Errorf("%w: %s", errNotFound, name)
	}
	return &r, nil
}

func assignOnce(sess *db.Session, t target, orgID, id, roleID int64) error {
	given, err := sess.Table(t.assignTable).Where("org_id = ? AND "+t.idColumn+" = ? AND role_id = ?", orgID, id, roleID).Exist()
	if err != nil || given {
		return err
	}
	_, err = sess.Exec("INSERT INTO "+t.assignTable+" (org_id, "+t.idColumn+", role_id, created) VALUES (?, ?, ?, ?)", orgID, id, roleID, time.Now())
	return err
}

func (a *API) reloadProvisioning(dir string) func(c *contextmodel.ReqContext) response.Response {
	return func(c *contextmodel.ReqContext) response.Response {
		changed, failed := Provision(c.Req.Context(), a.db, dir)
		for orgID, ids := range changed {
			a.clearCache(orgID, ids...)
		}
		if failed > 0 {
			return response.Error(http.StatusBadRequest, fmt.Sprintf("%d access-control provisioning entries failed, see server log", failed), nil)
		}
		return response.Success("Access control provisioning reloaded")
	}
}
