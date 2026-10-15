package guardian

import (
	"context"

	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
)

var _ DatasourceGuardian = new(rbacGuardian)

// rbacGuardian enforces per-datasource RBAC permissions (fork: replaces the OSS allow-all guardian).
type rbacGuardian struct {
	ac          accesscontrol.AccessControl
	user        identity.Requester
	dataSources []datasources.DataSource
}

func (g *rbacGuardian) can(action, uid string) bool {
	// ponytail: the DatasourceGuardian interface carries no context; thread one through if tracing/cancellation matters
	ok, err := g.ac.Evaluate(context.Background(), g.user, accesscontrol.EvalPermission(action, datasources.ScopeProvider.GetResourceScopeUID(uid)))
	return err == nil && ok
}

func (g *rbacGuardian) CanQuery(datasourceID int64) (bool, error) {
	for _, ds := range g.dataSources {
		if ds.ID == datasourceID {
			return g.can(datasources.ActionQuery, ds.UID), nil
		}
	}
	return false, nil
}

func (g *rbacGuardian) filter(action string, in []*datasources.DataSource) []*datasources.DataSource {
	out := make([]*datasources.DataSource, 0, len(in))
	for _, ds := range in {
		if g.can(action, ds.UID) {
			out = append(out, ds)
		}
	}
	return out
}

func (g *rbacGuardian) FilterDatasourcesByReadPermissions(ds []*datasources.DataSource) ([]*datasources.DataSource, error) {
	return g.filter(datasources.ActionRead, ds), nil
}

func (g *rbacGuardian) FilterDatasourcesByQueryPermissions(ds []*datasources.DataSource) ([]*datasources.DataSource, error) {
	return g.filter(datasources.ActionQuery, ds), nil
}
