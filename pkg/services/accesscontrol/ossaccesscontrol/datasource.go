package ossaccesscontrol

import (
	"context"

	"github.com/grafana/grafana/pkg/api/routing"
	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/accesscontrol/resourcepermissions"
	"github.com/grafana/grafana/pkg/services/apiserver"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/licensing"
	"github.com/grafana/grafana/pkg/services/team"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"go.opentelemetry.io/otel"
)

var tracer = otel.Tracer("github.com/grafana/grafana/pkg/accesscontrol/ossaccesscontrol")

// DatasourceQueryActions contains permissions to read information
// about a data source and submit arbitrary queries to it.
var DatasourceQueryActions = []string{
	datasources.ActionRead,
	datasources.ActionQuery,
}

var DatasourceEditActions = append(DatasourceQueryActions, datasources.ActionWrite, datasources.ActionDelete)
var DatasourceAdminActions = append(DatasourceEditActions, datasources.ActionPermissionsRead, datasources.ActionPermissionsWrite)

const datasourcePermissionsRoleGroup = "Data sources"

var _ accesscontrol.DatasourcePermissionsService = new(DatasourcePermissionsService)

type DatasourcePermissionsService struct {
	*resourcepermissions.Service
}

func ProvideDatasourcePermissionsService(
	cfg *setting.Cfg, features featuremgmt.FeatureToggles, router routing.RouteRegister, sql db.DB, ac accesscontrol.AccessControl,
	license licensing.Licensing, service accesscontrol.Service, teamService team.Service, userService user.Service,
	actionSetService resourcepermissions.ActionSetService, restConfigProvider apiserver.DirectRestConfigProvider,
) (*DatasourcePermissionsService, error) {
	options := resourcepermissions.Options{
		Resource:          datasources.ScopeRoot,
		ResourceAttribute: "uid",
		// Queried directly: the datasource service depends on this service, so injecting it here would be a cycle.
		// WithDbSession reuses the caller's transaction, so this also sees a datasource being created in it.
		ResourceValidator: func(ctx context.Context, orgID int64, resourceID string) error {
			return sql.WithDbSession(ctx, func(sess *db.Session) error {
				ok, err := sess.Table("data_source").Where("org_id = ? AND uid = ?", orgID, resourceID).Exist()
				if err != nil {
					return err
				}
				if !ok {
					return datasources.ErrDataSourceNotFound
				}
				return nil
			})
		},
		Assignments: resourcepermissions.Assignments{
			Users:           true,
			Teams:           true,
			BuiltInRoles:    true,
			ServiceAccounts: true,
		},
		PermissionsToActions: map[string][]string{
			"Query": DatasourceQueryActions,
			"Edit":  DatasourceEditActions,
			"Admin": DatasourceAdminActions,
		},
		ReaderRoleName:     permissionReaderRoleName,
		WriterRoleName:     permissionWriterRoleName,
		RoleGroup:          datasourcePermissionsRoleGroup,
		RestConfigProvider: restConfigProvider,
	}
	srv, err := resourcepermissions.New(cfg, options, features, router, license, ac, service, sql, teamService, userService, actionSetService)
	if err != nil {
		return nil, err
	}
	return &DatasourcePermissionsService{srv}, nil
}
