package guardian

import (
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/datasources"
)

type DatasourceGuardianProvider interface {
	New(orgID int64, user identity.Requester, dataSources ...datasources.DataSource) DatasourceGuardian
}

type DatasourceGuardian interface {
	CanQuery(datasourceID int64) (bool, error)
	FilterDatasourcesByReadPermissions([]*datasources.DataSource) ([]*datasources.DataSource, error)
	FilterDatasourcesByQueryPermissions([]*datasources.DataSource) ([]*datasources.DataSource, error)
}

func ProvideGuardian(ac accesscontrol.AccessControl) *OSSProvider {
	return &OSSProvider{ac: ac}
}

type OSSProvider struct {
	ac accesscontrol.AccessControl
}

func (p *OSSProvider) New(orgID int64, user identity.Requester, dataSources ...datasources.DataSource) DatasourceGuardian {
	return &rbacGuardian{ac: p.ac, user: user, dataSources: dataSources}
}
