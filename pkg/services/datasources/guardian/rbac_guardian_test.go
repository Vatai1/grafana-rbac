package guardian

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/services/accesscontrol/acimpl"
	"github.com/grafana/grafana/pkg/services/datasources"
	"github.com/grafana/grafana/pkg/services/user"
)

func TestRBACGuardian(t *testing.T) {
	a := datasources.DataSource{ID: 1, UID: "a"}
	b := datasources.DataSource{ID: 2, UID: "b"}
	usr := &user.SignedInUser{OrgID: 1, Permissions: map[int64]map[string][]string{1: {
		datasources.ActionQuery: {"datasources:uid:a"},
		datasources.ActionRead:  {"datasources:uid:a", "datasources:uid:b"},
	}}}
	p := ProvideGuardian(acimpl.ProvideAccessControlTest())

	ok, err := p.New(1, usr, a).CanQuery(1)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = p.New(1, usr, b).CanQuery(2)
	require.NoError(t, err)
	require.False(t, ok, "no query permission on b")

	ok, _ = p.New(1, usr, a).CanQuery(2)
	require.False(t, ok, "unknown datasource id must be denied")

	g := p.New(1, usr)
	q, _ := g.FilterDatasourcesByQueryPermissions([]*datasources.DataSource{&a, &b})
	require.Equal(t, []*datasources.DataSource{&a}, q)
	r, _ := g.FilterDatasourcesByReadPermissions([]*datasources.DataSource{&a, &b})
	require.Len(t, r, 2)
}
