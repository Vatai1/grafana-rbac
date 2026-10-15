package customroles

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/db"
	"github.com/grafana/grafana/pkg/tests/testsuite"
	"github.com/grafana/grafana/pkg/util/testutil"
)

func TestMain(m *testing.M) {
	testsuite.Run(m)
}

func TestIntegrationProvision(t *testing.T) {
	testutil.SkipIntegrationTestInShortMode(t)
	sql := db.NewTestStore(t)
	ctx := context.Background()
	now := time.Now()
	require.NoError(t, sql.WithDbSession(ctx, func(sess *db.Session) error {
		if _, err := sess.Exec("INSERT INTO org (id, name, version, created, updated) VALUES (2, 'Acme', 1, ?, ?)", now, now); err != nil {
			return err
		}
		if _, err := sess.Exec("INSERT INTO "+sql.GetDialect().Quote("user")+" (id, uid, login, email, name, org_id, version, is_admin, is_disabled, is_service_account, email_verified, help_flags1, created, updated, last_seen_at) VALUES (10, 'carol', 'carol', 'carol@x', 'carol', 2, 0, false, false, false, false, 0, ?, ?, ?)", now, now, now); err != nil {
			return err
		}
		_, err := sess.Exec("INSERT INTO org_user (org_id, user_id, role, created, updated) VALUES (2, 10, 'Viewer', ?, ?)", now, now)
		return err
	}))

	dir := t.TempDir()
	write := func(body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "roles.yaml"), []byte(body), 0o600))
	}
	count := func(q string, args ...any) int64 {
		var n int64
		require.NoError(t, sql.WithDbSession(ctx, func(sess *db.Session) error {
			_, err := sess.SQL(q, args...).Get(&n)
			return err
		}))
		return n
	}

	write(`
apiVersion: 2
roles:
  - uid: dsreader
    name: ds-reader
    orgName: Acme
    permissions:
      - {action: "datasources:query", scope: "datasources:*"}
users:
  - {login: carol, orgName: Acme, roles: [{uid: dsreader}]}
`)
	for range 2 { // applying twice must not duplicate anything
		changed, failed := Provision(ctx, sql, dir)
		require.Zero(t, failed)
		require.Equal(t, []int64{10}, changed[2])
	}
	require.EqualValues(t, 1, count("SELECT COUNT(*) FROM role WHERE uid = 'dsreader' AND org_id = 2 AND name = 'custom:ds-reader'"))
	require.EqualValues(t, 1, count("SELECT COUNT(*) FROM permission p INNER JOIN role r ON r.id = p.role_id WHERE r.uid = 'dsreader'"))
	require.EqualValues(t, 1, count("SELECT COUNT(*) FROM user_role WHERE user_id = 10 AND org_id = 2"))

	write("apiVersion: 2\nroles:\n  - {uid: dsreader, name: ds-reader, orgName: Acme, state: absent}\n")
	_, failed := Provision(ctx, sql, dir)
	require.Zero(t, failed)
	require.EqualValues(t, 0, count("SELECT COUNT(*) FROM role WHERE uid = 'dsreader'"))
	require.EqualValues(t, 0, count("SELECT COUNT(*) FROM user_role WHERE user_id = 10"))

	write("apiVersion: 2\nrolez: typo\n")
	_, failed = Provision(ctx, sql, dir)
	require.Equal(t, 1, failed, "unknown fields must be reported")
}
