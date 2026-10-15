import { useParams } from 'react-router-dom-v5-compat';

import { Permissions } from 'app/core/components/AccessControl/Permissions';
import { Page } from 'app/core/components/Page/Page';
import { contextSrv } from 'app/core/services/context_srv';

import { useDataSourceSettingsNav } from '../hooks/useDataSourceSettingsNav';

// Fork: per-datasource permissions (Query / Edit / Admin) backed by /api/access-control/datasources/:uid.
export function DataSourcePermissionsPage() {
  const { uid = '' } = useParams<{ uid: string }>();
  const { navId, pageNav } = useDataSourceSettingsNav('permissions');

  return (
    <Page navId={navId} pageNav={pageNav}>
      <Page.Contents>
        <Permissions
          resource="datasources"
          resourceId={uid}
          canSetPermissions={contextSrv.hasPermission('datasources.permissions:write')}
        />
      </Page.Contents>
    </Page>
  );
}
