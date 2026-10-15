import { useMemo, useState } from 'react';
import useAsync from 'react-use/lib/useAsync';

import { t } from '@grafana/i18n';
import { ConfirmModal, EmptyState, IconButton, InteractiveTable, LinkButton, Stack, TextLink } from '@grafana/ui';
import { Page } from 'app/core/components/Page/Page';
import { contextSrv } from 'app/core/services/context_srv';

import { type CustomRole, deleteRole, listRoles, shortName } from './api';

// Fork: Administration → Users and access → Roles.
export default function RolesListPage() {
  const [reload, setReload] = useState(0);
  const [toDelete, setToDelete] = useState<CustomRole>();
  const { value: roles = [], loading } = useAsync(listRoles, [reload]);
  const canWrite = contextSrv.hasPermission('roles:write');
  const canDelete = contextSrv.hasPermission('roles:delete');

  const columns = useMemo(
    () => [
      {
        id: 'name',
        header: t('custom-roles.list.name', 'Name'),
        cell: ({ row: { original } }: { row: { original: CustomRole } }) => (
          <TextLink href={`/admin/roles/edit/${original.uid}`} inline={false}>
            {original.displayName || shortName(original.name)}
          </TextLink>
        ),
      },
      { id: 'description', header: t('custom-roles.list.description', 'Description') },
      {
        id: 'permissions',
        header: t('custom-roles.list.permissions', 'Permissions'),
        cell: ({ row: { original } }: { row: { original: CustomRole } }) => original.permissions.length,
      },
      {
        id: 'actions',
        header: '',
        cell: ({ row: { original } }: { row: { original: CustomRole } }) =>
          canDelete && (
            <IconButton
              name="trash-alt"
              tooltip={t('custom-roles.list.delete', 'Delete role')}
              onClick={() => setToDelete(original)}
            />
          ),
      },
    ],
    [canDelete]
  );

  return (
    <Page
      navId="custom-roles"
      actions={
        canWrite && (
          <LinkButton href="/admin/roles/new" icon="plus">
            {t('custom-roles.list.new', 'New role')}
          </LinkButton>
        )
      }
    >
      <Page.Contents isLoading={loading}>
        {roles.length === 0 ? (
          <EmptyState variant="call-to-action" message={t('custom-roles.list.empty', 'No custom roles yet')} />
        ) : (
          <Stack direction="column">
            <InteractiveTable columns={columns} data={roles} getRowId={(r) => r.uid} />
          </Stack>
        )}
        <ConfirmModal
          isOpen={!!toDelete}
          title={t('custom-roles.list.delete', 'Delete role')}
          body={t('custom-roles.list.delete-body', 'The role will be removed from all users and teams.')}
          confirmText={t('custom-roles.list.delete-confirm', 'Delete')}
          onConfirm={async () => {
            await deleteRole(toDelete!.uid);
            setToDelete(undefined);
            setReload((r) => r + 1);
          }}
          onDismiss={() => setToDelete(undefined)}
        />
      </Page.Contents>
    </Page>
  );
}
