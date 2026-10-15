import { useState } from 'react';
import { useParams } from 'react-router-dom-v5-compat';
import useAsync from 'react-use/lib/useAsync';

import { t } from '@grafana/i18n';
import { locationService } from '@grafana/runtime';
import { Button, Field, IconButton, Input, Stack, Text } from '@grafana/ui';
import { Page } from 'app/core/components/Page/Page';
import { TeamPicker } from 'app/core/components/Select/TeamPicker';
import { UserPicker } from 'app/core/components/Select/UserPicker';
import { contextSrv } from 'app/core/services/context_srv';

import {
  type RolePermission,
  assignRole,
  createRole,
  getAssignments,
  getRole,
  shortName,
  unassignRole,
  updateRole,
} from './api';

// Fork: create/edit a custom role and manage who it is assigned to.
export default function RoleEditPage() {
  const { uid } = useParams<{ uid?: string }>();
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [description, setDescription] = useState('');
  const [permissions, setPermissions] = useState<RolePermission[]>([{ action: '', scope: '' }]);
  const [reloadAssignments, setReloadAssignments] = useState(0);
  const [userId, setUserId] = useState<number>();
  const [teamId, setTeamId] = useState<number>();
  const canWrite = contextSrv.hasPermission('roles:write');

  const { loading } = useAsync(async () => {
    if (!uid) {
      return;
    }
    const role = await getRole(uid);
    setName(shortName(role.name));
    setDisplayName(role.displayName);
    setDescription(role.description);
    setPermissions(role.permissions.length ? role.permissions : [{ action: '', scope: '' }]);
  }, [uid]);
  const { value: assignments } = useAsync(
    async () => (uid ? getAssignments(uid) : undefined),
    [uid, reloadAssignments]
  );

  const setPermission = (i: number, p: Partial<RolePermission>) =>
    setPermissions((ps) => ps.map((old, j) => (j === i ? { ...old, ...p } : old)));

  const onSave = async () => {
    const role = {
      name,
      displayName,
      description,
      permissions: permissions
        .filter((p) => p.action.trim())
        .map((p) => ({ action: p.action.trim(), scope: p.scope?.trim() })),
    };
    if (uid) {
      await updateRole(uid, role);
    } else {
      await createRole(role);
    }
    locationService.push('/admin/roles');
  };

  const change = async (fn: () => Promise<unknown>) => {
    await fn();
    setReloadAssignments((n) => n + 1);
  };

  return (
    <Page navId="custom-roles" pageNav={{ text: uid ? displayName || name : t('custom-roles.edit.new', 'New role') }}>
      <Page.Contents isLoading={loading}>
        <Stack direction="column" gap={2}>
          <Field
            label={t('custom-roles.edit.name', 'Name')}
            description={t('custom-roles.edit.name-desc', 'Letters, digits, ".", "_", "-" and ":"')}
          >
            <Input value={name} onChange={(e) => setName(e.currentTarget.value)} disabled={!canWrite} width={60} />
          </Field>
          <Field label={t('custom-roles.edit.display-name', 'Display name')}>
            <Input
              value={displayName}
              onChange={(e) => setDisplayName(e.currentTarget.value)}
              disabled={!canWrite}
              width={60}
            />
          </Field>
          <Field label={t('custom-roles.edit.description', 'Description')}>
            <Input
              value={description}
              onChange={(e) => setDescription(e.currentTarget.value)}
              disabled={!canWrite}
              width={60}
            />
          </Field>

          <Text element="h3">{t('custom-roles.edit.permissions', 'Permissions')}</Text>
          <Text color="secondary">
            {t(
              'custom-roles.edit.permissions-help',
              'Action, e.g. dashboards:read, datasources:query; scope, e.g. folders:uid:<uid>, datasources:uid:<uid> or * (empty = any).'
            )}
          </Text>
          {permissions.map((p, i) => (
            <Stack key={i} alignItems="center">
              <Input
                value={p.action}
                placeholder="dashboards:read"
                onChange={(e) => setPermission(i, { action: e.currentTarget.value })}
                disabled={!canWrite}
                width={35}
              />
              <Input
                value={p.scope ?? ''}
                placeholder="folders:uid:*"
                onChange={(e) => setPermission(i, { scope: e.currentTarget.value })}
                disabled={!canWrite}
                width={45}
              />
              {canWrite && (
                <IconButton
                  name="trash-alt"
                  tooltip={t('custom-roles.edit.remove-permission', 'Remove permission')}
                  onClick={() => setPermissions((ps) => ps.filter((_, j) => j !== i))}
                />
              )}
            </Stack>
          ))}
          {canWrite && (
            <Stack>
              <Button
                variant="secondary"
                icon="plus"
                onClick={() => setPermissions((ps) => [...ps, { action: '', scope: '' }])}
              >
                {t('custom-roles.edit.add-permission', 'Add permission')}
              </Button>
              <Button onClick={onSave} disabled={!name.trim()}>
                {t('custom-roles.edit.save', 'Save')}
              </Button>
            </Stack>
          )}

          {uid && assignments && (
            <>
              <Text element="h3">{t('custom-roles.edit.users', 'Users')}</Text>
              {assignments.users.map((u) => (
                <Stack key={u.id} alignItems="center">
                  <Text>{u.name ? `${u.name} (${u.login})` : u.login}</Text>
                  <IconButton
                    name="times"
                    tooltip={t('custom-roles.edit.unassign', 'Remove assignment')}
                    onClick={() => change(() => unassignRole('users', u.id, uid))}
                  />
                </Stack>
              ))}
              <Stack alignItems="center">
                <UserPicker onSelected={(v) => setUserId(v.value?.userId)} />
                <Button
                  variant="secondary"
                  disabled={!userId}
                  onClick={() => change(() => assignRole('users', userId!, uid))}
                >
                  {t('custom-roles.edit.assign', 'Assign')}
                </Button>
              </Stack>

              <Text element="h3">{t('custom-roles.edit.teams', 'Teams')}</Text>
              {assignments.teams.map((tm) => (
                <Stack key={tm.id} alignItems="center">
                  <Text>{tm.name}</Text>
                  <IconButton
                    name="times"
                    tooltip={t('custom-roles.edit.unassign', 'Remove assignment')}
                    onClick={() => change(() => unassignRole('teams', tm.id, uid))}
                  />
                </Stack>
              ))}
              <Stack alignItems="center">
                <TeamPicker onSelected={(v) => setTeamId(v.value?.id)} />
                <Button
                  variant="secondary"
                  disabled={!teamId}
                  onClick={() => change(() => assignRole('teams', teamId!, uid))}
                >
                  {t('custom-roles.edit.assign', 'Assign')}
                </Button>
              </Stack>
            </>
          )}
        </Stack>
      </Page.Contents>
    </Page>
  );
}
