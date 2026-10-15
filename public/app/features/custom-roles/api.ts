import { getBackendSrv } from '@grafana/runtime';

// Fork: client for the custom roles API (pkg/services/accesscontrol/customroles).

export const ROLE_PREFIX = 'custom:';

export interface RolePermission {
  action: string;
  scope?: string;
}

export interface CustomRole {
  uid: string;
  name: string;
  displayName: string;
  description: string;
  version: number;
  permissions: RolePermission[];
}

export interface RoleAssignments {
  users: Array<{ id: number; uid: string; login: string; name: string }>;
  teams: Array<{ id: number; uid: string; name: string }>;
}

export type RoleInput = Pick<CustomRole, 'displayName' | 'description' | 'permissions'> & { name: string };

const base = '/api/access-control';

export const shortName = (name: string) => (name.startsWith(ROLE_PREFIX) ? name.slice(ROLE_PREFIX.length) : name);

export const listRoles = (): Promise<CustomRole[]> => getBackendSrv().get(`${base}/roles`);
export const getRole = (uid: string): Promise<CustomRole> => getBackendSrv().get(`${base}/roles/${uid}`);
export const createRole = (role: RoleInput): Promise<CustomRole> => getBackendSrv().post(`${base}/roles`, role);
export const updateRole = (uid: string, role: RoleInput): Promise<CustomRole> =>
  getBackendSrv().put(`${base}/roles/${uid}`, role);
export const deleteRole = (uid: string) => getBackendSrv().delete(`${base}/roles/${uid}`);

export const getAssignments = (uid: string): Promise<RoleAssignments> =>
  getBackendSrv().get(`${base}/roles/${uid}/assignments`);
export const assignRole = (kind: 'users' | 'teams', id: number, roleUid: string) =>
  getBackendSrv().post(`${base}/${kind}/${id}/roles`, { roleUid });
export const unassignRole = (kind: 'users' | 'teams', id: number, roleUid: string) =>
  getBackendSrv().delete(`${base}/${kind}/${id}/roles/${roleUid}`);
