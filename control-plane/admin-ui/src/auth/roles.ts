import type { Role } from "../api/types";

export const WRITE_ROLES: Role[] = ["superadmin", "security-reviewer"];
export const APPROVE_ROLES: Role[] = ["superadmin", "approver"];

export function canWrite(role: Role | null): boolean {
  return role !== null && WRITE_ROLES.includes(role);
}

export function canApprove(role: Role | null): boolean {
  return role !== null && APPROVE_ROLES.includes(role);
}
