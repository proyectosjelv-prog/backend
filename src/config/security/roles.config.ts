// src/config/security/roles.config.ts

export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
  SUPER_ADMIN = 'SUPER_ADMIN',
}

export const ROLE_HIERARCHY = {
  [UserRole.SUPER_ADMIN]: 3,
  [UserRole.ADMIN]: 2,
  [UserRole.USER]: 1,
};