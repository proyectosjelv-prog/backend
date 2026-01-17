// src/auth/decorators/roles.decorator.ts
import { SetMetadata, applyDecorators } from '@nestjs/common';
import { UserRole } from '../../config/security/roles.config';
export const ROLES_KEY = 'roles';
export const IS_STRICT_KEY = 'isStrict';
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
export const StrictRoles = (...roles: UserRole[]) => {
  return applyDecorators(
    SetMetadata(ROLES_KEY, roles),
    SetMetadata(IS_STRICT_KEY, true),
  );
};