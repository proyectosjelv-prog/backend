// src/config/security/routes.map.ts
import { UserRole } from './roles.config';
import { RequestMethod } from '@nestjs/common';

interface RouteRule {
  path: string;
  method: RequestMethod;
  allowedRoles: UserRole[];
}

export const ACCESS_CONTROL_LIST: RouteRule[] = [
  {
    path: '/users',
    method: RequestMethod.GET,
    allowedRoles: [UserRole.ADMIN, UserRole.SUPER_ADMIN],
  },
  {
    path: '/users',
    method: RequestMethod.DELETE,
    allowedRoles: [UserRole.SUPER_ADMIN],
  },
  {
    path: '/reports/user',
    method: RequestMethod.GET,
    allowedRoles: [UserRole.USER, UserRole.ADMIN, UserRole.SUPER_ADMIN],
  }
];