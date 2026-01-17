// src/auth/guards/roles.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY, IS_STRICT_KEY } from '../decorators/roles.decorator';
import { UserRole, ROLE_HIERARCHY } from '../../config/security/roles.config';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const isStrict = this.reflector.getAllAndOverride<boolean>(IS_STRICT_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    
    if (!user || !user.role) return false; 
    
    const userRole = user.role as UserRole;

    if (isStrict) {
      return requiredRoles.includes(userRole);
    }

    const userLevel = ROLE_HIERARCHY[userRole] || 0;

    const hasPermission = requiredRoles.some((requiredRole) => {
      const requiredLevel = ROLE_HIERARCHY[requiredRole] || 0;
      return userLevel >= requiredLevel;
    });

    return hasPermission;
  }
}