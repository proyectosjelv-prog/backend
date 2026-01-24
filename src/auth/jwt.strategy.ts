// backend/src/auth/jwt.strategy.ts
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { jwtConstants } from '../config/security/jwt.constants';
import { PrismaService } from '../prisma.service'; // <--- 1. Importante

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  // 2. Inyectamos Prisma en el constructor
  constructor(private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request) => {
          return request?.cookies?.token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.secret,
    });
  }

  // 3. Esta función valida CADA petición
  async validate(payload: any) {
    // Buscamos al usuario en la DB fresca
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    // Si lo borraste de la DB, esto da error y bloquea el acceso
    if (!user) {
      throw new UnauthorizedException('Usuario eliminado o no encontrado');
    }

    // Retornamos el rol REAL de la base de datos, no el del token viejo
    return {
      userId: user.id, 
      email: user.email,
      role: user.role,
      username: user.username,
  };
  }
}