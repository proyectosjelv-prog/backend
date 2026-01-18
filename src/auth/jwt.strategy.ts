// src/auth/jwt.strategy.ts
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { jwtConstants } from '../config/security/jwt.constants'; // O donde tengas tu secret
import { PrismaService } from '../prisma.service'; // <--- Importa Prisma

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private prisma: PrismaService) { // <--- Inyectamos Prisma
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request) => {
          return request?.cookies?.token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.secret, // Asegúrate de usar tu env o constante
    });
  }

  // Esta función se ejecuta AUTOMÁTICAMENTE en cada petición protegida
  async validate(payload: any) {
    // 1. Buscamos al usuario REAL en la DB usando el ID del token
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub }, // 'sub' es el ID en el token estándar
    });

    // 2. Si el usuario fue eliminado, lanzamos error y bloqueamos el acceso
    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado o eliminado');
    }

    // 3. (Opcional) Si quieres que el cambio de rol sea INMEDIATO:
    // Retornamos el usuario de la DB, que tiene el rol NUEVO (no el del token)
    return { userId: user.id, email: user.email, role: user.role };
  }
}