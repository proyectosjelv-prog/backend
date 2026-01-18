import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PrismaService } from '../prisma.service';
import { EmailModule } from '../email/email.module';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { jwtConstants } from '../config/security/jwt.constants';

@Module({
  imports: [
    EmailModule,
    // Usamos registerAsync para esperar a que cargue el archivo .env
    JwtModule.registerAsync({
      useFactory: async (configService: ConfigService) => ({
        global: true,
      secret: jwtConstants.secret, // <--- 2. Aquí usamos tu secreto
      imports: [ConfigModule],
        signOptions: { expiresIn: '1h' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, JwtStrategy],
})
export class AuthModule {}