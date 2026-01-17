// src/auth/auth.service.ts
import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { EmailService } from '../email/email.service';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { UserRole } from '../config/security/roles.config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private emailService: EmailService,
    private jwtService: JwtService,
    private configService: ConfigService, // Inyectar config
  ) {}

  async register(registerDto: RegisterAuthDto) {
    const userExists = await this.prisma.user.findUnique({
      where: { email: registerDto.email },
    });

    if (userExists) {
      throw new BadRequestException('El correo ya está registrado');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(registerDto.password, salt);

    const verificationToken = uuidv4();

    const newUser = await this.prisma.user.create({
      data: {
        username: registerDto.username,
        email: registerDto.email,
        password: hashedPassword,
        role: 'USER',
        isVerified: false,
        verificationToken: verificationToken, 
      },
    });
    await this.emailService.sendVerificationEmail(newUser.email, verificationToken);

    return {
      message: 'Usuario registrado exitosamente. Por favor verifica tu email.',
      userId: newUser.id,
    };
  }

  async verifyUser(token: string) {
    const user = await this.prisma.user.findFirst({
      where: { verificationToken: token },
    });

    if (!user) {
      throw new BadRequestException('Token inválido o expirado');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
        verificationToken: null,
      },
    });

    return { message: '¡Cuenta verificada con éxito! Ya puedes iniciar sesión.' };
  }

  async login(loginDto: { email: string; password: string }) {
    const user = await this.prisma.user.findUnique({
      where: { email: loginDto.email },
    });

    if (!user) {
      throw new BadRequestException('Credenciales inválidas (Email)');
    }

    if (!user.isVerified) {
      throw new BadRequestException('Debes verificar tu correo antes de entrar');
    }

    const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);

    if (!isPasswordValid) {
      throw new BadRequestException('Credenciales inválidas (Password)');
    }

    const payload = { sub: user.id, email: user.email, role: user.role };
    
    return {
      access_token: await this.jwtService.signAsync(payload),
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    };
  }

  async deleteUser(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: id },
    });

    if (!user) {
      throw new BadRequestException('El usuario no existe');
    }

    await this.prisma.user.delete({
      where: { id: id },
    });

    return { message: `Usuario ${user.email} eliminado correctamente.` };
  }

  
  async getProfile(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    };
  }
  // NUEVO: Solicitar cambio de contraseña (envía correo)
  async requestPasswordReset(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new BadRequestException('Si el correo existe, se envió un enlace.');

    // Usamos el mismo campo verificationToken o creamos uno nuevo específico
    const resetToken = uuidv4();
    
    await this.prisma.user.update({
      where: { email },
      data: { verificationToken: resetToken } // Reusamos este campo temporalmente
    });

    // Ojo: Deberías crear un método sendResetPasswordEmail en emailService similar al de verificación
    // Por ahora simularemos que usa el mismo canal
    const frontendUrl = this.configService.get('FRONTEND_URL');
    const link = `${frontendUrl}/change-password?token=${resetToken}`;
    
    console.log(`LINK DE RECUPERACIÓN (Enviar por email): ${link}`);
    // await this.emailService.sendRecoveryEmail(email, link); // Implementar esto en EmailService

    return { message: 'Correo de recuperación enviado.' };
  }

  // NUEVO: Cambiar la contraseña usando el token
  async changePassword(token: string, newPassword: string) {
    const user = await this.prisma.user.findFirst({
      where: { verificationToken: token },
    });

    if (!user) throw new BadRequestException('Token inválido o expirado');

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        verificationToken: null, // Quemamos el token para que no se use de nuevo
      },
    });

    return { message: 'Contraseña actualizada correctamente. Inicia sesión.' };
  }
  
  async changeUserRole(userId: number, newRole: UserRole) {
    // Opcional: Validar que el rol exista
    if (!Object.values(UserRole).includes(newRole)) {
        throw new BadRequestException('El rol especificado no es válido');
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new BadRequestException('Usuario no encontrado');

    await this.prisma.user.update({
      where: { id: userId },
      data: { role: newRole },
    });

    return { message: `El rol del usuario ${user.email} ahora es ${newRole}` };
  }
}