// src/auth/auth.service.ts
import { Injectable, BadRequestException, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { EmailService } from '../email/email.service';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { UserRole } from '../config/security/roles.config';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private emailService: EmailService,
    private jwtService: JwtService,
    private configService: ConfigService, // Inyectar config
  ) {}

  // --- MÉTODO PRIVADO PARA GENERAR TOKENS ---
  private async generateTokens(userId: number, email: string, role: string) {
    const payload = { sub: userId, email, role };

    const [accessToken, refreshToken] = await Promise.all([
      // Access Token: Dura poco (ej. 15 min)
      this.jwtService.signAsync(payload, { 
        secret: this.configService.get('JWT_SECRET'),
        expiresIn: '15m' 
      }),
      // Refresh Token: Dura mucho (ej. 7 días)
      this.jwtService.signAsync(payload, { 
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: '7d' 
      }),
    ]);

    return { accessToken, refreshToken };
  }

  // --- MÉTODO PRIVADO PARA GUARDAR REFRESH TOKEN ---
  private async saveRefreshToken(userId: number, token: string) {
    // Calculamos fecha de expiración (7 días desde hoy)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.prisma.refreshToken.create({
      data: {
        token, // En prod idealmente guardarías el hash del token
        userId,
        expiresAt,
      },
    });
  }

  async refreshTokens(refreshToken: string, res: Response) {
    // 1. Buscamos el token en la base de datos
    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });

    // 2. Validaciones de seguridad extremas
    if (!storedToken) {
      throw new UnauthorizedException('Token inválido (No existe en DB)');
    }
    if (storedToken.revoked) {
      // Si el token estaba revocado y se intenta usar, ¡es un robo de sesión!
      // Medida de seguridad: revocar TODO de ese usuario
      await this.prisma.refreshToken.updateMany({
        where: { userId: storedToken.userId },
        data: { revoked: true },
      });
      throw new UnauthorizedException('Intento de reuso de token revocado. Sesión bloqueada.');
    }
    if (new Date() > storedToken.expiresAt) {
      throw new UnauthorizedException('Sesión expirada. Por favor inicia sesión de nuevo.');
    }

    // 3. Verificar firma criptográfica (JWT)
    try {
      await this.jwtService.verifyAsync(refreshToken, {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
      });
    } catch (e) {
      throw new UnauthorizedException('Token corrupto o firma inválida');
    }

    // 4. Rotación de Tokens (Seguridad clave)
    // Revocamos el token actual (ya se usó) y creamos uno nuevo
    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { revoked: true },
    });

    // Generamos el nuevo par
    const { accessToken, refreshToken: newRefreshToken } = await this.generateTokens(
      storedToken.userId,
      storedToken.user.email,
      storedToken.user.role,
    );

    // Guardamos el nuevo refresh token
    await this.saveRefreshToken(storedToken.userId, newRefreshToken);

    // 5. Seteamos las Cookies frescas
    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000, // 15 min
      path: '/', // <--- ¡AGREGA ESTO AQUÍ TAMBIÉN! 🔑
    });

    res.cookie('refresh_token', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
      path: '/auth/refresh',
    });

    return { message: 'Sesión renovada exitosamente' };
  }
  
  // Obtener estado (Público, para saber si mostrar el formulario)
  async getRegistrationStatus() {
    const config = await this.prisma.systemConfig.findUnique({
      where: { key: 'REGISTRATION_ENABLED' },
    });
    // Si no existe configuración, asumimos que está ABIERTO por defecto
    return { enabled: config ? config.value === 'true' : true };
  }

  // Cambiar estado (Solo Admin)
  async toggleRegistration(enable: boolean) {
    await this.prisma.systemConfig.upsert({
      where: { key: 'REGISTRATION_ENABLED' },
      update: { value: String(enable) },
      create: { key: 'REGISTRATION_ENABLED', value: String(enable) },
    });
    return { message: `Registro de usuarios ${enable ? 'HABILITADO' : 'DESHABILITADO'}` };
  }
  
  async register(registerDto: RegisterAuthDto) {
    const status = await this.getRegistrationStatus();
    if (!status.enabled) {
      throw new ForbiddenException('El registro de nuevos usuarios está cerrado temporalmente.');
    }
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

  async login(loginDto: { email: string; password: string }, res: Response) {
    const user = await this.prisma.user.findUnique({ where: { email: loginDto.email } });
    if (!user) throw new BadRequestException('Credenciales inválidas');
    if (!user.isVerified) throw new BadRequestException('Verifica tu correo');
    
    const isMatch = await bcrypt.compare(loginDto.password, user.password);
    if (!isMatch) throw new BadRequestException('Credenciales inválidas');

    // 1. Generar Tokens
    const { accessToken, refreshToken } = await this.generateTokens(user.id, user.email, user.role);

    // 2. Guardar Refresh Token en DB
    await this.saveRefreshToken(user.id, refreshToken);

    // 3. Setear Cookies Seguras
    // Access Token Cookie (HttpOnly)
    res.cookie('token', accessToken, {
      httpOnly: true, // No accesible por JS del frontend (evita XSS)
      secure: process.env.NODE_ENV === 'production', // Solo HTTPS en prod
      sameSite: 'lax', // Protección CSRF
      maxAge: 15 * 60 * 1000, // 15 min
      path: '/', // <--- ¡ESTA ES LA CLAVE! 🔑
    });

    // Refresh Token Cookie (HttpOnly, path específico)
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
      path: '/auth/refresh', // Solo se envía al endpoint de refresh
    });

    return {
      message: 'Login exitoso',
      user: { id: user.id, username: user.username, role: user.role }
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
  
  async requestPasswordReset(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    // Por seguridad, no decimos si el usuario existe o no
    if (!user) return { message: 'Si el correo existe, se envió un enlace.' };

    const resetToken = uuidv4();
    // Expiración: 1 hora desde ahora
    const expires = new Date();
    expires.setHours(expires.getHours() + 1);

    await this.prisma.user.update({
      where: { email },
      data: { 
        passwordResetToken: resetToken,
        passwordResetExpires: expires
      }
    });

    // Enviar Email (Simulado)
    const frontendUrl = this.configService.get('FRONTEND_URL');
    console.log(`LINK RESET: ${frontendUrl}/change-password?token=${resetToken}`);
    
    return { message: 'Si el correo existe, se envió un enlace.' };
  }

  // --- CAMBIAR PASSWORD CON TOKEN ---
  async changePassword(token: string, newPassword: string) {
    const user = await this.prisma.user.findFirst({
      where: { 
        passwordResetToken: token,
        passwordResetExpires: { gt: new Date() } // El token debe no haber expirado
      },
    });

    if (!user) throw new BadRequestException('Token inválido o expirado');

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null,   // Limpiar token
        passwordResetExpires: null, // Limpiar fecha
        // Opcional: Revocar todas las sesiones (refresh tokens) al cambiar clave
        refreshTokens: { deleteMany: {} } 
      },
    });

    return { message: 'Contraseña actualizada.' };
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
  
  // Obtener lista de todos los usuarios (sin passwords)
  async getAllUsers() {
    return this.prisma.user.findMany({
      select: {
        id: true,
        email: true,
        username: true,
        role: true,
        isVerified: true,
        createdAt: true,
      },
      orderBy: { id: 'asc' }
    });
  }

  async updatePassword(userId: number, oldPass: string, newPass: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new BadRequestException('Usuario no encontrado');

    const isMatch = await bcrypt.compare(oldPass, user.password);
    if (!isMatch) throw new BadRequestException('La contraseña anterior es incorrecta');

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(newPass, salt);

    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hash }
    });

    return { message: 'Contraseña actualizada correctamente' };
  }
  
  // --- LOGOUT ---
  async logout(res: Response) {
    // Limpiar cookies
    res.clearCookie('token');
    res.clearCookie('refresh_token', { path: '/auth/refresh' });
    return { message: 'Sesión cerrada' };
  }
}