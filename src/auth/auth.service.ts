// src/auth/auth.service.ts
import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { EmailService } from '../email/email.service';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private emailService: EmailService,
    private jwtService: JwtService,
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
}