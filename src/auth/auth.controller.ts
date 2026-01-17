// src/auth/auth.controller.ts
import { Controller, Post, Body, Get, Query, UseGuards, Request, Delete, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';
import { UserRole } from '../config/security/roles.config';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() registerDto: RegisterAuthDto) {
    return this.authService.register(registerDto);
  }

  @Get('verify')
  verifyAccount(@Query('token') token: string) {
    return this.authService.verifyUser(token);
  }

  @Post('login')
  login(@Body() loginDto: { email: string; password: string }) {
    return this.authService.login(loginDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Request() req) {
    const userId = req.user.userId;
    const user = await this.authService.getProfile(userId);
    return {
      mensaje: "¡Bienvenido a la zona VIP!",
      datos_usuario: user
    };
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('admin')
  onlyAdmin(@Request() req) {
    return {
      mensaje: "¡Hola Jefe! Si ves esto, eres Administrador.",
      usuario: req.user
    };
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN)
  @Delete('delete/:id')
  deleteUser(@Param('id') id: string) {
    return this.authService.deleteUser(+id);
  }
}