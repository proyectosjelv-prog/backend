// src/auth/auth.controller.ts
import { Controller, Post, Body, Get, Query, UseGuards, Request, Delete, Param } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';
import { UserRole } from '../config/security/roles.config';
import { Patch } from '@nestjs/common';


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
  
  @Post('request-password-reset')
  requestReset(@Body() body: { email: string }) {
    return this.authService.requestPasswordReset(body.email);
  }

  @Post('change-password')
  changePassword(@Body() body: { token: string; newPassword: string }) {
    return this.authService.changePassword(body.token, body.newPassword);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN) // Solo Admins y SuperAdmins pueden hacer esto
  @Patch('change-role/:id')
  async changeRole(
    @Param('id') id: string, 
    @Body('role') role: UserRole
  ) {
    return this.authService.changeUserRole(+id, role);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN) // Solo Admins ven la lista
  @Get('users')
  getAllUsers() {
    return this.authService.getAllUsers();
  }
}
