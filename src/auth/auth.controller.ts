// src/auth/auth.controller.ts
import { 
  Controller, 
  Post, 
  Body, 
  Get, 
  Query, 
  UseGuards, 
  Delete, 
  Param, 
  Patch, 
  Res, 
  Req, // <--- USAMOS ESTE DECORADOR (IMPORTANTE)
  UnauthorizedException,
  ForbiddenException
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';
import { UserRole } from '../config/security/roles.config';
import type { Request, Response } from 'express'; 
import { ThrottlerGuard } from '@nestjs/throttler';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // 1. Endpoint PÚBLICO para que el Frontend sepa si mostrar el form
  @Get('registration-status')
  async getRegStatus() {
    return this.authService.getRegistrationStatus();
  }
  // 2. Endpoint ADMIN para apagar/encender
  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
  @Post('admin/toggle-registration')
  async toggleRegistration(@Body() body: { enable: boolean }) {
    return this.authService.toggleRegistration(body.enable);
  }
  
  // 1. REGISTRO
  @Post('register')
  register(@Body() registerDto: RegisterAuthDto) {
    return this.authService.register(registerDto);
  }

  // 2. VERIFICACIÓN DE EMAIL
  @Get('verify')
  verifyAccount(@Query('token') token: string) {
    return this.authService.verifyUser(token);
  }

  // 3. LOGIN
  @Post('login')
  @UseGuards(ThrottlerGuard)
  async login(
    @Body() loginDto: { email: string; password: string },
    @Res({ passthrough: true }) res: Response // 'passthrough' permite devolver JSON y cookies manuales
  ) {
    return this.authService.login(loginDto, res);
  }

  @Post('logout')
  async logout(@Res({ passthrough: true }) res: Response) {
    return this.authService.logout(res);
  }

  @Post('refresh')
  async refreshTokens(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const refreshToken = req.cookies['refresh_token'];
    
    if (!refreshToken) throw new UnauthorizedException('No refresh token');

    // DESCOMENTA ESTA LÍNEA AHORA:
    return this.authService.refreshTokens(refreshToken, res);
  }

  // 4. PERFIL (LIVE UPDATE)
  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Req() req: Request) { // <--- CORREGIDO: @Req()
    return {
      mensaje: "Sesión válida",
      user: req.user 
    };
  }

  // --- GESTIÓN DE CONTRASEÑAS ---

  @Post('request-password-reset')
  requestReset(@Body() body: { email: string }) {
    return this.authService.requestPasswordReset(body.email);
  }

  @Post('change-password') 
  changePasswordWithToken(@Body() body: { token: string; newPassword: string }) {
    return this.authService.changePassword(body.token, body.newPassword);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('update-password')
  updatePasswordLogged(@Req() req: Request, @Body() body: any) { // <--- CORREGIDO: @Req()
    // Forzamos el tipado a 'any' para acceder a .userId sin extender la interfaz todavía
    const user = req.user as any; 
    return this.authService.updatePassword(user.userId, body.oldPassword, body.newPassword);
  }

  // --- ZONA ADMIN ---

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('admin')
  onlyAdmin(@Req() req: Request) { // <--- CORREGIDO: @Req()
    return {
      mensaje: "¡Hola Jefe!",
      usuario: req.user
    };
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
  @Get('users')
  getAllUsers() {
    return this.authService.getAllUsers();
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN)
  @Delete('delete/:id')
  deleteUser(@Param('id') id: string) {
    return this.authService.deleteUser(+id);
  }

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
  @Patch('change-role/:id')
  async changeRole(
    @Param('id') id: string, 
    @Body('role') newRole: UserRole,
    @Req() req: any // <--- 1. Recibimos al solicitante
  ) {
    // 2. Pasamos el usuario solicitante al servicio
    return this.authService.changeUserRole(+id, newRole, req.user); 
  }

  
}