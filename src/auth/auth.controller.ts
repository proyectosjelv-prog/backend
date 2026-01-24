import { Controller, Post, Body, Get, Query, UseGuards, Request, Delete, Param, Patch } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterAuthDto } from './dto/register-auth.dto';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';
import { UserRole } from '../config/security/roles.config';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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
  login(@Body() loginDto: { email: string; password: string }) {
    return this.authService.login(loginDto);
  }

  // 4. PERFIL (LIVE UPDATE)
  // Este endpoint es clave para tu frontend. Devuelve el usuario fresco de la DB.
  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Request() req) {
    return {
      mensaje: "Sesión válida",
      user: req.user // Esto viene de JwtStrategy.validate() -> DB
    };
  }

  // --- GESTIÓN DE CONTRASEÑAS ---

  // A. Olvidé mi contraseña (Pide el correo para enviar link)
  @Post('request-password-reset')
  requestReset(@Body() body: { email: string }) {
    return this.authService.requestPasswordReset(body.email);
  }

  // B. Restaurar contraseña con TOKEN (Viene del correo)
  // No necesita AuthGuard porque el usuario no puede loguearse si olvidó la clave.
  @Post('change-password') 
  changePasswordWithToken(@Body() body: { token: string; newPassword: string }) {
    return this.authService.changePassword(body.token, body.newPassword);
  }

  // C. Actualizar contraseña (ESTANDO LOGUEADO)
  // Requiere AuthGuard para saber quién es el usuario (req.user)
  @UseGuards(AuthGuard('jwt'))
  @Post('update-password')
  updatePasswordLogged(@Request() req, @Body() body: any) {
    // Nota: Asegúrate de tener el método updatePassword en tu AuthService
    return this.authService.updatePassword(req.user.userId, body.oldPassword, body.newPassword);
  }

  // --- ZONA ADMIN ---

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('admin')
  onlyAdmin(@Request() req) {
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
    @Body('role') role: UserRole
  ) {
    return this.authService.changeUserRole(+id, role);
  }
}