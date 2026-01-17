// src/auth/dto/register-auth.dto.ts
import { IsEmail, IsString, MinLength } from 'class-validator';

export class RegisterAuthDto {
  @IsString()
  username: string;

  @IsEmail({}, { message: 'El correo no es válido' })
  email: string;

  @IsString()
  @MinLength(6, { message: 'La contraseña debe tener al menos 6 caracteres' })
  password: string;
}