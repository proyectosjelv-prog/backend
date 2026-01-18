// src/config/security/jwt.constants.ts
export const jwtConstants = {
  // Esta es la "llave maestra" para firmar tus tokens. 
  // Cámbiala por algo muy difícil de adivinar.
  secret: process.env.JWT_SECRET || 'CLAVE_SECRETA_POR_DEFECTO',
};