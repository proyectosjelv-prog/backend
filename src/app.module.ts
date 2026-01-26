// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config'; // <--- Importante
import { AuthModule } from './auth/auth.module';
import { EmailModule } from './email/email.module';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';

@Module({
  imports: [
    // Esto carga el archivo .env automáticamente
    ConfigModule.forRoot({ isGlobal: true }),
    
    // 2. CONFIGURAR LÍMITES:
    ThrottlerModule.forRoot([{
      ttl: 60000, // Tiempo de vida (1 minuto en milisegundos)
      limit: 15,   // Límite de intentos permitidos en ese tiempo
    }]),
    AuthModule, 
    EmailModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}