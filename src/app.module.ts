// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config'; // <--- Importante
import { AuthModule } from './auth/auth.module';
import { EmailModule } from './email/email.module';

@Module({
  imports: [
    // Esto carga el archivo .env automáticamente
    ConfigModule.forRoot({
      isGlobal: true, 
    }),
    AuthModule, 
    EmailModule
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}