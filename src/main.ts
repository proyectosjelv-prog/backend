// backend/src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
// Importación compatible con "esModuleInterop: true"
import cookieParser from 'cookie-parser'; 
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.use(helmet());
  // 1. Usamos cookieParser directamente (sin spread '...')
  app.use(cookieParser());

  // 2. Configuración CORS Correcta
  app.enableCors({
    // IMPORTANTE: NO uses '*' si usas credentials: true.
    // Debes poner la URL exacta de tu frontend:
    // origin: process.env.FRONTEND_URL || 'http://localhost:4321',
    origin: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, // Esto permite que las cookies viajen
  });

  if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
    throw new Error('FATAL: JWT_SECRET o JWT_REFRESH_SECRET no están definidos.');
  }

  await app.listen(process.env.PORT || 3000, '0.0.0.0');
  console.log(`Backend corriendo en: ${await app.getUrl()}`);
}
bootstrap();