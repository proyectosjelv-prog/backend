// prisma.config.ts
export default {
  datasource: {
    // Esto lee la URL de tu archivo .env automáticamente
    url: process.env.DATABASE_URL,
  },
};