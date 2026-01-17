// src/email/email.service.ts
import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.createTestAccount();
  }

  async createTestAccount() {
    const testAccount = await nodemailer.createTestAccount();

    this.transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      secure: false, 
      auth: {
        user: testAccount.user, 
        pass: testAccount.pass, 
      },
    });
  }

  async sendVerificationEmail(to: string, token: string) {
    const verificationLink = `http://localhost:3000/auth/verify?token=${token}`;

    const info = await this.transporter.sendMail({
      from: '"Mi Proyecto Modular 👻" <no-reply@mi-proyecto.com>',
      to: to,
      subject: 'Verifica tu correo ✔',
      html: `
        <h1>Bienvenido</h1>
        <p>Por favor verifica tu cuenta haciendo clic en el siguiente enlace:</p>
        <a href="${verificationLink}">Verificar mi cuenta</a>
        <p>O copia este link: ${verificationLink}</p>
      `,
    });

    console.log('📧 Correo enviado (Preview): ' + nodemailer.getTestMessageUrl(info));
  }
  
}