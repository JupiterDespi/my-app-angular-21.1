const nodemailer = require('nodemailer');

function isEmailConfigured() {
  return Boolean(process.env.SMTP_USER && process.env.SMTP_PASS);
}

function createTransporter() {
  return nodemailer.createTransport({
    service: process.env.SMTP_SERVICE || 'gmail',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

async function sendVerificationEmail(account, verificationToken) {
  if (!isEmailConfigured()) return false;

  const verifyUrl = `${process.env.CLIENT_ORIGIN || 'http://localhost:4200'}/account/verify-email?token=${verificationToken}`;
  await createTransporter().sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: account.email,
    subject: 'Verify your email',
    html: `
      <p>Hi ${account.firstName || account.first_name},</p>
      <p>Please verify your email address using this link:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
    `
  });

  return true;
}

async function sendPasswordResetEmail(account, resetToken) {
  if (!isEmailConfigured()) return false;

  const resetUrl = `${process.env.CLIENT_ORIGIN || 'http://localhost:4200'}/account/reset-password?token=${resetToken}`;
  await createTransporter().sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: account.email,
    subject: 'Reset your password',
    html: `
      <p>Hi ${account.firstName || account.first_name},</p>
      <p>Please reset your password using this link:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
    `
  });

  return true;
}

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail
};
