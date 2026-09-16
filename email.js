// email.js — wysyłka e-maili. Obsługuje trzy tryby, wybierane automatycznie
// na podstawie tego, co ustawisz w zmiennych środowiskowych:
//
//   1) RESEND_API_KEY ustawiony  -> wysyłka przez Resend (API, zalecane
//      dla produkcji — dobra dostarczalność, statystyki, brak limitów SMTP).
//   2) SMTP_HOST ustawiony       -> wysyłka przez zwykłe SMTP, np. skrzynkę
//      pocztową na hostingu az.pl albo jakikolwiek inny serwer pocztowy.
//   3) Żadne z powyższych        -> tryb deweloperski: e-mail nie jest
//      wysyłany, treść trafia do logów serwera (patrz server.js — w tym
//      trybie token resetu hasła wraca też wprost w odpowiedzi API,
//      wyłącznie do celów testowych).
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const SMTP_HOST = process.env.SMTP_HOST;
const MAIL_FROM = process.env.MAIL_FROM || 'Firefighter24 <onboarding@resend.dev>';

const EMAIL_CONFIGURED = !!(RESEND_API_KEY || SMTP_HOST);
const EMAIL_MODE = RESEND_API_KEY ? 'resend' : (SMTP_HOST ? 'smtp' : 'dev');

let smtpTransporter = null;
function getSmtpTransporter() {
  if (smtpTransporter) return smtpTransporter;
  const nodemailer = require('nodemailer');
  const port = Number(process.env.SMTP_PORT || 587);
  smtpTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port,
    // Port 465 wymaga połączenia od razu szyfrowanego (SSL); port 587 (zalecany,
    // np. przez az.pl) startuje jako zwykłe połączenie i przechodzi na
    // szyfrowanie przez STARTTLS — nodemailer robi to automatycznie przy secure:false.
    secure: port === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  return smtpTransporter;
}

async function sendViaResend({ to, subject, html }) {
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: MAIL_FROM, to, subject, html }),
    });
    if (!res.ok) {
      console.error('Błąd wysyłki e-maila (Resend):', res.status, await res.text().catch(() => ''));
      return { sent: false, devMode: false, error: true };
    }
    return { sent: true, devMode: false };
  } catch (e) {
    console.error('Błąd wysyłki e-maila (Resend):', e.message);
    return { sent: false, devMode: false, error: true };
  }
}

async function sendViaSmtp({ to, subject, html }) {
  try {
    const transporter = getSmtpTransporter();
    await transporter.sendMail({ from: MAIL_FROM, to, subject, html });
    return { sent: true, devMode: false };
  } catch (e) {
    console.error('Błąd wysyłki e-maila (SMTP):', e.message);
    return { sent: false, devMode: false, error: true };
  }
}

async function sendEmail({ to, subject, html }) {
  if (EMAIL_MODE === 'resend') return sendViaResend({ to, subject, html });
  if (EMAIL_MODE === 'smtp') return sendViaSmtp({ to, subject, html });

  console.log('--- [DEV MODE: brak RESEND_API_KEY / SMTP_HOST, e-mail nie został wysłany] ---');
  console.log('Do:', to);
  console.log('Temat:', subject);
  console.log('Treść:', html);
  console.log('--------------------------------------------------------------');
  return { sent: false, devMode: true };
}

module.exports = { sendEmail, EMAIL_CONFIGURED, EMAIL_MODE };
