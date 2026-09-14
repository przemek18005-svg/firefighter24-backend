// email.js — wysyłka e-maili przez Resend (https://resend.com).
// Jeśli RESEND_API_KEY nie jest ustawiony, e-mail nie zostanie wysłany —
// zamiast tego treść trafia do logów serwera, żeby dało się testować reset
// hasła bez skonfigurowanego dostawcy poczty. To celowy tryb "awaryjny",
// nie coś, co powinno zostać tak w prawdziwej, pełnej produkcji.
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const MAIL_FROM = process.env.MAIL_FROM || 'Firefighter24 <onboarding@resend.dev>';

async function sendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) {
    console.log('--- [DEV MODE: brak RESEND_API_KEY, e-mail nie został wysłany] ---');
    console.log('Do:', to);
    console.log('Temat:', subject);
    console.log('Treść:', html);
    console.log('--------------------------------------------------------------');
    return { sent: false, devMode: true };
  }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: MAIL_FROM, to, subject, html }),
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      console.error('Błąd wysyłki e-maila (Resend):', res.status, errText);
      return { sent: false, devMode: false, error: true };
    }
    return { sent: true, devMode: false };
  } catch (e) {
    console.error('Błąd wysyłki e-maila:', e.message);
    return { sent: false, devMode: false, error: true };
  }
}

module.exports = { sendEmail, EMAIL_CONFIGURED: !!RESEND_API_KEY };
