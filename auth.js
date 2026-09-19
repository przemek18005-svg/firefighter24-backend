// auth.js — logika tokenów JWT i middleware kontroli dostępu.
// KLUCZOWA RÓŻNICA wobec wersji front-endowej: te sprawdzenia ról dzieją się
// na serwerze, więc nie da się ich obejść konsolą przeglądarki.
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('BŁĄD: brak zmiennej środowiskowej JWT_SECRET. Ustaw ją przed uruchomieniem serwera (patrz README).');
  process.exit(1);
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, unitId: user.unit_id, role: user.role, name: user.name, email: user.email, kind: 'unit' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

// Token dla konta gminnego — celowo osobny "kind", żeby token strażaka/zarządu
// jednostki nigdy nie przeszedł jako token gminy, i odwrotnie, nawet gdyby
// ktoś spróbował go ręcznie podstawić.
function signGminaToken(account) {
  return jwt.sign(
    { sub: account.id, gminaCode: account.gmina_code, name: account.name, email: account.email, kind: 'gmina' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Brak tokenu uwierzytelniającego.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // Tokeny wydane przed wprowadzeniem tego rozróżnienia nie mają pola "kind"
    // — traktujemy brak pola jak "unit", żeby nie wylogować wszystkich
    // dotychczasowych użytkowników przy tym wdrożeniu. Odrzucamy tylko
    // token jawnie oznaczony jako inny rodzaj (np. "gmina").
    if (payload.kind && payload.kind !== 'unit') return res.status(401).json({ error: 'Nieprawidłowy typ tokenu.' });
    req.user = { id: payload.sub, unitId: payload.unitId, role: payload.role, name: payload.name, email: payload.email };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token nieprawidłowy lub wygasł. Zaloguj się ponownie.' });
  }
}

function requireGminaAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Brak tokenu uwierzytelniającego.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.kind !== 'gmina') return res.status(401).json({ error: 'Nieprawidłowy typ tokenu.' });
    req.gmina = { id: payload.sub, gminaCode: payload.gminaCode, name: payload.name, email: payload.email };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token nieprawidłowy lub wygasł. Zaloguj się ponownie.' });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Nie masz uprawnień do wykonania tej operacji.' });
    }
    next();
  };
}

module.exports = { signToken, signGminaToken, requireAuth, requireGminaAuth, requireRole, JWT_SECRET };
