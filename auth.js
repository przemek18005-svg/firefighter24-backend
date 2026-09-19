// auth.js — logika tokenów JWT i middleware kontroli dostępu.
// KLUCZOWA RÓŻNICA wobec wersji front-endowej: te sprawdzenia ról dzieją się
// na serwerze, więc nie da się ich obejść konsolą przeglądarki.
const jwt = require('jsonwebtoken');
const { pool } = require('./db');

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

/* requireAuth celowo NIE ufa roli/uprawnieniom zapisanym w samym tokenie —
   token może żyć 30 dni, a Zarząd musi móc natychmiast zmienić komuś rolę,
   nadać/cofnąć uprawnienie albo usunąć konto i mieć pewność, że to działa
   od razu, a nie dopiero po ponownym zalogowaniu tamtej osoby. Dlatego przy
   każdym żądaniu dociągamy świeże role+permissions z bazy — token służy
   tylko do potwierdzenia TOŻSAMOŚCI (kim jest ten użytkownik), nie do
   przechowywania jego bieżących uprawnień. */
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Brak tokenu uwierzytelniającego.' });
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: 'Token nieprawidłowy lub wygasł. Zaloguj się ponownie.' });
  }
  // Tokeny wydane przed wprowadzeniem tego rozróżnienia nie mają pola "kind"
  // — traktujemy brak pola jak "unit", żeby nie wylogować wszystkich
  // dotychczasowych użytkowników przy tym wdrożeniu. Odrzucamy tylko
  // token jawnie oznaczony jako inny rodzaj (np. "gmina").
  if (payload.kind && payload.kind !== 'unit') return res.status(401).json({ error: 'Nieprawidłowy typ tokenu.' });
  try {
    const { rows } = await pool.query(
      `SELECT id, unit_id, name, email, role, permissions FROM users WHERE id = $1`,
      [payload.sub]
    );
    const dbUser = rows[0];
    if (!dbUser) return res.status(401).json({ error: 'Konto nie istnieje. Zaloguj się ponownie.' });
    req.user = {
      id: dbUser.id, unitId: dbUser.unit_id, role: dbUser.role,
      name: dbUser.name, email: dbUser.email, permissions: dbUser.permissions || {},
    };
    next();
  } catch (e) {
    console.error('Błąd weryfikacji sesji:', e.message);
    return res.status(500).json({ error: 'Błąd serwera podczas weryfikacji sesji.' });
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

/* requireRoleOrPermission: dostęp mają role wymienione w allowedRoles ORAZ
   każdy, komu Zarząd nadał konkretną, nazwaną flagę uprawnienia (niezależnie
   od jego roli bazowej). Zarząd zawsze przechodzi automatycznie — jest
   pełnoprawnym administratorem jednostki niezależnie od tych flag. */
function requireRoleOrPermission(allowedRoles, permissionFlag) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Brak tokenu uwierzytelniającego.' });
    if (req.user.role === 'Zarząd') return next();
    if (allowedRoles.includes(req.user.role)) return next();
    if (permissionFlag && req.user.permissions && req.user.permissions[permissionFlag] === true) return next();
    return res.status(403).json({ error: 'Nie masz uprawnień do wykonania tej operacji.' });
  };
}

module.exports = { signToken, signGminaToken, requireAuth, requireGminaAuth, requireRole, requireRoleOrPermission, JWT_SECRET };
