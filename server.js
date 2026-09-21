// server.js — REST API dla Firefighter24 (wersja na PostgreSQL).
// Hasła haszowane bcryptem, role egzekwowane po stronie serwera, dane
// współdzielone między urządzeniami. Baza to teraz PostgreSQL zamiast pliku
// SQLite — dzięki temu backend może działać na hostingach bez płatnego,
// trwałego dysku (np. darmowy Koyeb + darmowa baza Postgres).
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { v4: uuid } = require('uuid');
const { pool, initSchema } = require('./db');
const { signToken, signGminaToken, requireAuth, requireGminaAuth, requireRole, requireRoleOrPermission } = require('./auth');
const { validateBody } = require('./validation');
const { sendEmail, EMAIL_CONFIGURED, EMAIL_MODE } = require('./email');

const app = express();
app.use(cors());
// Limit domyślny (100kb) jest za mały na załączniki zdjęć do raportów z
// wyjazdów (zapisywane tymczasowo jako base64 wprost w bazie — patrz niżej
// przy trasie /api/trips, sekcja o załączniku). 8mb z zapasem na kodowanie base64.
app.use(express.json({ limit: '8mb' }));
app.set('trust proxy', 1); // hostingi typu Koyeb/Railway stoją za reverse proxy — potrzebne, żeby rate-limit widział prawdziwe IP

const PORT = process.env.PORT || 3001;

/* ---------- Małe pomocniki do zapytań (żeby nie powtarzać pool.query wszędzie) ---------- */
async function dbGet(sql, params = []) {
  const { rows } = await pool.query(sql, params);
  return rows[0] || null;
}
async function dbAll(sql, params = []) {
  const { rows } = await pool.query(sql, params);
  return rows;
}
async function dbRun(sql, params = []) {
  return pool.query(sql, params);
}

async function logAudit(unitId, userName, action, details) {
  await dbRun(
    `INSERT INTO audit_log (id, unit_id, user_name, action, details) VALUES ($1,$2,$3,$4,$5)`,
    [uuid(), unitId, userName, action, details || '']
  );
}

// Losowy kod gminy (24 znaki, duże/małe litery + cyfry) — generowany przez
// serwer, nie wpisywany ręcznie, żeby uniknąć literówek, kolizji między
// gminami i żeby ktoś z zewnątrz nie odgadł go łatwym słowem.
function generateGminaCode(length = 24) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.randomBytes(length);
  let code = '';
  for (let i = 0; i < length; i++) code += alphabet[bytes[i] % alphabet.length];
  return code;
}

/* ---------- LIMIT PRÓB (rate limiting) ---------- */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zbyt wiele prób. Spróbuj ponownie za kilka minut.' },
});
const strictAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 6,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zbyt wiele prób logowania. Spróbuj ponownie za kilka minut.' },
});

// ---------- AUTORYZACJA ----------

app.post('/api/auth/register', authLimiter, validateBody({
  unitName: { required: true, type: 'string', max: 200 },
  name: { required: true, type: 'string', max: 200 },
  email: { required: true, type: 'email' },
  password: { required: true, type: 'password' },
}), async (req, res) => {
  const { unitName, name, email, password } = req.body;
  const emailLower = email.trim().toLowerCase();
  const existing = await dbGet(`SELECT id FROM users WHERE email = $1`, [emailLower]);
  if (existing) return res.status(409).json({ error: 'Konto z tym adresem e-mail już istnieje.' });

  const unitId = uuid();
  const userId = uuid();
  const passwordHash = await bcrypt.hash(password, 12);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`INSERT INTO units (id, name) VALUES ($1,$2)`, [unitId, unitName.trim()]);
    await client.query(
      `INSERT INTO users (id, unit_id, name, email, password_hash, role) VALUES ($1,$2,$3,$4,$5,'Zarząd')`,
      [userId, unitId, name.trim(), emailLower, passwordHash]
    );
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Błąd rejestracji:', e.message);
    return res.status(500).json({ error: 'Nie udało się utworzyć jednostki. Spróbuj ponownie.' });
  } finally {
    client.release();
  }

  await logAudit(unitId, name, 'Zarejestrowano jednostkę', unitName);

  res.status(201).json({
    token: signToken({ id: userId, unit_id: unitId, name: name.trim(), email: emailLower, role: 'Zarząd' }),
    user: { id: userId, name: name.trim(), email: emailLower, role: 'Zarząd', permissions: {} },
    unit: { id: unitId, name: unitName.trim(), gminaCode: null },
  });
});

app.post('/api/auth/login', strictAuthLimiter, validateBody({
  email: { required: true, type: 'email' },
  password: { required: true, type: 'string', max: 200 },
}), async (req, res) => {
  const { email, password } = req.body;
  const emailLower = email.trim().toLowerCase();
  const user = await dbGet(`SELECT * FROM users WHERE email = $1`, [emailLower]);
  if (!user) return res.status(401).json({ error: 'Nie znaleziono konta z tym adresem e-mail.' });
  if (!(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Nieprawidłowe hasło.' });
  }
  const unit = await dbGet(`SELECT * FROM units WHERE id = $1`, [user.unit_id]);
  await logAudit(user.unit_id, user.name, 'Zalogowano się', user.email);
  res.json({
    token: signToken(user),
    user: { id: user.id, name: user.name, email: user.email, role: user.role, permissions: user.permissions || {} },
    unit: { id: unit.id, name: unit.name, gminaCode: unit.gmina_code },
  });
});

/* ---------- RESET HASŁA (dwuetapowy, z tokenem) ---------- */
app.post('/api/auth/forgot-password', strictAuthLimiter, validateBody({
  email: { required: true, type: 'email' },
}), async (req, res) => {
  const emailLower = req.body.email.trim().toLowerCase();
  const genericOk = { ok: true, message: 'Jeśli konto z tym adresem e-mail istnieje, wysłaliśmy na nie instrukcje resetu hasła.' };
  const user = await dbGet(`SELECT * FROM users WHERE email = $1`, [emailLower]);
  if (!user) return res.json(genericOk);

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

  await dbRun(
    `INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)`,
    [uuid(), user.id, tokenHash, expiresAt]
  );

  const resetUrl = `${process.env.APP_URL || 'https://ezielonka.pl/app/'}?resetToken=${rawToken}&email=${encodeURIComponent(emailLower)}`;
  const emailResult = await sendEmail({
    to: emailLower,
    subject: 'Reset hasła — Firefighter24',
    html: `<p>Otrzymaliśmy prośbę o reset hasła do konta Firefighter24.</p>
           <p><a href="${resetUrl}">Kliknij tutaj, aby ustawić nowe hasło</a> (link ważny 1 godzinę).</p>
           <p>Jeśli to nie Ty prosiłeś o reset, zignoruj tę wiadomość.</p>`,
  });
  await logAudit(user.unit_id, user.name, 'Poproszono o reset hasła', emailResult.devMode ? '(tryb dev — brak RESEND_API_KEY)' : '');

  // Token w odpowiedzi JSON pokazujemy WYŁĄCZNIE, gdy ktoś świadomie ustawił
  // NODE_ENV=development (np. do testów lokalnych) — nie samym brakiem
  // RESEND_API_KEY/SMTP_HOST. To druga, niezależna warstwa zabezpieczenia:
  // nawet jeśli poczta zostanie przypadkiem źle skonfigurowana na prawdziwym
  // serwerze, token i tak nie wycieknie, dopóki ktoś jawnie nie włączy trybu dev.
  if (emailResult.devMode && process.env.NODE_ENV === 'development') {
    return res.json({ ...genericOk, devToken: rawToken, devNote: 'RESEND_API_KEY nie jest ustawiony — token zwrócony tylko do celów testowych (NODE_ENV=development).' });
  }
  res.json(genericOk);
});

app.post('/api/auth/reset-password', strictAuthLimiter, validateBody({
  email: { required: true, type: 'email' },
  token: { required: true, type: 'string', max: 128 },
  newPassword: { required: true, type: 'password' },
}), async (req, res) => {
  const emailLower = req.body.email.trim().toLowerCase();
  const { token, newPassword } = req.body;
  const user = await dbGet(`SELECT * FROM users WHERE email = $1`, [emailLower]);
  if (!user) return res.status(400).json({ error: 'Link jest nieprawidłowy lub wygasł.' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const record = await dbGet(
    `SELECT * FROM password_resets WHERE user_id = $1 AND token_hash = $2 AND used = 0 ORDER BY created_at DESC LIMIT 1`,
    [user.id, tokenHash]
  );
  if (!record) return res.status(400).json({ error: 'Link jest nieprawidłowy lub został już użyty.' });
  if (new Date(record.expires_at).getTime() < Date.now()) {
    return res.status(400).json({ error: 'Link wygasł. Poproś o nowy reset hasła.' });
  }

  const passwordHash = await bcrypt.hash(newPassword, 12);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE users SET password_hash = $1 WHERE id = $2`, [passwordHash, user.id]);
    await client.query(`UPDATE password_resets SET used = 1 WHERE id = $1`, [record.id]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    return res.status(500).json({ error: 'Nie udało się zresetować hasła. Spróbuj ponownie.' });
  } finally {
    client.release();
  }
  await logAudit(user.unit_id, user.name, 'Zresetowano hasło', '');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const user = await dbGet(`SELECT id, name, email, role, permissions FROM users WHERE id = $1`, [req.user.id]);
  const unit = await dbGet(`SELECT id, name, gmina_code FROM units WHERE id = $1`, [req.user.unitId]);
  res.json({ user: { ...user, permissions: user.permissions || {} }, unit: { id: unit.id, name: unit.name, gminaCode: unit.gmina_code } });
});

/* ---------- POMOCNICZY GENERATOR TRAS CRUD ----------
   Każdy zasób jednostki (strażacy, sprzęt, pojazdy...) ma ten sam kształt:
   lista/dodaj/edytuj/usuń, zawsze filtrowane po unit_id z tokenu. */
function crudRoutes({ table, fields, readRoles, writeRoles, permissionFlag, auditLabel, rules }) {
  const router = express.Router();
  const validator = rules ? validateBody(rules) : (req, res, next) => next();
  // Domyślnie odczyt mają wszystkie role jednostki, chyba że moduł jawnie
  // ogranicza go (np. Flota, Sprzęt) — permissionFlag pozwala Zarządowi
  // nadać dostęp pojedynczej osobie mimo jej roli bazowej.
  const canRead = requireRoleOrPermission(readRoles || ['Zarząd', 'Skarbnik', 'Strażak'], permissionFlag);
  const canWrite = requireRoleOrPermission(writeRoles, permissionFlag);

  router.get('/', requireAuth, canRead, async (req, res) => {
    try {
      const rows = await dbAll(`SELECT * FROM ${table} WHERE unit_id = $1`, [req.user.unitId]);
      res.json(rows);
    } catch (e) { res.status(500).json({ error: 'Błąd odczytu danych.' }); }
  });

  router.post('/', requireAuth, canWrite, validator, async (req, res) => {
    try {
      const id = uuid();
      const cols = ['id', 'unit_id', ...fields];
      const values = [id, req.user.unitId, ...fields.map(f => req.body[f] ?? null)];
      const placeholders = cols.map((_, i) => `$${i + 1}`).join(',');
      const row = await dbGet(
        `INSERT INTO ${table} (${cols.join(',')}) VALUES (${placeholders}) RETURNING *`,
        values
      );
      await logAudit(req.user.unitId, req.user.name, `Dodano: ${auditLabel}`, '');
      res.status(201).json(row);
    } catch (e) { console.error(e.message); res.status(500).json({ error: 'Błąd zapisu danych.' }); }
  });

  router.put('/:id', requireAuth, canWrite, validator, async (req, res) => {
    try {
      const values = fields.map(f => req.body[f] ?? null);
      const setClause = fields.map((f, i) => `${f} = $${i + 1}`).join(', ');
      const row = await dbGet(
        `UPDATE ${table} SET ${setClause} WHERE id = $${fields.length + 1} AND unit_id = $${fields.length + 2} RETURNING *`,
        [...values, req.params.id, req.user.unitId]
      );
      if (!row) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });
      await logAudit(req.user.unitId, req.user.name, `Edytowano: ${auditLabel}`, '');
      res.json(row);
    } catch (e) { console.error(e.message); res.status(500).json({ error: 'Błąd zapisu danych.' }); }
  });

  router.delete('/:id', requireAuth, canWrite, async (req, res) => {
    try {
      const row = await dbGet(
        `DELETE FROM ${table} WHERE id = $1 AND unit_id = $2 RETURNING id`,
        [req.params.id, req.user.unitId]
      );
      if (!row) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });
      await logAudit(req.user.unitId, req.user.name, `Usunięto: ${auditLabel}`, '');
      res.status(204).end();
    } catch (e) { res.status(500).json({ error: 'Błąd usuwania danych.' }); }
  });

  return router;
}

app.use('/api/firefighters', crudRoutes({
  table: 'firefighters', fields: ['first', 'last', 'role', 'join_date', 'med_date', 'org_body', 'org_role'],
  readRoles: ['Zarząd', 'Strażak'], writeRoles: ['Zarząd'], permissionFlag: 'firefighters', auditLabel: 'strażak',
  rules: {
    first: { required: true, type: 'string', max: 100 },
    last: { required: true, type: 'string', max: 100 },
    role: { type: 'string', max: 100 },
    join_date: { type: 'date' },
    med_date: { type: 'date' },
    org_body: { type: 'enum', enum: ['zarzad', 'komisja'] },
    org_role: { type: 'string', max: 100 },
  },
}));

app.use('/api/sections', crudRoutes({
  table: 'sections', fields: ['name'],
  writeRoles: ['Zarząd'], permissionFlag: 'structure', auditLabel: 'sekcja',
  rules: { name: { required: true, type: 'string', max: 150 } },
}));

// Przypisania strażaków do sekcji — osobne trasy, bo to relacja między dwoma
// zasobami (sekcja <-> strażak), nie pasuje do generycznego crudRoutes.
app.get('/api/section-members', requireAuth, async (req, res) => {
  const rows = await dbAll(`
    SELECT sm.id, sm.section_id, sm.firefighter_id, sm.commander, f.first, f.last
    FROM section_members sm
    JOIN firefighters f ON f.id = sm.firefighter_id
    WHERE sm.unit_id = $1
  `, [req.user.unitId]);
  res.json(rows);
});

app.post('/api/section-members', requireAuth, requireRoleOrPermission(['Zarząd'], 'structure'), validateBody({
  section_id: { required: true, type: 'string', max: 100 },
  firefighter_id: { required: true, type: 'string', max: 100 },
}), async (req, res) => {
  const { section_id, firefighter_id, commander } = req.body;
  const section = await dbGet(`SELECT id FROM sections WHERE id = $1 AND unit_id = $2`, [section_id, req.user.unitId]);
  if (!section) return res.status(404).json({ error: 'Nie znaleziono sekcji.' });
  const ff = await dbGet(`SELECT id, first, last FROM firefighters WHERE id = $1 AND unit_id = $2`, [firefighter_id, req.user.unitId]);
  if (!ff) return res.status(404).json({ error: 'Nie znaleziono strażaka.' });
  const dup = await dbGet(`SELECT id FROM section_members WHERE section_id = $1 AND firefighter_id = $2`, [section_id, firefighter_id]);
  if (dup) return res.status(409).json({ error: 'Ten strażak jest już przypisany do tej sekcji.' });
  const id = uuid();
  await dbRun(
    `INSERT INTO section_members (id, unit_id, section_id, firefighter_id, commander) VALUES ($1,$2,$3,$4,$5)`,
    [id, req.user.unitId, section_id, firefighter_id, commander ? 1 : 0]
  );
  await logAudit(req.user.unitId, req.user.name, 'Dodano do sekcji', `${ff.first} ${ff.last}`);
  res.status(201).json({ id, section_id, firefighter_id, commander: commander ? 1 : 0, first: ff.first, last: ff.last });
});

app.delete('/api/section-members/:id', requireAuth, requireRoleOrPermission(['Zarząd'], 'structure'), async (req, res) => {
  const row = await dbGet(`DELETE FROM section_members WHERE id = $1 AND unit_id = $2 RETURNING id`, [req.params.id, req.user.unitId]);
  if (!row) return res.status(404).json({ error: 'Nie znaleziono przypisania.' });
  await logAudit(req.user.unitId, req.user.name, 'Usunięto z sekcji', '');
  res.status(204).end();
});

app.use('/api/vehicles', crudRoutes({
  table: 'vehicles', fields: ['name', 'plate', 'oc_date', 'review_date', 'mileage'],
  readRoles: ['Zarząd'], writeRoles: ['Zarząd'], permissionFlag: 'fleet', auditLabel: 'pojazd',
  rules: {
    name: { required: true, type: 'string', max: 150 },
    plate: { type: 'string', max: 30 },
    oc_date: { type: 'date' },
    review_date: { type: 'date' },
    mileage: { type: 'nonNegativeNumber' },
  },
}));

app.use('/api/fuel', crudRoutes({
  table: 'fuel_log', fields: ['vehicle_id', 'vehicle_name', 'date', 'liters', 'cost'],
  readRoles: ['Zarząd'], writeRoles: ['Zarząd'], permissionFlag: 'fleet', auditLabel: 'tankowanie',
  rules: {
    date: { required: true, type: 'date' },
    liters: { required: true, type: 'positiveNumber' },
    cost: { type: 'nonNegativeNumber' },
  },
}));

app.use('/api/gear', crudRoutes({
  table: 'gear', fields: ['name', 'category', 'review_date'],
  readRoles: ['Zarząd'], writeRoles: ['Zarząd'], permissionFlag: 'gear', auditLabel: 'sprzęt',
  rules: {
    name: { required: true, type: 'string', max: 150 },
    review_date: { type: 'date' },
  },
}));

// Wyjazdy — osobne, ręcznie pisane trasy (nie generyczny crudRoutes), z dwóch
// powodów: (1) lista wyjazdów NIE dociąga za każdym razem załącznika zdjęcia
// (może być ciężki) — do tego jest osobna trasa /:id/attachment; (2) pola
// logiczne i listy JSON mają w bazie NOT NULL — trzeba pilnować, żeby nigdy
// nie wysłać do nich jawnego null, tylko sensowną wartość domyślną.
const TRIP_FIELDS = ['date', 'type', 'place', 'crew', 'lat', 'lng', 'departure_time', 'return_time',
  'street', 'house_number', 'postal_code', 'city', 'address_gmina', 'description',
  'other_services', 'medical_aid', 'injured', 'handover_notes', 'psp_report_number',
  'equipment_used', 'supplies_used', 'present_not_departed_ids',
  'attachment_filename', 'attachment_mimetype', 'attachment_data'];
const TRIP_LIST_FIELDS = TRIP_FIELDS.filter(f => f !== 'attachment_data');
const TRIP_JSONB_ARRAY_FIELDS = ['other_services', 'equipment_used', 'supplies_used', 'present_not_departed_ids'];
// Front-end wysyła te cztery pola jako gotowy tekst JSON (JSON.stringify po
// swojej stronie) — tu tylko przekazujemy dalej, Postgres sam rzutuje tekst
// JSON na kolumnę jsonb. Booleany dostają jawną wartość true/false, nigdy null.
function tripFieldValue(body, f) {
  if (f === 'medical_aid' || f === 'injured') return body[f] === true;
  if (TRIP_JSONB_ARRAY_FIELDS.includes(f)) return body[f] ?? '[]';
  return body[f] ?? null;
}
const tripValidator = validateBody({
  date: { required: true, type: 'date' },
  place: { type: 'string', max: 200 },
  departure_time: { type: 'string', max: 10 },
  return_time: { type: 'string', max: 10 },
  street: { type: 'string', max: 150 },
  house_number: { type: 'string', max: 30 },
  postal_code: { type: 'string', max: 10 },
  city: { type: 'string', max: 100 },
  address_gmina: { type: 'string', max: 100 },
  description: { type: 'string', max: 3000 },
  other_services: { type: 'string', max: 2000 },
  handover_notes: { type: 'string', max: 3000 },
  psp_report_number: { type: 'string', max: 50 },
  equipment_used: { type: 'string', max: 3000 },
  supplies_used: { type: 'string', max: 3000 },
  present_not_departed_ids: { type: 'string', max: 3000 },
  attachment_filename: { type: 'string', max: 255 },
  attachment_mimetype: { type: 'string', max: 100 },
  attachment_data: { type: 'string', max: 7000000 },
});
const tripPerm = requireRoleOrPermission(['Zarząd'], 'trips');

app.get('/api/trips', requireAuth, tripPerm, async (req, res) => {
  const rows = await dbAll(`SELECT id, unit_id, ${TRIP_LIST_FIELDS.join(', ')} FROM trips WHERE unit_id = $1`, [req.user.unitId]);
  res.json(rows);
});

// Załącznik pobierany osobno, tylko na żądanie — nie obciąża listy wyjazdów.
app.get('/api/trips/:id/attachment', requireAuth, tripPerm, async (req, res) => {
  const row = await dbGet(`SELECT attachment_filename, attachment_mimetype, attachment_data FROM trips WHERE id = $1 AND unit_id = $2`, [req.params.id, req.user.unitId]);
  if (!row || !row.attachment_data) return res.status(404).json({ error: 'Brak załącznika.' });
  res.json(row);
});

app.post('/api/trips', requireAuth, tripPerm, tripValidator, async (req, res) => {
  try {
    const id = uuid();
    const cols = ['id', 'unit_id', ...TRIP_FIELDS];
    const values = [id, req.user.unitId, ...TRIP_FIELDS.map(f => tripFieldValue(req.body, f))];
    const placeholders = cols.map((_, i) => `$${i + 1}`).join(',');
    const row = await dbGet(
      `INSERT INTO trips (${cols.join(',')}) VALUES (${placeholders}) RETURNING id, unit_id, ${TRIP_LIST_FIELDS.join(', ')}`,
      values
    );
    await logAudit(req.user.unitId, req.user.name, 'Dodano: wyjazd', '');
    res.status(201).json(row);
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Błąd zapisu danych.' }); }
});

app.put('/api/trips/:id', requireAuth, tripPerm, tripValidator, async (req, res) => {
  try {
    const values = TRIP_FIELDS.map(f => tripFieldValue(req.body, f));
    const setClause = TRIP_FIELDS.map((f, i) => `${f} = $${i + 1}`).join(', ');
    const row = await dbGet(
      `UPDATE trips SET ${setClause} WHERE id = $${TRIP_FIELDS.length + 1} AND unit_id = $${TRIP_FIELDS.length + 2} RETURNING id, unit_id, ${TRIP_LIST_FIELDS.join(', ')}`,
      [...values, req.params.id, req.user.unitId]
    );
    if (!row) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });
    await logAudit(req.user.unitId, req.user.name, 'Edytowano: wyjazd', '');
    res.json(row);
  } catch (e) { console.error(e.message); res.status(500).json({ error: 'Błąd zapisu danych.' }); }
});

app.delete('/api/trips/:id', requireAuth, tripPerm, async (req, res) => {
  const row = await dbGet(`DELETE FROM trips WHERE id = $1 AND unit_id = $2 RETURNING id`, [req.params.id, req.user.unitId]);
  if (!row) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });
  await logAudit(req.user.unitId, req.user.name, 'Usunięto: wyjazd', '');
  res.status(204).end();
});

// Pojazdy przypisane do konkretnego wyjazdu (jeden wyjazd = wiele pojazdów,
// każdy z własną załogą). Zwracamy od razu imiona dowódcy/kierowcy przez JOIN
// — ratowników (lista ID) front-end dopasowuje sam do już wczytanej listy strażaków.
app.get('/api/trip-vehicles', requireAuth, tripPerm, async (req, res) => {
  const rows = await dbAll(`
    SELECT tv.*, cf.first AS commander_first, cf.last AS commander_last,
           df.first AS driver_first, df.last AS driver_last
    FROM trip_vehicles tv
    LEFT JOIN firefighters cf ON cf.id = tv.commander_id
    LEFT JOIN firefighters df ON df.id = tv.driver_id
    WHERE tv.unit_id = $1
  `, [req.user.unitId]);
  res.json(rows);
});

app.post('/api/trip-vehicles', requireAuth, tripPerm, validateBody({
  trip_id: { required: true, type: 'string', max: 100 },
  vehicle_name: { type: 'string', max: 150 },
  mileage_after: { type: 'nonNegativeNumber' },
  engine_hours: { type: 'nonNegativeNumber' },
}), async (req, res) => {
  const trip = await dbGet(`SELECT id FROM trips WHERE id = $1 AND unit_id = $2`, [req.body.trip_id, req.user.unitId]);
  if (!trip) return res.status(404).json({ error: 'Nie znaleziono wyjazdu.' });
  const id = uuid();
  await dbRun(
    `INSERT INTO trip_vehicles (id, unit_id, trip_id, vehicle_id, vehicle_name, mileage_after, engine_hours, commander_id, driver_id, rescuer_ids)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [id, req.user.unitId, req.body.trip_id, req.body.vehicle_id || null, req.body.vehicle_name || null,
     req.body.mileage_after ?? null, req.body.engine_hours ?? null, req.body.commander_id || null, req.body.driver_id || null,
     req.body.rescuer_ids ?? '[]']
  );
  const row = await dbGet(`SELECT * FROM trip_vehicles WHERE id = $1`, [id]);
  await logAudit(req.user.unitId, req.user.name, 'Dodano pojazd do wyjazdu', row.vehicle_name || '');
  res.status(201).json(row);
});

app.put('/api/trip-vehicles/:id', requireAuth, tripPerm, async (req, res) => {
  const existing = await dbGet(`SELECT id FROM trip_vehicles WHERE id = $1 AND unit_id = $2`, [req.params.id, req.user.unitId]);
  if (!existing) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });
  await dbRun(
    `UPDATE trip_vehicles SET vehicle_id=$1, vehicle_name=$2, mileage_after=$3, engine_hours=$4, commander_id=$5, driver_id=$6, rescuer_ids=$7 WHERE id=$8`,
    [req.body.vehicle_id || null, req.body.vehicle_name || null, req.body.mileage_after ?? null, req.body.engine_hours ?? null,
     req.body.commander_id || null, req.body.driver_id || null, req.body.rescuer_ids ?? '[]', req.params.id]
  );
  const row = await dbGet(`SELECT * FROM trip_vehicles WHERE id = $1`, [req.params.id]);
  res.json(row);
});

app.delete('/api/trip-vehicles/:id', requireAuth, tripPerm, async (req, res) => {
  const row = await dbGet(`DELETE FROM trip_vehicles WHERE id = $1 AND unit_id = $2 RETURNING id`, [req.params.id, req.user.unitId]);
  if (!row) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });
  res.status(204).end();
});

app.use('/api/schedule', crudRoutes({
  table: 'schedule', fields: ['type', 'date', 'description'],
  writeRoles: ['Zarząd'], permissionFlag: 'schedule', auditLabel: 'wydarzenie w terminarzu',
  rules: {
    date: { required: true, type: 'date' },
    description: { type: 'string', max: 500 },
  },
}));

app.use('/api/dues', crudRoutes({
  table: 'dues', fields: ['firefighter_id', 'firefighter_name', 'month', 'amount', 'status'],
  writeRoles: ['Zarząd', 'Skarbnik'], permissionFlag: 'dues', auditLabel: 'wpłata składki',
  rules: {
    month: { required: true, type: 'month' },
    amount: { required: true, type: 'positiveNumber' },
    status: { type: 'enum', enum: ['ok', 'warn'] },
  },
}));

app.use('/api/mdp-members', crudRoutes({
  table: 'mdp_members', fields: ['first', 'last', 'dob'],
  readRoles: ['Zarząd'], writeRoles: ['Zarząd'], permissionFlag: 'mdp', auditLabel: 'członek MDP',
  rules: {
    first: { required: true, type: 'string', max: 100 },
    last: { required: true, type: 'string', max: 100 },
    dob: { type: 'date' },
  },
}));

app.use('/api/mdp-meetings', crudRoutes({
  table: 'mdp_meetings', fields: ['date', 'topic', 'present'],
  readRoles: ['Zarząd'], writeRoles: ['Zarząd'], permissionFlag: 'mdp', auditLabel: 'zebranie MDP',
  rules: {
    date: { required: true, type: 'date' },
    present: { type: 'nonNegativeNumber' },
  },
}));

app.use('/api/tasks', crudRoutes({
  table: 'tasks', fields: ['title', 'description', 'assignee_id', 'assignee_name', 'due', 'priority', 'status'],
  writeRoles: ['Zarząd', 'Skarbnik', 'Strażak'], auditLabel: 'zadanie',
  rules: {
    title: { required: true, type: 'string', max: 200 },
    due: { type: 'date' },
    priority: { type: 'enum', enum: ['Niski', 'Średni', 'Wysoki'] },
    status: { type: 'enum', enum: ['Do zrobienia', 'W trakcie', 'Zrobione'] },
  },
}));

// Ogłoszenia: czyta cała jednostka, publikuje i usuwa tylko Zarząd (albo
// osoba z jawnie nadaną flagą 'announcements').
app.use('/api/announcements', crudRoutes({
  table: 'announcements', fields: ['title', 'body', 'author_name', 'pinned'],
  writeRoles: ['Zarząd'], permissionFlag: 'announcements', auditLabel: 'ogłoszenie',
  rules: {
    title: { required: true, type: 'string', max: 200 },
  },
}));

// Ćwiczenia: osobny moduł od Wyjazdów — szkolenia i treningi jednostki,
// z frekwencją i czasem trwania. Widoczne dla wszystkich ról (jak Terminarz),
// zapis tylko Zarząd (albo osoba z flagą 'exercises').
app.use('/api/exercises', crudRoutes({
  table: 'exercises', fields: ['date', 'topic', 'type', 'duration_hours', 'participants', 'notes'],
  writeRoles: ['Zarząd'], permissionFlag: 'exercises', auditLabel: 'ćwiczenie',
  rules: {
    date: { required: true, type: 'date' },
    topic: { type: 'string', max: 200 },
    duration_hours: { type: 'nonNegativeNumber' },
    participants: { type: 'nonNegativeNumber' },
  },
}));

/* Zapotrzebowanie / zakupy — celowo NIE generyczny crudRoutes, bo zgłaszanie
   potrzeby jest otwarte dla każdej roli (każdy strażak może zauważyć brak
   sprzętu), a zmiana statusu/edycja/usunięcie to już decyzja Zarządu (albo
   osoby z nadaną flagą 'purchases'). To asymetria, której generyczny
   crudRoutes nie obsługuje (ten sam zestaw ról dla POST i PUT/DELETE). */
const purchasePerm = requireRoleOrPermission(['Zarząd'], 'purchases');
const purchaseCreateValidator = validateBody({
  name: { required: true, type: 'string', max: 200 },
  quantity: { type: 'positiveNumber' },
  description: { type: 'string', max: 1000 },
});
// Przy edycji (PUT) `name` NIE jest wymagane — Zarząd często chce zmienić
// tylko status, bez przepisywania całego zgłoszenia od nowa.
const purchaseUpdateValidator = validateBody({
  name: { type: 'string', max: 200 },
  quantity: { type: 'positiveNumber' },
  description: { type: 'string', max: 1000 },
  status: { type: 'enum', enum: ['Nowe', 'Zatwierdzone', 'Odrzucone', 'Zrealizowane'] },
});

app.get('/api/purchases', requireAuth, async (req, res) => {
  const rows = await dbAll(`SELECT * FROM purchase_requests WHERE unit_id = $1 ORDER BY created_at DESC`, [req.user.unitId]);
  res.json(rows);
});

app.post('/api/purchases', requireAuth, purchaseCreateValidator, async (req, res) => {
  const id = uuid();
  const quantity = req.body.quantity ? Math.round(Number(req.body.quantity)) : 1;
  await dbRun(
    `INSERT INTO purchase_requests (id, unit_id, name, quantity, description, reported_by_name) VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, req.user.unitId, req.body.name.trim(), quantity, req.body.description || null, req.user.name]
  );
  const row = await dbGet(`SELECT * FROM purchase_requests WHERE id = $1`, [id]);
  await logAudit(req.user.unitId, req.user.name, 'Zgłoszono zapotrzebowanie', req.body.name.trim());
  res.status(201).json(row);
});

app.put('/api/purchases/:id', requireAuth, purchasePerm, purchaseUpdateValidator, async (req, res) => {
  const existing = await dbGet(`SELECT * FROM purchase_requests WHERE id = $1 AND unit_id = $2`, [req.params.id, req.user.unitId]);
  if (!existing) return res.status(404).json({ error: 'Nie znaleziono zgłoszenia.' });
  const quantity = req.body.quantity ? Math.round(Number(req.body.quantity)) : existing.quantity;
  await dbRun(
    `UPDATE purchase_requests SET name=$1, quantity=$2, description=$3, status=$4 WHERE id=$5`,
    [req.body.name ? req.body.name.trim() : existing.name, quantity, req.body.description ?? existing.description,
     req.body.status || existing.status, req.params.id]
  );
  const row = await dbGet(`SELECT * FROM purchase_requests WHERE id = $1`, [req.params.id]);
  await logAudit(req.user.unitId, req.user.name, 'Zmieniono zapotrzebowanie', `${row.name} → ${row.status}`);
  res.json(row);
});

app.delete('/api/purchases/:id', requireAuth, purchasePerm, async (req, res) => {
  const row = await dbGet(`DELETE FROM purchase_requests WHERE id = $1 AND unit_id = $2 RETURNING id`, [req.params.id, req.user.unitId]);
  if (!row) return res.status(404).json({ error: 'Nie znaleziono zgłoszenia.' });
  await logAudit(req.user.unitId, req.user.name, 'Usunięto zapotrzebowanie', '');
  res.status(204).end();
});

// ---------- USTAWIENIA JEDNOSTKI ----------
// Kod gminy — dowolny, wspólny ciąg znaków, który Zarząd ustala samodzielnie.
// Jednostki z tym samym kodem grupują się razem w panelu gminy (patrz niżej).
app.put('/api/unit/settings', requireAuth, requireRole('Zarząd'), validateBody({
  gmina_code: { type: 'string', max: 100 },
}), async (req, res) => {
  const gminaCode = (req.body.gmina_code || '').trim() || null;
  await dbRun(`UPDATE units SET gmina_code = $1 WHERE id = $2`, [gminaCode, req.user.unitId]);
  await logAudit(req.user.unitId, req.user.name, 'Zmieniono ustawienia jednostki', gminaCode ? `kod gminy: ${gminaCode}` : 'usunięto kod gminy');
  res.json({ ok: true, gminaCode });
});

/* ---------- PANEL GMINY ----------
   Zupełnie osobny system logowania od kont jednostek — token ma inny "kind"
   (patrz auth.js), więc token strażaka nigdy nie zadziała tutaj i odwrotnie.
   Konto gminne widzi tylko ZAGREGOWANE liczby dla jednostek ze swoim kodem
   gminy — nie ma dostępu do pełnych, szczegółowych danych żadnej jednostki
   (żadnych nazwisk, żadnych operacyjnych szczegółów wyjazdów). To świadomy
   wybór: nadzór na poziomie gminy nie powinien oznaczać podglądu wszystkiego. */
app.post('/api/gmina/auth/register', authLimiter, validateBody({
  name: { required: true, type: 'string', max: 200 },
  email: { required: true, type: 'email' },
  password: { required: true, type: 'password' },
}), async (req, res) => {
  const { name, password } = req.body;
  const emailLower = req.body.email.trim().toLowerCase();
  const existing = await dbGet(`SELECT id FROM gmina_accounts WHERE email = $1`, [emailLower]);
  if (existing) return res.status(409).json({ error: 'Konto z tym adresem e-mail już istnieje.' });

  let gminaCode = null;
  for (let attempt = 0; attempt < 5 && !gminaCode; attempt++) {
    const candidate = generateGminaCode(24);
    const clash = await dbGet(`SELECT id FROM gmina_accounts WHERE gmina_code = $1`, [candidate]);
    if (!clash) gminaCode = candidate;
  }
  if (!gminaCode) return res.status(500).json({ error: 'Nie udało się wygenerować unikalnego kodu gminy. Spróbuj ponownie.' });

  const id = uuid();
  const passwordHash = await bcrypt.hash(password, 12);
  await dbRun(
    `INSERT INTO gmina_accounts (id, gmina_code, name, email, password_hash) VALUES ($1,$2,$3,$4,$5)`,
    [id, gminaCode, name.trim(), emailLower, passwordHash]
  );
  const account = { id, gmina_code: gminaCode, name: name.trim(), email: emailLower };
  res.status(201).json({ token: signGminaToken(account), account: { id, gminaCode, name: name.trim(), email: emailLower } });
});

app.post('/api/gmina/auth/login', strictAuthLimiter, validateBody({
  email: { required: true, type: 'email' },
  password: { required: true, type: 'string', max: 200 },
}), async (req, res) => {
  const emailLower = req.body.email.trim().toLowerCase();
  const account = await dbGet(`SELECT * FROM gmina_accounts WHERE email = $1`, [emailLower]);
  if (!account) return res.status(401).json({ error: 'Nie znaleziono konta z tym adresem e-mail.' });
  if (!(await bcrypt.compare(req.body.password, account.password_hash))) {
    return res.status(401).json({ error: 'Nieprawidłowe hasło.' });
  }
  res.json({
    token: signGminaToken(account),
    account: { id: account.id, gminaCode: account.gmina_code, name: account.name, email: account.email },
  });
});

/* Regeneracja kodu gminy na żądanie (przycisk w panelu). Celowo NIE zrywa
   już podłączonych jednostek — razem z kontem(-ami) gminy przepisujemy też
   wszystkie jednostki, które miały stary kod, na nowy, w jednej transakcji.
   Token zwracany w odpowiedzi trzeba od razu podmienić po stronie
   przeglądarki — stary token niesie już nieaktualny kod. */
app.post('/api/gmina/regenerate-code', authLimiter, requireGminaAuth, async (req, res) => {
  const oldCode = req.gmina.gminaCode;
  let newCode = null;
  for (let attempt = 0; attempt < 5 && !newCode; attempt++) {
    const candidate = generateGminaCode(24);
    const clash = await dbGet(`SELECT id FROM gmina_accounts WHERE gmina_code = $1`, [candidate]);
    if (!clash) newCode = candidate;
  }
  if (!newCode) return res.status(500).json({ error: 'Nie udało się wygenerować nowego kodu. Spróbuj ponownie.' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE gmina_accounts SET gmina_code = $1 WHERE gmina_code = $2`, [newCode, oldCode]);
    await client.query(`UPDATE units SET gmina_code = $1 WHERE gmina_code = $2`, [newCode, oldCode]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Błąd regeneracji kodu gminy:', e.message);
    return res.status(500).json({ error: 'Nie udało się zaktualizować kodu. Spróbuj ponownie.' });
  } finally {
    client.release();
  }
  const freshAccount = { id: req.gmina.id, gmina_code: newCode, name: req.gmina.name, email: req.gmina.email };
  res.json({ gminaCode: newCode, token: signGminaToken(freshAccount) });
});

app.get('/api/gmina/overview', requireGminaAuth, async (req, res) => {
  const units = await dbAll(`SELECT id, name, created_at FROM units WHERE gmina_code = $1 ORDER BY name`, [req.gmina.gminaCode]);
  const overview = await Promise.all(units.map(async (unit) => {
    const [firefighters, vehicles, gear, trips90d, exercises90d] = await Promise.all([
      dbGet(`SELECT COUNT(*)::int AS n FROM firefighters WHERE unit_id = $1`, [unit.id]),
      dbGet(`SELECT COUNT(*)::int AS n FROM vehicles WHERE unit_id = $1`, [unit.id]),
      dbGet(`SELECT COUNT(*)::int AS n FROM gear WHERE unit_id = $1`, [unit.id]),
      dbGet(`SELECT COUNT(*)::int AS n FROM trips WHERE unit_id = $1 AND date >= to_char(NOW() - INTERVAL '90 days', 'YYYY-MM-DD')`, [unit.id]),
      dbGet(`SELECT COUNT(*)::int AS n FROM exercises WHERE unit_id = $1 AND date >= to_char(NOW() - INTERVAL '90 days', 'YYYY-MM-DD')`, [unit.id]),
    ]);
    return {
      id: unit.id, name: unit.name, createdAt: unit.created_at,
      firefighterCount: firefighters.n, vehicleCount: vehicles.n, gearCount: gear.n,
      trips90d: trips90d.n, exercises90d: exercises90d.n,
    };
  }));
  res.json({ gminaCode: req.gmina.gminaCode, units: overview });
});

// Czas trwania wyjazdu w godzinach (liczba dziesiętna), z obsługą przypadku
// gdy powrót jest po północy (np. wyjazd 23:40 -> powrót 00:20). Zwraca null,
// gdy brakuje którejś z godzin — takiego wyjazdu nie da się policzyć.
function tripDurationHours(departureTime, returnTime) {
  if (!departureTime || !returnTime) return null;
  const dm = /^(\d{1,2}):(\d{2})$/.exec(departureTime);
  const rm = /^(\d{1,2}):(\d{2})$/.exec(returnTime);
  if (!dm || !rm) return null;
  let startMin = Number(dm[1]) * 60 + Number(dm[2]);
  let endMin = Number(rm[1]) * 60 + Number(rm[2]);
  if (endMin < startMin) endMin += 24 * 60; // powrót po północy
  return (endMin - startMin) / 60;
}

app.get('/api/gmina/settings', requireGminaAuth, async (req, res) => {
  const row = await dbGet(`SELECT rate_per_hour, rounding_method FROM gmina_settings WHERE gmina_code = $1`, [req.gmina.gminaCode]);
  res.json(row || { rate_per_hour: 0, rounding_method: 'ceil_per_trip' });
});

app.put('/api/gmina/settings', requireGminaAuth, validateBody({
  rate_per_hour: { type: 'nonNegativeNumber' },
  rounding_method: { type: 'enum', enum: ['ceil_per_trip', 'sum_exact'] },
}), async (req, res) => {
  const rate = req.body.rate_per_hour ?? 0;
  const method = req.body.rounding_method || 'ceil_per_trip';
  await dbRun(`
    INSERT INTO gmina_settings (gmina_code, rate_per_hour, rounding_method, updated_at)
    VALUES ($1,$2,$3,NOW())
    ON CONFLICT (gmina_code) DO UPDATE SET rate_per_hour = $2, rounding_method = $3, updated_at = NOW()
  `, [req.gmina.gminaCode, rate, method]);
  res.json({ rate_per_hour: rate, rounding_method: method });
});

// Lista wyjazdów jednostek tej gminy z ostatnich 6 miesięcy, z policzonym
// czasem trwania każdego — do wyliczenia ekwiwalentu. Celowo BEZ adresu,
// opisu, załogi czy innych szczegółów operacyjnych — tylko to, co potrzebne
// do rozliczenia czasu (data, rodzaj, godziny, czas trwania).
app.get('/api/gmina/trips', requireGminaAuth, async (req, res) => {
  const units = await dbAll(`SELECT id, name FROM units WHERE gmina_code = $1 ORDER BY name`, [req.gmina.gminaCode]);
  const settings = (await dbGet(`SELECT rate_per_hour, rounding_method FROM gmina_settings WHERE gmina_code = $1`, [req.gmina.gminaCode]))
    || { rate_per_hour: 0, rounding_method: 'ceil_per_trip' };
  if (!units.length) return res.json({ trips: [], settings });
  const unitIds = units.map(u => u.id);
  const unitNameById = Object.fromEntries(units.map(u => [u.id, u.name]));
  const sixMonthsAgo = new Date();
  sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
  const cutoff = sixMonthsAgo.toISOString().slice(0, 10);
  const rows = await dbAll(
    `SELECT id, unit_id, date, type, departure_time, return_time FROM trips
     WHERE unit_id = ANY($1) AND date >= $2 ORDER BY date DESC`,
    [unitIds, cutoff]
  );
  const trips = rows.map(t => ({
    id: t.id, unitName: unitNameById[t.unit_id], date: t.date, type: t.type,
    departureTime: t.departure_time, returnTime: t.return_time,
    durationHours: tripDurationHours(t.departure_time, t.return_time),
  }));
  res.json({ trips, settings });
});

// ---------- KONTA UŻYTKOWNIKÓW ----------
// Uprawnienia, które Zarząd może nadać pojedynczej osobie niezależnie od jej
// roli bazowej — każda flaga daje pełny (odczyt+zapis) dostęp do jednego
// modułu. Konta i Historia są celowo NIE do nadania — to zawsze wyłącznie
// Zarząd, bo dotyczą zarządzania innymi kontami i pełnego dziennika zdarzeń.
const GRANTABLE_PERMISSIONS = ['firefighters', 'fleet', 'gear', 'trips', 'schedule', 'dues', 'mdp', 'structure', 'exercises', 'announcements', 'purchases'];

app.get('/api/users', requireAuth, requireRole('Zarząd'), async (req, res) => {
  const rows = await dbAll(`SELECT id, name, email, role, permissions FROM users WHERE unit_id = $1`, [req.user.unitId]);
  res.json(rows);
});

app.post('/api/users', requireAuth, requireRole('Zarząd'), validateBody({
  name: { required: true, type: 'string', max: 200 },
  email: { required: true, type: 'email' },
  password: { required: true, type: 'password' },
  role: { required: true, type: 'enum', enum: ['Zarząd', 'Skarbnik', 'Strażak'] },
}), async (req, res) => {
  const { name, email, password, role } = req.body;
  const emailLower = email.trim().toLowerCase();
  if (await dbGet(`SELECT id FROM users WHERE email = $1`, [emailLower])) {
    return res.status(409).json({ error: 'Konto z tym adresem e-mail już istnieje.' });
  }
  const id = uuid();
  const passwordHash = await bcrypt.hash(password, 12);
  await dbRun(
    `INSERT INTO users (id, unit_id, name, email, password_hash, role) VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, req.user.unitId, name.trim(), emailLower, passwordHash, role]
  );
  await logAudit(req.user.unitId, req.user.name, 'Utworzono konto użytkownika', `${name} (${role})`);
  res.status(201).json({ id, name: name.trim(), email: emailLower, role, permissions: {} });
});

app.put('/api/users/:id', requireAuth, requireRole('Zarząd'), validateBody({
  name: { type: 'string', max: 200 },
  email: { type: 'email' },
  password: { type: 'password' },
  role: { type: 'enum', enum: ['Zarząd', 'Skarbnik', 'Strażak'] },
}), async (req, res) => {
  const target = await dbGet(`SELECT * FROM users WHERE id = $1 AND unit_id = $2`, [req.params.id, req.user.unitId]);
  if (!target) return res.status(404).json({ error: 'Nie znaleziono konta.' });
  const { name, email, password, role } = req.body || {};
  if (email) {
    const emailLower = email.trim().toLowerCase();
    const clash = await dbGet(`SELECT id FROM users WHERE email = $1 AND id != $2`, [emailLower, req.params.id]);
    if (clash) return res.status(409).json({ error: 'Ten adres e-mail jest już używany przez inne konto.' });
  }
  const passwordHash = password ? await bcrypt.hash(password, 12) : target.password_hash;
  const emailLower = (email || target.email).trim().toLowerCase();
  await dbRun(
    `UPDATE users SET name=$1, email=$2, password_hash=$3, role=$4 WHERE id=$5`,
    [name || target.name, emailLower, passwordHash, role || target.role, req.params.id]
  );
  await logAudit(req.user.unitId, req.user.name, 'Edytowano konto użytkownika', name || target.name);
  res.json({ ok: true });
});

// Nadawanie/cofanie granularnych uprawnień — osobna trasa od edycji samego
// konta, bo to inny rodzaj decyzji (co ta osoba może robić, nie kim jest).
// Wejściowy obiekt jest czyszczony do wyłącznie znanych, dozwolonych flag —
// nikt nie wstrzyknie tu dowolnego klucza z ciała żądania.
app.put('/api/users/:id/permissions', requireAuth, requireRole('Zarząd'), async (req, res) => {
  const target = await dbGet(`SELECT id, name, role FROM users WHERE id = $1 AND unit_id = $2`, [req.params.id, req.user.unitId]);
  if (!target) return res.status(404).json({ error: 'Nie znaleziono konta.' });
  const input = (req.body && typeof req.body.permissions === 'object' && !Array.isArray(req.body.permissions)) ? req.body.permissions : {};
  const clean = {};
  for (const key of GRANTABLE_PERMISSIONS) {
    if (input[key] === true) clean[key] = true;
  }
  await dbRun(`UPDATE users SET permissions = $1 WHERE id = $2`, [JSON.stringify(clean), req.params.id]);
  await logAudit(req.user.unitId, req.user.name, 'Zmieniono uprawnienia konta', `${target.name}: ${Object.keys(clean).join(', ') || 'brak dodatkowych uprawnień'}`);
  res.json({ ok: true, permissions: clean });
});

app.delete('/api/users/:id', requireAuth, requireRole('Zarząd'), async (req, res) => {
  const target = await dbGet(`SELECT * FROM users WHERE id = $1 AND unit_id = $2`, [req.params.id, req.user.unitId]);
  if (!target) return res.status(404).json({ error: 'Nie znaleziono konta.' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'Nie możesz usunąć własnego konta, na którym jesteś zalogowany.' });
  const { n } = await dbGet(`SELECT COUNT(*)::int AS n FROM users WHERE unit_id = $1 AND role = 'Zarząd'`, [req.user.unitId]);
  if (target.role === 'Zarząd' && n <= 1) return res.status(400).json({ error: 'To jedyne konto z rolą Zarząd — nie można go usunąć.' });
  await dbRun(`DELETE FROM users WHERE id = $1`, [req.params.id]);
  await logAudit(req.user.unitId, req.user.name, 'Usunięto konto użytkownika', target.name);
  res.status(204).end();
});

// ---------- HISTORIA DZIAŁAŃ ----------
app.get('/api/audit', requireAuth, requireRole('Zarząd'), async (req, res) => {
  const rows = await dbAll(`SELECT * FROM audit_log WHERE unit_id = $1 ORDER BY ts DESC LIMIT 300`, [req.user.unitId]);
  res.json(rows);
});

/* ---------- KOPIA ZAPASOWA ----------
   Na Postgresie (w odróżnieniu od SQLite) nie robimy już własnej migawki
   pliku bazy — to zadanie należy do dostawcy bazy (Koyeb/Neon/Supabase
   zwykle same robią kopie danych). Zostaje pełny, przenośny eksport JSON
   danych jednostki na żądanie — działa niezależnie od tego, kto hostuje bazę. */
app.get('/api/backup/full', requireAuth, requireRole('Zarząd'), async (req, res) => {
  const unitId = req.user.unitId;
  const tables = {
    firefighters: 'firefighters', vehicles: 'vehicles', fuel: 'fuel_log', gear: 'gear',
    trips: 'trips', schedule: 'schedule', dues: 'dues', mdpMembers: 'mdp_members',
    mdpMeetings: 'mdp_meetings', tasks: 'tasks', announcements: 'announcements', sections: 'sections', exercises: 'exercises', tripVehicles: 'trip_vehicles', purchases: 'purchase_requests',
  };
  const data = {};
  for (const [key, table] of Object.entries(tables)) {
    data[key] = await dbAll(`SELECT * FROM ${table} WHERE unit_id = $1`, [unitId]);
  }
  data.users = await dbAll(`SELECT id, name, email, role FROM users WHERE unit_id = $1`, [unitId]);
  data.sectionMembers = await dbAll(`SELECT * FROM section_members WHERE unit_id = $1`, [unitId]);
  data.auditLog = await dbAll(`SELECT * FROM audit_log WHERE unit_id = $1 ORDER BY ts DESC LIMIT 300`, [unitId]);
  const unit = await dbGet(`SELECT * FROM units WHERE id = $1`, [unitId]);
  res.json({ app: 'Firefighter24', exportedAt: new Date().toISOString(), unit, data });
});

/* ---------- PANEL ADMINISTRATORA PLATFORMY ----------
   To jest celowo ODDZIELONE od ról w obrębie jednostek (Zarząd/Skarbnik/
   Strażak) — te są zamknięte w swojej jednostce i tak powinno zostać.
   Ten dostęp jest dla operatora całej platformy (Ciebie), żeby widzieć
   wszystkie zarejestrowane jednostki naraz. Zabezpieczony osobnym sekretem
   w nagłówku, nie tokenem JWT żadnego użytkownika. Jeśli ADMIN_SECRET nie
   jest ustawiony w zmiennych środowiskowych, ten panel jest całkowicie
   wyłączony (nie działa "otwarty", tylko odmawia dostępu). */
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zbyt wiele prób. Spróbuj ponownie za kilka minut.' },
});
function requireAdminSecret(req, res, next) {
  const secret = process.env.ADMIN_SECRET;
  if (!secret) return res.status(503).json({ error: 'Panel administratora nie jest skonfigurowany (brak ADMIN_SECRET w zmiennych środowiskowych).' });
  const provided = req.headers['x-admin-secret'];
  if (!provided || provided !== secret) return res.status(401).json({ error: 'Nieprawidłowy klucz administratora.' });
  next();
}

app.get('/api/admin/units', adminLimiter, requireAdminSecret, async (req, res) => {
  const rows = await dbAll(`
    SELECT
      u.id,
      u.name,
      u.created_at,
      (SELECT COUNT(*) FROM users WHERE unit_id = u.id)::int AS user_count,
      (SELECT COUNT(*) FROM firefighters WHERE unit_id = u.id)::int AS firefighter_count
    FROM units u
    ORDER BY u.created_at DESC
  `);
  res.json(rows);
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'firefighter24-backend', db: 'postgres', emailConfigured: EMAIL_CONFIGURED, emailMode: EMAIL_MODE });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'Baza danych niedostępna.' });
  }
});

initSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Firefighter24 API działa na porcie ${PORT} (PostgreSQL)`);
      if (!EMAIL_CONFIGURED) console.log('Uwaga: brak RESEND_API_KEY i SMTP_HOST — reset hasła działa w trybie deweloperskim.');
    });
  })
  .catch((e) => {
    console.error('Nie udało się zainicjować schematu bazy danych:', e.message);
    process.exit(1);
  });
