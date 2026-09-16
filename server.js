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
const { signToken, requireAuth, requireRole } = require('./auth');
const { validateBody } = require('./validation');
const { sendEmail, EMAIL_CONFIGURED, EMAIL_MODE } = require('./email');

const app = express();
app.use(cors());
app.use(express.json());
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
  const passwordHash = bcrypt.hashSync(password, 12);

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
    user: { id: userId, name: name.trim(), email: emailLower, role: 'Zarząd' },
    unit: { id: unitId, name: unitName.trim() },
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
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Nieprawidłowe hasło.' });
  }
  const unit = await dbGet(`SELECT * FROM units WHERE id = $1`, [user.unit_id]);
  await logAudit(user.unit_id, user.name, 'Zalogowano się', user.email);
  res.json({
    token: signToken(user),
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
    unit: { id: unit.id, name: unit.name },
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

  if (emailResult.devMode) {
    return res.json({ ...genericOk, devToken: rawToken, devNote: 'RESEND_API_KEY nie jest ustawiony — token zwrócony tylko do celów testowych.' });
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

  const passwordHash = bcrypt.hashSync(newPassword, 12);
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
  const user = await dbGet(`SELECT id, name, email, role FROM users WHERE id = $1`, [req.user.id]);
  const unit = await dbGet(`SELECT id, name FROM units WHERE id = $1`, [req.user.unitId]);
  res.json({ user, unit });
});

/* ---------- POMOCNICZY GENERATOR TRAS CRUD ----------
   Każdy zasób jednostki (strażacy, sprzęt, pojazdy...) ma ten sam kształt:
   lista/dodaj/edytuj/usuń, zawsze filtrowane po unit_id z tokenu. */
function crudRoutes({ table, fields, writeRoles, auditLabel, rules }) {
  const router = express.Router();
  const validator = rules ? validateBody(rules) : (req, res, next) => next();

  router.get('/', requireAuth, async (req, res) => {
    try {
      const rows = await dbAll(`SELECT * FROM ${table} WHERE unit_id = $1`, [req.user.unitId]);
      res.json(rows);
    } catch (e) { res.status(500).json({ error: 'Błąd odczytu danych.' }); }
  });

  router.post('/', requireAuth, requireRole(...writeRoles), validator, async (req, res) => {
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

  router.put('/:id', requireAuth, requireRole(...writeRoles), validator, async (req, res) => {
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

  router.delete('/:id', requireAuth, requireRole(...writeRoles), async (req, res) => {
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
  table: 'firefighters', fields: ['first', 'last', 'role', 'join_date', 'med_date'],
  writeRoles: ['Zarząd'], auditLabel: 'strażak',
  rules: {
    first: { required: true, type: 'string', max: 100 },
    last: { required: true, type: 'string', max: 100 },
    role: { type: 'string', max: 100 },
    join_date: { type: 'date' },
    med_date: { type: 'date' },
  },
}));

app.use('/api/vehicles', crudRoutes({
  table: 'vehicles', fields: ['name', 'plate', 'oc_date', 'review_date', 'mileage'],
  writeRoles: ['Zarząd'], auditLabel: 'pojazd',
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
  writeRoles: ['Zarząd'], auditLabel: 'tankowanie',
  rules: {
    date: { required: true, type: 'date' },
    liters: { required: true, type: 'positiveNumber' },
    cost: { type: 'nonNegativeNumber' },
  },
}));

app.use('/api/gear', crudRoutes({
  table: 'gear', fields: ['name', 'category', 'review_date'],
  writeRoles: ['Zarząd'], auditLabel: 'sprzęt',
  rules: {
    name: { required: true, type: 'string', max: 150 },
    review_date: { type: 'date' },
  },
}));

app.use('/api/trips', crudRoutes({
  table: 'trips', fields: ['date', 'type', 'place', 'crew'],
  writeRoles: ['Zarząd'], auditLabel: 'wyjazd',
  rules: {
    date: { required: true, type: 'date' },
    place: { type: 'string', max: 200 },
  },
}));

app.use('/api/schedule', crudRoutes({
  table: 'schedule', fields: ['type', 'date', 'description'],
  writeRoles: ['Zarząd'], auditLabel: 'wydarzenie w terminarzu',
  rules: {
    date: { required: true, type: 'date' },
    description: { type: 'string', max: 500 },
  },
}));

app.use('/api/dues', crudRoutes({
  table: 'dues', fields: ['firefighter_id', 'firefighter_name', 'month', 'amount', 'status'],
  writeRoles: ['Zarząd', 'Skarbnik'], auditLabel: 'wpłata składki',
  rules: {
    month: { required: true, type: 'month' },
    amount: { required: true, type: 'positiveNumber' },
    status: { type: 'enum', enum: ['ok', 'warn'] },
  },
}));

app.use('/api/mdp-members', crudRoutes({
  table: 'mdp_members', fields: ['first', 'last', 'dob'],
  writeRoles: ['Zarząd'], auditLabel: 'członek MDP',
  rules: {
    first: { required: true, type: 'string', max: 100 },
    last: { required: true, type: 'string', max: 100 },
    dob: { type: 'date' },
  },
}));

app.use('/api/mdp-meetings', crudRoutes({
  table: 'mdp_meetings', fields: ['date', 'topic', 'present'],
  writeRoles: ['Zarząd'], auditLabel: 'zebranie MDP',
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

// ---------- KONTA UŻYTKOWNIKÓW ----------
app.get('/api/users', requireAuth, requireRole('Zarząd'), async (req, res) => {
  const rows = await dbAll(`SELECT id, name, email, role FROM users WHERE unit_id = $1`, [req.user.unitId]);
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
  await dbRun(
    `INSERT INTO users (id, unit_id, name, email, password_hash, role) VALUES ($1,$2,$3,$4,$5,$6)`,
    [id, req.user.unitId, name.trim(), emailLower, bcrypt.hashSync(password, 12), role]
  );
  await logAudit(req.user.unitId, req.user.name, 'Utworzono konto użytkownika', `${name} (${role})`);
  res.status(201).json({ id, name: name.trim(), email: emailLower, role });
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
  const passwordHash = password ? bcrypt.hashSync(password, 12) : target.password_hash;
  const emailLower = (email || target.email).trim().toLowerCase();
  await dbRun(
    `UPDATE users SET name=$1, email=$2, password_hash=$3, role=$4 WHERE id=$5`,
    [name || target.name, emailLower, passwordHash, role || target.role, req.params.id]
  );
  await logAudit(req.user.unitId, req.user.name, 'Edytowano konto użytkownika', name || target.name);
  res.json({ ok: true });
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
    mdpMeetings: 'mdp_meetings', tasks: 'tasks',
  };
  const data = {};
  for (const [key, table] of Object.entries(tables)) {
    data[key] = await dbAll(`SELECT * FROM ${table} WHERE unit_id = $1`, [unitId]);
  }
  data.users = await dbAll(`SELECT id, name, email, role FROM users WHERE unit_id = $1`, [unitId]);
  data.auditLog = await dbAll(`SELECT * FROM audit_log WHERE unit_id = $1 ORDER BY ts DESC LIMIT 300`, [unitId]);
  const unit = await dbGet(`SELECT * FROM units WHERE id = $1`, [unitId]);
  res.json({ app: 'Firefighter24', exportedAt: new Date().toISOString(), unit, data });
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
