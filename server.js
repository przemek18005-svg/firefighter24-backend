// server.js — REST API dla Firefighter24.
// Zastępuje warstwę localStorage z prototypu frontendowego prawdziwym serwerem:
// hasła haszowane bcryptem (nie SHA-256 bez soli), role egzekwowane po stronie
// serwera (nie da się ich obejść konsolą przeglądarki), dane współdzielone
// między urządzeniami zamiast zamknięte w jednej przeglądarce.
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const { v4: uuid } = require('uuid');
const db = require('./db');
const { signToken, requireAuth, requireRole } = require('./auth');
const { validateBody, isValidEmail, isValidPassword } = require('./validation');
const { sendEmail, EMAIL_CONFIGURED } = require('./email');

const app = express();
app.use(cors());
app.use(express.json());
app.set('trust proxy', 1); // Railway stoi za reverse proxy — potrzebne, żeby rate-limit widział prawdziwe IP, nie IP proxy

const PORT = process.env.PORT || 3001;

function logAudit(unitId, userName, action, details) {
  db.prepare(`INSERT INTO audit_log (id, unit_id, user_name, action, details) VALUES (?,?,?,?,?)`)
    .run(uuid(), unitId, userName, action, details || '');
}

/* ---------- LIMIT PRÓB (rate limiting) ----------
   Chroni przed automatycznym zgadywaniem haseł / zalewaniem endpointów
   rejestracji i resetu. Limit liczony per adres IP. */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minut
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Zbyt wiele prób. Spróbuj ponownie za kilka minut.' },
});
const strictAuthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 6, // logowanie i reset — dużo bardziej restrykcyjnie niż reszta
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
}), (req, res) => {
  const { unitName, name, email, password } = req.body;
  const emailLower = email.trim().toLowerCase();
  const existing = db.prepare(`SELECT id FROM users WHERE email = ?`).get(emailLower);
  if (existing) return res.status(409).json({ error: 'Konto z tym adresem e-mail już istnieje.' });

  const unitId = uuid();
  const userId = uuid();
  const passwordHash = bcrypt.hashSync(password, 12);

  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO units (id, name) VALUES (?, ?)`).run(unitId, unitName.trim());
    db.prepare(`INSERT INTO users (id, unit_id, name, email, password_hash, role) VALUES (?,?,?,?,?, 'Zarząd')`)
      .run(userId, unitId, name.trim(), emailLower, passwordHash);
  });
  tx();

  logAudit(unitId, name, 'Zarejestrowano jednostkę', unitName);

  const user = { id: userId, unit_id: unitId, name: name.trim(), email: emailLower, role: 'Zarząd' };
  res.status(201).json({ token: signToken(user), user: { id: userId, name: user.name, email: emailLower, role: 'Zarząd' }, unit: { id: unitId, name: unitName.trim() } });
});

app.post('/api/auth/login', strictAuthLimiter, validateBody({
  email: { required: true, type: 'email' },
  password: { required: true, type: 'string', max: 200 },
}), (req, res) => {
  const { email, password } = req.body;
  const emailLower = email.trim().toLowerCase();
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(emailLower);
  if (!user) return res.status(401).json({ error: 'Nie znaleziono konta z tym adresem e-mail.' });
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Nieprawidłowe hasło.' });
  }
  const unit = db.prepare(`SELECT * FROM units WHERE id = ?`).get(user.unit_id);
  logAudit(user.unit_id, user.name, 'Zalogowano się', user.email);
  res.json({ token: signToken(user), user: { id: user.id, name: user.name, email: user.email, role: user.role }, unit: { id: unit.id, name: unit.name } });
});

/* ---------- RESET HASŁA (prawdziwy, dwuetapowy, z tokenem) ----------
   Krok 1: użytkownik podaje e-mail -> generujemy jednorazowy token (ważny 1h),
   zapisujemy TYLKO jego hash w bazie (jak hasło) i wysyłamy e-mail z linkiem.
   Odpowiedź jest zawsze taka sama niezależnie od tego, czy e-mail istnieje
   w bazie — to celowe, żeby nie dało się w ten sposób sprawdzać, czyje konta
   istnieją w systemie (tzw. ochrona przed user enumeration).
   Krok 2: użytkownik wraca z linku z tokenem i ustawia nowe hasło. */
app.post('/api/auth/forgot-password', strictAuthLimiter, validateBody({
  email: { required: true, type: 'email' },
}), async (req, res) => {
  const emailLower = req.body.email.trim().toLowerCase();
  const genericOk = { ok: true, message: 'Jeśli konto z tym adresem e-mail istnieje, wysłaliśmy na nie instrukcje resetu hasła.' };
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(emailLower);
  if (!user) return res.json(genericOk); // ta sama odpowiedź, żeby nie zdradzać czy konto istnieje

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 godzina

  db.prepare(`INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES (?,?,?,?)`)
    .run(uuid(), user.id, tokenHash, expiresAt);

  const resetUrl = `${process.env.APP_URL || 'https://ezielonka.pl/app/'}?resetToken=${rawToken}&email=${encodeURIComponent(emailLower)}`;
  const emailResult = await sendEmail({
    to: emailLower,
    subject: 'Reset hasła — Firefighter24',
    html: `<p>Otrzymaliśmy prośbę o reset hasła do konta Firefighter24.</p>
           <p><a href="${resetUrl}">Kliknij tutaj, aby ustawić nowe hasło</a> (link ważny 1 godzinę).</p>
           <p>Jeśli to nie Ty prosiłeś o reset, zignoruj tę wiadomość.</p>`,
  });
  logAudit(user.unit_id, user.name, 'Poproszono o reset hasła', emailResult.devMode ? '(tryb dev — brak RESEND_API_KEY)' : '');

  // W trybie deweloperskim (brak skonfigurowanego dostawcy e-mail) zwracamy
  // token wprost w odpowiedzi, inaczej nie dałoby się przetestować resetu
  // bez podłączonej skrzynki. W prawdziwej produkcji (RESEND_API_KEY ustawiony)
  // token NIGDY nie wraca w odpowiedzi API — tylko e-mailem.
  if (emailResult.devMode) {
    return res.json({ ...genericOk, devToken: rawToken, devNote: 'RESEND_API_KEY nie jest ustawiony — token zwrócony tylko do celów testowych.' });
  }
  res.json(genericOk);
});

app.post('/api/auth/reset-password', strictAuthLimiter, validateBody({
  email: { required: true, type: 'email' },
  token: { required: true, type: 'string', max: 128 },
  newPassword: { required: true, type: 'password' },
}), (req, res) => {
  const emailLower = req.body.email.trim().toLowerCase();
  const { token, newPassword } = req.body;
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(emailLower);
  if (!user) return res.status(400).json({ error: 'Link jest nieprawidłowy lub wygasł.' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const record = db.prepare(
    `SELECT * FROM password_resets WHERE user_id = ? AND token_hash = ? AND used = 0 ORDER BY created_at DESC LIMIT 1`
  ).get(user.id, tokenHash);
  if (!record) return res.status(400).json({ error: 'Link jest nieprawidłowy lub został już użyty.' });
  if (new Date(record.expires_at).getTime() < Date.now()) {
    return res.status(400).json({ error: 'Link wygasł. Poproś o nowy reset hasła.' });
  }

  const passwordHash = bcrypt.hashSync(newPassword, 12);
  const tx = db.transaction(() => {
    db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).run(passwordHash, user.id);
    db.prepare(`UPDATE password_resets SET used = 1 WHERE id = ?`).run(record.id);
  });
  tx();
  logAudit(user.unit_id, user.name, 'Zresetowano hasło', '');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare(`SELECT id, name, email, role FROM users WHERE id = ?`).get(req.user.id);
  const unit = db.prepare(`SELECT id, name FROM units WHERE id = ?`).get(req.user.unitId);
  res.json({ user, unit });
});

// ---------- POMOCNICZY GENERATOR TRAS CRUD ----------
// Każdy zasób jednostki (strażacy, sprzęt, pojazdy...) ma ten sam kształt:
// lista/dodaj/edytuj/usuń, zawsze filtrowane po unit_id z tokenu — jednostka
// A nigdy nie zobaczy nawet wiersza danych jednostki B. Walidacja (rules) jest
// teraz obowiązkowa — backend nie ufa ślepo temu, co przyśle klient.
function crudRoutes({ table, fields, writeRoles, auditLabel, rules }) {
  const router = express.Router();
  const validator = rules ? validateBody(rules) : (req, res, next) => next();

  router.get('/', requireAuth, (req, res) => {
    const rows = db.prepare(`SELECT * FROM ${table} WHERE unit_id = ?`).all(req.user.unitId);
    res.json(rows);
  });

  router.post('/', requireAuth, requireRole(...writeRoles), validator, (req, res) => {
    const id = uuid();
    const values = fields.map(f => req.body[f] ?? null);
    const cols = ['id', 'unit_id', ...fields];
    const placeholders = cols.map(() => '?').join(',');
    db.prepare(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${placeholders})`)
      .run(id, req.user.unitId, ...values);
    logAudit(req.user.unitId, req.user.name, `Dodano: ${auditLabel}`, '');
    const row = db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(id);
    res.status(201).json(row);
  });

  router.put('/:id', requireAuth, requireRole(...writeRoles), validator, (req, res) => {
    const existing = db.prepare(`SELECT * FROM ${table} WHERE id = ? AND unit_id = ?`).get(req.params.id, req.user.unitId);
    if (!existing) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });
    const setClause = fields.map(f => `${f} = ?`).join(', ');
    const values = fields.map(f => req.body[f] ?? null);
    db.prepare(`UPDATE ${table} SET ${setClause} WHERE id = ? AND unit_id = ?`).run(...values, req.params.id, req.user.unitId);
    logAudit(req.user.unitId, req.user.name, `Edytowano: ${auditLabel}`, '');
    const row = db.prepare(`SELECT * FROM ${table} WHERE id = ?`).get(req.params.id);
    res.json(row);
  });

  router.delete('/:id', requireAuth, requireRole(...writeRoles), (req, res) => {
    const existing = db.prepare(`SELECT * FROM ${table} WHERE id = ? AND unit_id = ?`).get(req.params.id, req.user.unitId);
    if (!existing) return res.status(404).json({ error: 'Nie znaleziono rekordu.' });
    db.prepare(`DELETE FROM ${table} WHERE id = ? AND unit_id = ?`).run(req.params.id, req.user.unitId);
    logAudit(req.user.unitId, req.user.name, `Usunięto: ${auditLabel}`, '');
    res.status(204).end();
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
  table: 'schedule', fields: ['type', 'date', 'desc'],
  writeRoles: ['Zarząd'], auditLabel: 'wydarzenie w terminarzu',
  rules: {
    date: { required: true, type: 'date' },
    desc: { type: 'string', max: 500 },
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

// Zadania: dostępne (odczyt i zapis) dla wszystkich ról w jednostce —
// to zwykła lista rzeczy do zrobienia, nie wymaga ograniczeń jak dane osobowe czy finanse.
app.use('/api/tasks', crudRoutes({
  table: 'tasks', fields: ['title', 'desc', 'assignee_id', 'assignee_name', 'due', 'priority', 'status'],
  writeRoles: ['Zarząd', 'Skarbnik', 'Strażak'], auditLabel: 'zadanie',
  rules: {
    title: { required: true, type: 'string', max: 200 },
    due: { type: 'date' },
    priority: { type: 'enum', enum: ['Niski', 'Średni', 'Wysoki'] },
    status: { type: 'enum', enum: ['Do zrobienia', 'W trakcie', 'Zrobione'] },
  },
}));

// ---------- KONTA UŻYTKOWNIKÓW (zarządzanie dostępem w jednostce) ----------
app.get('/api/users', requireAuth, requireRole('Zarząd'), (req, res) => {
  const rows = db.prepare(`SELECT id, name, email, role FROM users WHERE unit_id = ?`).all(req.user.unitId);
  res.json(rows);
});

app.post('/api/users', requireAuth, requireRole('Zarząd'), validateBody({
  name: { required: true, type: 'string', max: 200 },
  email: { required: true, type: 'email' },
  password: { required: true, type: 'password' },
  role: { required: true, type: 'enum', enum: ['Zarząd', 'Skarbnik', 'Strażak'] },
}), (req, res) => {
  const { name, email, password, role } = req.body;
  const emailLower = email.trim().toLowerCase();
  if (db.prepare(`SELECT id FROM users WHERE email = ?`).get(emailLower)) {
    return res.status(409).json({ error: 'Konto z tym adresem e-mail już istnieje.' });
  }
  const id = uuid();
  db.prepare(`INSERT INTO users (id, unit_id, name, email, password_hash, role) VALUES (?,?,?,?,?,?)`)
    .run(id, req.user.unitId, name.trim(), emailLower, bcrypt.hashSync(password, 12), role);
  logAudit(req.user.unitId, req.user.name, 'Utworzono konto użytkownika', `${name} (${role})`);
  res.status(201).json({ id, name: name.trim(), email: emailLower, role });
});

app.put('/api/users/:id', requireAuth, requireRole('Zarząd'), validateBody({
  name: { type: 'string', max: 200 },
  email: { type: 'email' },
  password: { type: 'password' },
  role: { type: 'enum', enum: ['Zarząd', 'Skarbnik', 'Strażak'] },
}), (req, res) => {
  const target = db.prepare(`SELECT * FROM users WHERE id = ? AND unit_id = ?`).get(req.params.id, req.user.unitId);
  if (!target) return res.status(404).json({ error: 'Nie znaleziono konta.' });
  const { name, email, password, role } = req.body || {};
  if (email) {
    const emailLower = email.trim().toLowerCase();
    const clash = db.prepare(`SELECT id FROM users WHERE email = ? AND id != ?`).get(emailLower, req.params.id);
    if (clash) return res.status(409).json({ error: 'Ten adres e-mail jest już używany przez inne konto.' });
  }
  const passwordHash = password ? bcrypt.hashSync(password, 12) : target.password_hash;
  const emailLower = (email || target.email).trim().toLowerCase();
  db.prepare(`UPDATE users SET name=?, email=?, password_hash=?, role=? WHERE id=?`)
    .run(name || target.name, emailLower, passwordHash, role || target.role, req.params.id);
  logAudit(req.user.unitId, req.user.name, 'Edytowano konto użytkownika', name || target.name);
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAuth, requireRole('Zarząd'), (req, res) => {
  const target = db.prepare(`SELECT * FROM users WHERE id = ? AND unit_id = ?`).get(req.params.id, req.user.unitId);
  if (!target) return res.status(404).json({ error: 'Nie znaleziono konta.' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'Nie możesz usunąć własnego konta, na którym jesteś zalogowany.' });
  const zarzadCount = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE unit_id = ? AND role = 'Zarząd'`).get(req.user.unitId).n;
  if (target.role === 'Zarząd' && zarzadCount <= 1) return res.status(400).json({ error: 'To jedyne konto z rolą Zarząd — nie można go usunąć.' });
  db.prepare(`DELETE FROM users WHERE id = ?`).run(req.params.id);
  logAudit(req.user.unitId, req.user.name, 'Usunięto konto użytkownika', target.name);
  res.status(204).end();
});

// ---------- HISTORIA DZIAŁAŃ (tylko odczyt) ----------
app.get('/api/audit', requireAuth, requireRole('Zarząd'), (req, res) => {
  const rows = db.prepare(`SELECT * FROM audit_log WHERE unit_id = ? ORDER BY ts DESC LIMIT 300`).all(req.user.unitId);
  res.json(rows);
});

/* ---------- KOPIE ZAPASOWE ----------
   Dwa niezależne mechanizmy:
   1) Pełny eksport JSON danych TEJ jednostki na żądanie (Zarząd) — przenośny,
      działa nawet bez dostępu do systemu plików serwera.
   2) Automatyczna, cykliczna migawka całego pliku bazy SQLite na wolumenie
      (wszystkie jednostki naraz) — awaryjna siatka bezpieczeństwa, gdyby coś
      poszło nie tak z samymi danymi, niezależnie od warstwy aplikacji. */
app.get('/api/backup/full', requireAuth, requireRole('Zarząd'), (req, res) => {
  const unitId = req.user.unitId;
  const tables = {
    firefighters: 'firefighters', vehicles: 'vehicles', fuel: 'fuel_log', gear: 'gear',
    trips: 'trips', schedule: 'schedule', dues: 'dues', mdpMembers: 'mdp_members',
    mdpMeetings: 'mdp_meetings', tasks: 'tasks',
  };
  const data = {};
  for (const [key, table] of Object.entries(tables)) {
    data[key] = db.prepare(`SELECT * FROM ${table} WHERE unit_id = ?`).all(unitId);
  }
  data.users = db.prepare(`SELECT id, name, email, role FROM users WHERE unit_id = ?`).all(unitId);
  data.auditLog = db.prepare(`SELECT * FROM audit_log WHERE unit_id = ? ORDER BY ts DESC LIMIT 300`).all(unitId);
  const unit = db.prepare(`SELECT * FROM units WHERE id = ?`).get(unitId);
  res.json({ app: 'Firefighter24', exportedAt: new Date().toISOString(), unit, data });
});

const BACKUP_DIR = path.join(path.dirname(db.DB_PATH), 'backups');
const BACKUP_RETENTION = 7; // dni

function runDbBackup() {
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const dest = path.join(BACKUP_DIR, `firefighter24-${stamp}.db`);
    db.backup(dest)
      .then(() => {
        console.log('Kopia zapasowa bazy zapisana:', dest);
        const files = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.db')).sort();
        const excess = files.length - BACKUP_RETENTION;
        if (excess > 0) {
          files.slice(0, excess).forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
        }
      })
      .catch(err => console.error('Błąd kopii zapasowej bazy:', err.message));
  } catch (e) {
    console.error('Błąd przygotowania kopii zapasowej:', e.message);
  }
}
// Pierwsza kopia wkrótce po starcie, potem co 24h. Wymaga trwałego wolumenu
// pod BACKUP_DIR (ten sam, na którym leży sama baza) — bez niego kopie i tak
// zginą przy restarcie kontenera, tak jak sama baza.
setTimeout(runDbBackup, 60 * 1000);
setInterval(runDbBackup, 24 * 60 * 60 * 1000);

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'firefighter24-backend', emailConfigured: EMAIL_CONFIGURED }));

app.listen(PORT, () => {
  console.log(`Firefighter24 API działa na porcie ${PORT}`);
  if (!EMAIL_CONFIGURED) console.log('Uwaga: RESEND_API_KEY nie ustawiony — reset hasła działa w trybie deweloperskim (token w odpowiedzi API, e-mail nie jest wysyłany).');
});

