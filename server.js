// server.js — REST API dla Firefighter24.
// Zastępuje warstwę localStorage z prototypu frontendowego prawdziwym serwerem:
// hasła haszowane bcryptem (nie SHA-256 bez soli), role egzekwowane po stronie
// serwera (nie da się ich obejść konsolą przeglądarki), dane współdzielone
// między urządzeniami zamiast zamknięte w jednej przeglądarce.
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { v4: uuid } = require('uuid');
const db = require('./db');
const { signToken, requireAuth, requireRole } = require('./auth');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;

function logAudit(unitId, userName, action, details) {
  db.prepare(`INSERT INTO audit_log (id, unit_id, user_name, action, details) VALUES (?,?,?,?,?)`)
    .run(uuid(), unitId, userName, action, details || '');
}

// ---------- AUTORYZACJA ----------

app.post('/api/auth/register', (req, res) => {
  const { unitName, name, email, password } = req.body || {};
  if (!unitName || !name || !email || !password) {
    return res.status(400).json({ error: 'Uzupełnij nazwę jednostki, imię i nazwisko, e-mail oraz hasło.' });
  }
  if (password.length < 6) return res.status(400).json({ error: 'Hasło musi mieć co najmniej 6 znaków.' });

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

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Podaj e-mail i hasło.' });
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

// Reset hasła: w tej wersji od razu ustawia nowe hasło po podaniu e-maila.
// TODO produkcyjne: wysyłka jednorazowego, wygasającego tokenu na e-mail
// (np. Resend/SendGrid) zamiast pozwalać na reset samym adresem e-mail.
app.post('/api/auth/reset-password', (req, res) => {
  const { email, newPassword } = req.body || {};
  if (!email || !newPassword) return res.status(400).json({ error: 'Podaj e-mail i nowe hasło.' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Hasło musi mieć co najmniej 6 znaków.' });
  const emailLower = email.trim().toLowerCase();
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(emailLower);
  if (!user) return res.status(404).json({ error: 'Nie znaleziono konta z tym adresem e-mail.' });
  const passwordHash = bcrypt.hashSync(newPassword, 12);
  db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).run(passwordHash, user.id);
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
// A nigdy nie zobaczy nawet wiersza danych jednostki B.
function crudRoutes({ path, table, fields, writeRoles, auditLabel }) {
  const router = express.Router();

  router.get('/', requireAuth, (req, res) => {
    const rows = db.prepare(`SELECT * FROM ${table} WHERE unit_id = ?`).all(req.user.unitId);
    res.json(rows);
  });

  router.post('/', requireAuth, requireRole(...writeRoles), (req, res) => {
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

  router.put('/:id', requireAuth, requireRole(...writeRoles), (req, res) => {
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

// Strażacy: odczyt dla każdego zalogowanego w jednostce, zapis tylko Zarząd
// — to dokładnie egzekwuje po stronie serwera to, co w prototypie
// front-endowym było tylko chowaniem przycisków.
app.use('/api/firefighters', crudRoutes({
  table: 'firefighters', fields: ['first', 'last', 'role', 'join_date', 'med_date'],
  writeRoles: ['Zarząd'], auditLabel: 'strażak',
}));

app.use('/api/vehicles', crudRoutes({
  table: 'vehicles', fields: ['name', 'plate', 'oc_date', 'review_date', 'mileage'],
  writeRoles: ['Zarząd'], auditLabel: 'pojazd',
}));

app.use('/api/fuel', crudRoutes({
  table: 'fuel_log', fields: ['vehicle_id', 'vehicle_name', 'date', 'liters', 'cost'],
  writeRoles: ['Zarząd'], auditLabel: 'tankowanie',
}));

app.use('/api/gear', crudRoutes({
  table: 'gear', fields: ['name', 'category', 'review_date'],
  writeRoles: ['Zarząd'], auditLabel: 'sprzęt',
}));

app.use('/api/trips', crudRoutes({
  table: 'trips', fields: ['date', 'type', 'place', 'crew'],
  writeRoles: ['Zarząd'], auditLabel: 'wyjazd',
}));

app.use('/api/schedule', crudRoutes({
  table: 'schedule', fields: ['type', 'date', 'desc'],
  writeRoles: ['Zarząd'], auditLabel: 'wydarzenie w terminarzu',
}));

app.use('/api/dues', crudRoutes({
  table: 'dues', fields: ['firefighter_id', 'firefighter_name', 'month', 'amount', 'status'],
  writeRoles: ['Zarząd', 'Skarbnik'], auditLabel: 'wpłata składki',
}));

app.use('/api/mdp-members', crudRoutes({
  table: 'mdp_members', fields: ['first', 'last', 'dob'],
  writeRoles: ['Zarząd'], auditLabel: 'członek MDP',
}));

app.use('/api/mdp-meetings', crudRoutes({
  table: 'mdp_meetings', fields: ['date', 'topic', 'present'],
  writeRoles: ['Zarząd'], auditLabel: 'zebranie MDP',
}));

// Zadania: dostępne (odczyt i zapis) dla wszystkich ról w jednostce —
// to zwykła lista rzeczy do zrobienia, nie wymaga ograniczeń jak dane osobowe czy finanse.
app.use('/api/tasks', crudRoutes({
  table: 'tasks', fields: ['title', 'desc', 'assignee_id', 'assignee_name', 'due', 'priority', 'status'],
  writeRoles: ['Zarząd', 'Skarbnik', 'Strażak'], auditLabel: 'zadanie',
}));

// ---------- KONTA UŻYTKOWNIKÓW (zarządzanie dostępem w jednostce) ----------
app.get('/api/users', requireAuth, requireRole('Zarząd'), (req, res) => {
  const rows = db.prepare(`SELECT id, name, email, role FROM users WHERE unit_id = ?`).all(req.user.unitId);
  res.json(rows);
});

app.post('/api/users', requireAuth, requireRole('Zarząd'), (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (!name || !email || !password || !role) return res.status(400).json({ error: 'Uzupełnij wszystkie pola.' });
  if (password.length < 6) return res.status(400).json({ error: 'Hasło musi mieć co najmniej 6 znaków.' });
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

app.put('/api/users/:id', requireAuth, requireRole('Zarząd'), (req, res) => {
  const target = db.prepare(`SELECT * FROM users WHERE id = ? AND unit_id = ?`).get(req.params.id, req.user.unitId);
  if (!target) return res.status(404).json({ error: 'Nie znaleziono konta.' });
  const { name, email, password, role } = req.body || {};
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

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'firefighter24-backend' }));

app.listen(PORT, () => {
  console.log(`Firefighter24 API działa na porcie ${PORT}`);
});
