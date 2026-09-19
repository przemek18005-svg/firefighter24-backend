// db.js — połączenie z PostgreSQL i schemat tabel.
// Zmiana względem wcześniejszej wersji (SQLite/better-sqlite3): PostgreSQL
// wymaga prawdziwego serwera bazodanowego (np. darmowej bazy Koyeb/Neon/Supabase)
// zamiast pliku na dysku — ale dzięki temu nie zależymy już od trwałego
// wolumenu pod samym API, co otwiera drzwi do hostingów bez płatnych dysków.
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('BŁĄD: brak zmiennej środowiskowej DATABASE_URL. Ustaw ją na connection string do bazy PostgreSQL.');
  process.exit(1);
}

const pool = new Pool({
  connectionString,
  // Większość darmowych hostingów Postgres (Koyeb, Neon, Supabase) wymaga SSL,
  // ale z certyfikatem, którego Node domyślnie nie zweryfikuje — to standardowe,
  // bezpieczne w tym kontekście ustawienie dla połączeń do zaufanego, znanego hosta.
  ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('Nieoczekiwany błąd puli połączeń PostgreSQL:', err.message);
});

async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS units (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      gmina_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('Zarząd','Skarbnik','Strażak')),
      permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS firefighters (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      first TEXT NOT NULL,
      last TEXT NOT NULL,
      role TEXT,
      join_date TEXT,
      med_date TEXT,
      org_body TEXT CHECK(org_body IS NULL OR org_body IN ('zarzad','komisja')),
      org_role TEXT
    );

    CREATE TABLE IF NOT EXISTS vehicles (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      plate TEXT,
      oc_date TEXT,
      review_date TEXT,
      mileage INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS fuel_log (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      vehicle_id TEXT,
      vehicle_name TEXT,
      date TEXT NOT NULL,
      liters REAL NOT NULL,
      cost REAL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS gear (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      category TEXT,
      review_date TEXT
    );

    CREATE TABLE IF NOT EXISTS trips (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      date TEXT NOT NULL,
      type TEXT,
      place TEXT,
      crew TEXT,
      lat REAL,
      lng REAL
    );

    CREATE TABLE IF NOT EXISTS schedule (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      type TEXT,
      date TEXT NOT NULL,
      description TEXT
    );

    CREATE TABLE IF NOT EXISTS dues (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      firefighter_id TEXT,
      firefighter_name TEXT,
      month TEXT NOT NULL,
      amount REAL NOT NULL,
      status TEXT CHECK(status IN ('ok','warn'))
    );

    CREATE TABLE IF NOT EXISTS mdp_members (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      first TEXT NOT NULL,
      last TEXT NOT NULL,
      dob TEXT
    );

    CREATE TABLE IF NOT EXISTS mdp_meetings (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      date TEXT NOT NULL,
      topic TEXT,
      present INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT,
      assignee_id TEXT,
      assignee_name TEXT,
      due TEXT,
      priority TEXT,
      status TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      user_name TEXT,
      action TEXT NOT NULL,
      details TEXT,
      ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS announcements (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      body TEXT,
      author_name TEXT,
      pinned INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sections (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS section_members (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      section_id TEXT NOT NULL REFERENCES sections(id) ON DELETE CASCADE,
      firefighter_id TEXT NOT NULL REFERENCES firefighters(id) ON DELETE CASCADE,
      commander INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS exercises (
      id TEXT PRIMARY KEY,
      unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      date TEXT NOT NULL,
      topic TEXT,
      type TEXT,
      duration_hours REAL,
      participants INTEGER,
      notes TEXT
    );

    CREATE TABLE IF NOT EXISTS gmina_accounts (
      id TEXT PRIMARY KEY,
      gmina_code TEXT NOT NULL,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_firefighters_unit ON firefighters(unit_id);
    CREATE INDEX IF NOT EXISTS idx_vehicles_unit ON vehicles(unit_id);
    CREATE INDEX IF NOT EXISTS idx_gear_unit ON gear(unit_id);
    CREATE INDEX IF NOT EXISTS idx_trips_unit ON trips(unit_id);
    CREATE INDEX IF NOT EXISTS idx_schedule_unit ON schedule(unit_id);
    CREATE INDEX IF NOT EXISTS idx_dues_unit ON dues(unit_id);
    CREATE INDEX IF NOT EXISTS idx_mdp_members_unit ON mdp_members(unit_id);
    CREATE INDEX IF NOT EXISTS idx_mdp_meetings_unit ON mdp_meetings(unit_id);
    CREATE INDEX IF NOT EXISTS idx_tasks_unit ON tasks(unit_id);
    CREATE INDEX IF NOT EXISTS idx_audit_unit ON audit_log(unit_id);
    CREATE INDEX IF NOT EXISTS idx_users_unit ON users(unit_id);
    CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id);
    CREATE INDEX IF NOT EXISTS idx_announcements_unit ON announcements(unit_id);
    CREATE INDEX IF NOT EXISTS idx_sections_unit ON sections(unit_id);
    CREATE INDEX IF NOT EXISTS idx_section_members_unit ON section_members(unit_id);
    CREATE INDEX IF NOT EXISTS idx_section_members_section ON section_members(section_id);
    CREATE INDEX IF NOT EXISTS idx_section_members_firefighter ON section_members(firefighter_id);
    CREATE INDEX IF NOT EXISTS idx_exercises_unit ON exercises(unit_id);
    CREATE INDEX IF NOT EXISTS idx_gmina_accounts_code ON gmina_accounts(gmina_code);
  `);

  /* ---------- MIGRACJE: dopisywanie kolumn do tabel, które już istniały ----------
     "CREATE TABLE IF NOT EXISTS" nic nie robi, jeśli tabela już jest w bazie —
     więc nowe kolumny dodawane do istniejących tabel (np. trips.lat/lng przy
     module Mapa) muszą przejść osobno przez ALTER TABLE, inaczej cicho by nie
     trafiły do już działającej bazy na Neon. To jest bezpieczne uruchamiać przy
     każdym starcie serwera — IF NOT EXISTS sprawia, że nic się nie dzieje,
     jeśli kolumna już tam jest. */
  await pool.query(`
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS lat REAL;
    ALTER TABLE trips ADD COLUMN IF NOT EXISTS lng REAL;
    ALTER TABLE firefighters ADD COLUMN IF NOT EXISTS org_body TEXT;
    ALTER TABLE firefighters ADD COLUMN IF NOT EXISTS org_role TEXT;
    ALTER TABLE units ADD COLUMN IF NOT EXISTS gmina_code TEXT;
    CREATE INDEX IF NOT EXISTS idx_units_gmina_code ON units(gmina_code);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '{}'::jsonb;
  `);
}

module.exports = { pool, initSchema };
