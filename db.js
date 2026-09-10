// db.js — inicjalizacja bazy SQLite i schemat tabel.
// SQLite wybrany celowo dla tej fazy: zero zewnętrznej usługi bazodanowej,
// jeden plik na dysku, łatwe do przeniesienia na Postgres później (patrz README).
const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'firefighter24.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS units (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Zarząd','Skarbnik','Strażak')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS firefighters (
  id TEXT PRIMARY KEY,
  unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
  first TEXT NOT NULL,
  last TEXT NOT NULL,
  role TEXT,
  join_date TEXT,
  med_date TEXT
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
  crew TEXT
);

CREATE TABLE IF NOT EXISTS schedule (
  id TEXT PRIMARY KEY,
  unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
  type TEXT,
  date TEXT NOT NULL,
  desc TEXT
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

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
  user_name TEXT,
  action TEXT NOT NULL,
  details TEXT,
  ts TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  unit_id TEXT NOT NULL REFERENCES units(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  desc TEXT,
  assignee_id TEXT,
  assignee_name TEXT,
  due TEXT,
  priority TEXT,
  status TEXT
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
`);

module.exports = db;
