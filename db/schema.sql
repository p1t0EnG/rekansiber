-- Tabel akun tim SOC (bukan untuk pengguna publik -- publik pakai IOC checker tanpa login)
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  full_name     TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'member', -- 'admin' | 'member'
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Sesi login aktif (dipakai untuk auth berbasis cookie/token sederhana)
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,           -- token acak (bukan angka urut)
  user_id    INTEGER NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Log tiap pengecekan IOC -- ini yang jadi basis dashboard usage & report bulanan
CREATE TABLE IF NOT EXISTS ioc_checks (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER REFERENCES users(id),  -- NULL kalau dicek dari halaman publik
  ioc_value      TEXT NOT NULL,
  ioc_type       TEXT NOT NULL,                 -- 'ip' | 'domain' | 'hash' | 'url'
  source         TEXT NOT NULL,                 -- 'public' | 'soc'
  verdict        TEXT,                          -- 'clean' | 'suspicious' | 'malicious' (ringkasan)
  result_summary TEXT,                          -- JSON ringkas hasil VT/AbuseIPDB/OTX
  checked_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Template report phishing (untuk dikirim ke hosting provider)
CREATE TABLE IF NOT EXISTS phishing_reports (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL REFERENCES users(id),
  target_domain TEXT NOT NULL,
  hosting_email TEXT,
  status        TEXT NOT NULL DEFAULT 'draft', -- 'draft' | 'sent' | 'resolved'
  notes         TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ioc_checks_user ON ioc_checks(user_id);
CREATE INDEX IF NOT EXISTS idx_ioc_checks_date ON ioc_checks(checked_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
