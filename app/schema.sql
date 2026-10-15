CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('Admin', 'Investigator')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
  case_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open', 'Analyzed', 'Closed')),
  created_by INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_assignments (
  case_id INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  assigned_at TEXT NOT NULL,
  PRIMARY KEY (case_id, user_id)
);

CREATE TABLE IF NOT EXISTS evidence_files (
  file_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  uploaded_by INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
  uploader_name TEXT NOT NULL,
  file_name TEXT NOT NULL,
  stored_name TEXT NOT NULL UNIQUE,
  source_type TEXT NOT NULL CHECK (source_type IN ('Log', 'Browser History', 'Login Events', 'File Events')),
  file_size INTEGER NOT NULL,
  file_hash TEXT NOT NULL,
  event_count INTEGER NOT NULL DEFAULT 0,
  skipped_count INTEGER NOT NULL DEFAULT 0,
  upload_date TEXT NOT NULL,
  UNIQUE (case_id, file_hash)
);

CREATE TABLE IF NOT EXISTS correlation_groups (
  group_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  group_label TEXT NOT NULL,
  risk_score REAL NOT NULL,
  risk_level TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  event_count INTEGER NOT NULL,
  key_event_count INTEGER NOT NULL,
  main_user TEXT,
  main_ip TEXT,
  main_device TEXT,
  stages TEXT
);

CREATE TABLE IF NOT EXISTS events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  file_id INTEGER NOT NULL REFERENCES evidence_files(file_id) ON DELETE CASCADE,
  group_id INTEGER REFERENCES correlation_groups(group_id) ON DELETE SET NULL,
  event_time TEXT NOT NULL,
  event_ts INTEGER NOT NULL,
  source_type TEXT NOT NULL,
  event_type TEXT NOT NULL,
  action TEXT,
  result TEXT,
  username TEXT,
  ip_address TEXT,
  dest_ip TEXT,
  device TEXT,
  file_path TEXT,
  url TEXT,
  details TEXT,
  raw_data TEXT,
  importance_score REAL,
  importance_level TEXT,
  anomaly_score REAL,
  stage TEXT,
  is_noise INTEGER NOT NULL DEFAULT 0,
  repeat_count INTEGER NOT NULL DEFAULT 1,
  reasons TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_case_ts ON events (case_id, event_ts);
CREATE INDEX IF NOT EXISTS idx_events_case_level ON events (case_id, importance_level);
CREATE INDEX IF NOT EXISTS idx_events_case_noise ON events (case_id, is_noise);
CREATE INDEX IF NOT EXISTS idx_events_group ON events (group_id);

CREATE TABLE IF NOT EXISTS analysis_results (
  result_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  summary_text TEXT NOT NULL,
  total_events INTEGER NOT NULL,
  key_events INTEGER NOT NULL,
  removed_events INTEGER NOT NULL,
  group_count INTEGER NOT NULL,
  critical_count INTEGER NOT NULL,
  generated_by INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
  generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  session_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_activity TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
  attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
  identifier TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  success INTEGER NOT NULL,
  attempted_at TEXT NOT NULL
);

