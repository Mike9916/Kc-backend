-- Create schemas
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS app;

-- RAW mirror
CREATE TABLE IF NOT EXISTS raw.files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  filename     TEXT NOT NULL,
  record_index INTEGER,
  data         JSONB NOT NULL,
  imported_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_files_filename ON raw.files(filename);
CREATE INDEX IF NOT EXISTS idx_files_gin ON raw.files USING GIN (data);

-- APP normalized (summarized for brevity)
CREATE TABLE IF NOT EXISTS app.accounts (
  account_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  phone TEXT,
  password_hash TEXT,
  status TEXT DEFAULT 'active',
  payload JSONB,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_accounts_username ON app.accounts(username);

CREATE TABLE IF NOT EXISTS app.members (
  member_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  scj_id TEXT,
  name TEXT NOT NULL,
  gender TEXT,
  phone TEXT,
  email TEXT,
  tribe TEXT,
  center TEXT,
  jyk TEXT,
  cell TEXT,
  status TEXT,
  payload JSONB,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_members_scj ON app.members(scj_id);
CREATE INDEX IF NOT EXISTS idx_members_jyk ON app.members(jyk, cell);

CREATE TABLE IF NOT EXISTS app.roles (
  role_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  role_key TEXT UNIQUE NOT NULL,
  description TEXT,
  payload JSONB
);

CREATE TABLE IF NOT EXISTS app.whitelist (
  whitelist_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  account_id UUID REFERENCES app.accounts(account_id),
  member_id  UUID REFERENCES app.members(member_id),
  role_id    UUID REFERENCES app.roles(role_id),
  tribe TEXT, center TEXT, jyk TEXT, cell TEXT,
  notes TEXT, payload JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_whitelist_scope ON app.whitelist(tribe, center, jyk, cell);

DO $$ BEGIN
  CREATE TYPE report_type AS ENUM ('service', 'education', 'evangelism', 'offering', 'generic');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS app.reports (
  report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  type report_type NOT NULL,
  leader_id UUID,
  scope_tribe  TEXT,
  scope_center TEXT,
  scope_jyk    TEXT,
  scope_cell   TEXT,
  period_start DATE,
  period_end   DATE,
  total INT,
  attended_physical INT,
  attended_online   INT,
  attended_other    INT,
  not_attended      INT,
  metrics JSONB,
  payload JSONB,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reports_type_period ON app.reports(type, period_start, period_end);
CREATE INDEX IF NOT EXISTS idx_reports_scope ON app.reports(scope_tribe, scope_center, scope_jyk, scope_cell);
CREATE INDEX IF NOT EXISTS idx_reports_metrics_gin ON app.reports USING GIN (metrics);

CREATE TABLE IF NOT EXISTS app.audit (
  audit_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  actor TEXT, action TEXT, target TEXT,
  meta JSONB, created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.announcements (
  announcement_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title TEXT, body TEXT, author TEXT, channel TEXT,
  starts_at TIMESTAMPTZ, ends_at TIMESTAMPTZ,
  payload JSONB, created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.issues (
  issue_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  created_by TEXT, category TEXT, content TEXT,
  status TEXT DEFAULT 'open', payload JSONB,
  created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.support_inbox (
  ticket_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  from_user TEXT, subject TEXT, body TEXT,
  status TEXT DEFAULT 'open', payload JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.media (
  media_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title TEXT, url TEXT, kind TEXT,
  payload JSONB, created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.flags (
  key TEXT PRIMARY KEY,
  value JSONB,
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.settings (
  key TEXT PRIMARY KEY,
  value JSONB,
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app.special_dates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  label TEXT, date DATE, payload JSONB
);

CREATE TABLE IF NOT EXISTS app.core_channel (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  channel_key TEXT UNIQUE,
  description TEXT,
  payload JSONB
);

CREATE TABLE IF NOT EXISTS app.forwards (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  from_role TEXT, to_role TEXT, rules JSONB, payload JSONB
);

CREATE TABLE IF NOT EXISTS app.leader_forwards (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  leader TEXT, to_leader TEXT, rules JSONB, payload JSONB
);

CREATE TABLE IF NOT EXISTS app.leader_workflow (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  step_key TEXT, config JSONB, payload JSONB
);