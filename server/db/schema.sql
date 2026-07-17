-- Public Toilet Payment System — Multi-Tenant Schema
-- Run with: psql "$DATABASE_URL" -f db/schema.sql

CREATE TABLE IF NOT EXISTS clients (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'client_admin' CHECK (role IN ('super_admin', 'client_admin')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A site = one physical toilet location (e.g. "Building B — CBD", "Ngong").
-- site_key authenticates the reception app + ESP32 door units for that location —
-- devices never see a client's login credentials, only their own site's key.
CREATE TABLE IF NOT EXISTS sites (
  id SERIAL PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  site_key TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS doors (
  id SERIAL PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  door_key TEXT NOT NULL, -- 'male', 'female', 'disabled_m', 'disabled_f', 'shower_m', 'shower_f'
  price_kes INTEGER NOT NULL,
  UNIQUE (site_id, door_key)
);

CREATE TABLE IF NOT EXISTS transactions (
  id SERIAL PRIMARY KEY,
  reference TEXT UNIQUE NOT NULL,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  door_id INTEGER NOT NULL REFERENCES doors(id) ON DELETE CASCADE,
  phone TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', -- pending -> paid
  otp TEXT,
  otp_expires_at TIMESTAMPTZ,
  used BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NFC tags belong to a client (issued to their cleaning staff) and are scoped to
-- specific sites within that client via the junction table below.
CREATE TABLE IF NOT EXISTS nfc_tags (
  id SERIAL PRIMARY KEY,
  client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  uid TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nfc_tag_sites (
  tag_id INTEGER NOT NULL REFERENCES nfc_tags(id) ON DELETE CASCADE,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  PRIMARY KEY (tag_id, site_id)
);

CREATE INDEX IF NOT EXISTS idx_transactions_reference ON transactions(reference);
CREATE INDEX IF NOT EXISTS idx_transactions_site_door_otp ON transactions(site_id, door_id, otp);
CREATE INDEX IF NOT EXISTS idx_sites_client ON sites(client_id);
CREATE INDEX IF NOT EXISTS idx_nfc_tags_client ON nfc_tags(client_id);
