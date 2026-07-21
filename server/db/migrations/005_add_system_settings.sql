-- Run once on an existing database: psql "$DATABASE_URL" -f db/migrations/005_add_system_settings.sql
CREATE TABLE IF NOT EXISTS system_settings (
  id INTEGER PRIMARY KEY DEFAULT 1,
  installer_pin TEXT NOT NULL,
  CONSTRAINT single_row CHECK (id = 1)
);

-- Seed a default row so /device-setup never crashes on a missing row.
-- Change this immediately from the admin dashboard after migrating —
-- this default is not secret.
INSERT INTO system_settings (id, installer_pin)
VALUES (1, 'CHANGE-ME-0000')
ON CONFLICT (id) DO NOTHING;
