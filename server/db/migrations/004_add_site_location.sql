-- Run once on an existing database: psql "$DATABASE_URL" -f db/migrations/004_add_site_location.sql
ALTER TABLE sites ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION;
