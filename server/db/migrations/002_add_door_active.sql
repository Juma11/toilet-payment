-- Run once on an existing database: psql "$DATABASE_URL" -f db/migrations/002_add_door_active.sql
ALTER TABLE doors ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;
