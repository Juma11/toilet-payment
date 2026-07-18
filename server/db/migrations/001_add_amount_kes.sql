-- Run once on an existing database: psql "$DATABASE_URL" -f db/migrations/001_add_amount_kes.sql
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS amount_kes INTEGER NOT NULL DEFAULT 0;
