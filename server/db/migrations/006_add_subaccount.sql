-- Run once on an existing database: psql "$DATABASE_URL" -f db/migrations/006_add_subaccount.sql
ALTER TABLE clients ADD COLUMN IF NOT EXISTS paystack_subaccount_code TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS payout_percentage NUMERIC;
