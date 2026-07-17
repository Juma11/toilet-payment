/**
 * Run once to create the first super_admin account:
 *   node seed.js "Vincent Juma" your@email.com yourStrongPassword
 */
require("dotenv").config();
const pool = require("./db");
const { hashPassword } = require("./auth");

async function main() {
  const [name, email, password] = process.argv.slice(2);
  if (!name || !email || !password) {
    console.error("Usage: node seed.js <name> <email> <password>");
    process.exit(1);
  }

  const passwordHash = await hashPassword(password);
  const result = await pool.query(
    `INSERT INTO clients (name, email, password_hash, role) VALUES ($1, $2, $3, 'super_admin')
     ON CONFLICT (email) DO UPDATE SET password_hash = $3, role = 'super_admin'
     RETURNING id, name, email, role`,
    [name, email, passwordHash]
  );

  console.log("Super admin ready:", result.rows[0]);
  await pool.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
