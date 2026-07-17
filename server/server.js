/**
 * Public Toilet Payment System — Multi-Tenant Backend
 *
 * Roles:
 *  - super_admin: Vincent. Creates client accounts. Can view/act on any client via ?clientId=.
 *  - client_admin: a toilet-business owner. Manages their own sites, doors, NFC tags.
 *  - devices (reception app + ESP32 doors): authenticate via a per-site "site_key",
 *    never see a client login. This keeps a leaked device key scoped to one site only.
 *
 * Endpoints:
 *  Auth:
 *    POST   /auth/login                     -> { email, password } -> { token }
 *
 *  Super-admin only:
 *    POST   /admin/clients                  -> create a new client account
 *    GET    /admin/clients                  -> list all clients
 *
 *  Client-scoped (client_admin uses own token; super_admin passes ?clientId=):
 *    POST   /sites                          -> create a site + its doors, returns site_key
 *    GET    /sites                          -> list this client's sites
 *    POST   /nfc-tags                       -> issue/update a staff NFC tag, scoped to siteIds
 *    GET    /nfc-tags                       -> list this client's tags
 *    DELETE /nfc-tags/:uid                  -> deactivate a tag
 *
 *  Device-facing (x-site-key header, no login):
 *    POST   /charge                         -> { doorKey, phone } -> triggers Paystack STK push
 *    POST   /validate                       -> { doorKey, otp } -> unlock check
 *    POST   /nfc/validate                   -> { uid } -> staff tag unlock check
 *
 *  Public:
 *    POST   /paystack/webhook               -> Paystack calls this on payment events
 *    GET    /health
 */

require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

const pool = require("./db");
const {
  hashPassword,
  comparePassword,
  signToken,
  requireAuth,
  requireSuperAdmin,
  resolveClientId,
  requireSiteKey,
} = require("./auth");

const app = express();
app.use(express.json());

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const OTP_EXPIRY_MS = 10 * 60 * 1000;
const OTP_LENGTH = 6;

// ---- Helpers ----
function generateOtp(length = OTP_LENGTH) {
  const digits = "0123456789";
  let otp = "";
  for (let i = 0; i < length; i++) otp += digits[crypto.randomInt(0, digits.length)];
  return otp;
}

function generateReference() {
  return "toilet_" + crypto.randomBytes(8).toString("hex");
}

function generateSiteKey() {
  return "site_" + crypto.randomBytes(16).toString("hex");
}

function normalizeKenyanPhone(raw) {
  const digits = String(raw).replace(/[^\d]/g, "");
  if (digits.length === 12 && digits.startsWith("254")) return "+" + digits;
  if (digits.length === 10 && digits.startsWith("0")) return "+254" + digits.slice(1);
  if (digits.length === 9) return "+254" + digits;
  return null;
}

// Stub — replace with Africa's Talking / Twilio
async function sendSms(phone, message) {
  console.log(`[SMS -> ${phone}]: ${message}`);
}

// =====================================================================
// AUTH
// =====================================================================

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  try {
    const result = await pool.query("SELECT * FROM clients WHERE email = $1", [email]);
    const client = result.rows[0];

    if (!client || !(await comparePassword(password, client.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = signToken({
      id: client.id,
      role: client.role,
      clientId: client.role === "super_admin" ? null : client.id,
      name: client.name,
    });

    res.json({ token, role: client.role, name: client.name });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// =====================================================================
// SUPER ADMIN: manage clients
// =====================================================================

app.post("/admin/clients", requireAuth, requireSuperAdmin, async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "name, email and password are required" });
  }

  try {
    const passwordHash = await hashPassword(password);
    const result = await pool.query(
      "INSERT INTO clients (name, email, password_hash, role) VALUES ($1, $2, $3, 'client_admin') RETURNING id, name, email, role, created_at",
      [name, email, passwordHash]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Email already in use" });
    console.error("Create client error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.get("/admin/clients", requireAuth, requireSuperAdmin, async (req, res) => {
  const result = await pool.query(
    `SELECT c.id, c.name, c.email, c.role, c.created_at, COUNT(s.id) AS site_count
     FROM clients c LEFT JOIN sites s ON s.client_id = c.id
     WHERE c.role = 'client_admin'
     GROUP BY c.id ORDER BY c.created_at DESC`
  );
  res.json(result.rows);
});

// =====================================================================
// CLIENT-SCOPED: sites
// =====================================================================

app.post("/sites", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  if (!clientId) return res.status(400).json({ error: "clientId is required (super admin: pass ?clientId=)" });

  const { name, doors } = req.body;
  if (!name || !doors || typeof doors !== "object" || Object.keys(doors).length === 0) {
    return res.status(400).json({ error: "name and a non-empty doors object (doorKey -> price) are required" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const siteKey = generateSiteKey();
    const siteResult = await client.query(
      "INSERT INTO sites (client_id, name, site_key) VALUES ($1, $2, $3) RETURNING *",
      [clientId, name, siteKey]
    );
    const site = siteResult.rows[0];

    for (const [doorKey, price] of Object.entries(doors)) {
      await client.query(
        "INSERT INTO doors (site_id, door_key, price_kes) VALUES ($1, $2, $3)",
        [site.id, doorKey, price]
      );
    }

    await client.query("COMMIT");
    res.json({ ...site, doors });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Create site error:", err);
    res.status(500).json({ error: "Internal error" });
  } finally {
    client.release();
  }
});

app.get("/sites", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);

  try {
    const sitesResult = clientId
      ? await pool.query("SELECT * FROM sites WHERE client_id = $1 ORDER BY created_at DESC", [clientId])
      : await pool.query("SELECT * FROM sites ORDER BY created_at DESC"); // super admin, no filter

    const sites = sitesResult.rows;
    for (const site of sites) {
      const doorsResult = await pool.query("SELECT door_key, price_kes FROM doors WHERE site_id = $1", [site.id]);
      site.doors = doorsResult.rows.reduce((acc, d) => ({ ...acc, [d.door_key]: d.price_kes }), {});
    }
    res.json(sites);
  } catch (err) {
    console.error("List sites error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// =====================================================================
// CLIENT-SCOPED: NFC tags
// =====================================================================

app.post("/nfc-tags", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  if (!clientId) return res.status(400).json({ error: "clientId is required (super admin: pass ?clientId=)" });

  const { uid, name, siteIds } = req.body;
  if (!uid || !name || !Array.isArray(siteIds) || siteIds.length === 0) {
    return res.status(400).json({ error: "uid, name, and a non-empty siteIds array are required" });
  }

  const client = await pool.connect();
  try {
    // Confirm every siteId actually belongs to this client — prevents scoping a tag to someone else's site
    const ownedSites = await client.query(
      "SELECT id FROM sites WHERE client_id = $1 AND id = ANY($2::int[])",
      [clientId, siteIds]
    );
    if (ownedSites.rows.length !== siteIds.length) {
      return res.status(400).json({ error: "One or more siteIds do not belong to this client" });
    }

    await client.query("BEGIN");
    const tagResult = await client.query(
      `INSERT INTO nfc_tags (client_id, uid, name, active) VALUES ($1, $2, $3, true)
       ON CONFLICT (uid) DO UPDATE SET name = $3, active = true
       RETURNING id`,
      [clientId, uid, name]
    );
    const tagId = tagResult.rows[0].id;

    await client.query("DELETE FROM nfc_tag_sites WHERE tag_id = $1", [tagId]);
    for (const siteId of siteIds) {
      await client.query("INSERT INTO nfc_tag_sites (tag_id, site_id) VALUES ($1, $2)", [tagId, siteId]);
    }

    await client.query("COMMIT");
    res.json({ uid, name, siteIds });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Create/update tag error:", err);
    res.status(500).json({ error: "Internal error" });
  } finally {
    client.release();
  }
});

app.get("/nfc-tags", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);

  try {
    const tagsResult = clientId
      ? await pool.query("SELECT * FROM nfc_tags WHERE client_id = $1 ORDER BY created_at DESC", [clientId])
      : await pool.query("SELECT * FROM nfc_tags ORDER BY created_at DESC");

    const tags = tagsResult.rows;
    for (const tag of tags) {
      const sitesResult = await pool.query(
        "SELECT s.id, s.name FROM nfc_tag_sites nts JOIN sites s ON s.id = nts.site_id WHERE nts.tag_id = $1",
        [tag.id]
      );
      tag.sites = sitesResult.rows;
    }
    res.json(tags);
  } catch (err) {
    console.error("List tags error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.delete("/nfc-tags/:uid", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  try {
    const result = await pool.query(
      "UPDATE nfc_tags SET active = false WHERE uid = $1 AND ($2::int IS NULL OR client_id = $2) RETURNING uid",
      [req.params.uid, clientId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Tag not found" });
    res.json({ message: "Tag deactivated", uid: req.params.uid });
  } catch (err) {
    console.error("Deactivate tag error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// =====================================================================
// DEVICE-FACING: reception app + ESP32 doors (authenticated via x-site-key)
// =====================================================================

app.post("/charge", requireSiteKey(pool), async (req, res) => {
  const { doorKey, phone, email } = req.body;
  const site = req.site;

  if (!doorKey || !phone) {
    return res.status(400).json({ error: "doorKey and phone are required" });
  }

  const normalizedPhone = normalizeKenyanPhone(phone);
  if (!normalizedPhone) {
    return res.status(400).json({ error: "Could not parse phone number" });
  }

  try {
    const doorResult = await pool.query("SELECT * FROM doors WHERE site_id = $1 AND door_key = $2", [site.id, doorKey]);
    const door = doorResult.rows[0];
    if (!door) return res.status(400).json({ error: `Unknown doorKey '${doorKey}' for this site` });

    const reference = generateReference();

    const paystackRes = await fetch("https://api.paystack.co/charge", {
      method: "POST",
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        email: email || "info@vintechafrica.com",
        amount: door.price_kes * 100,
        currency: "KES",
        reference,
        mobile_money: { phone: normalizedPhone, provider: "mpesa" },
      }),
    });
    const data = await paystackRes.json();

    if (!data.status) {
      return res.status(400).json({ error: data.message || "Charge initiation failed" });
    }

    await pool.query(
      "INSERT INTO transactions (reference, site_id, door_id, phone, status) VALUES ($1, $2, $3, $4, 'pending')",
      [reference, site.id, door.id, normalizedPhone]
    );

    res.json({ message: "STK push sent", reference, paystackStatus: data.data.status });
  } catch (err) {
    console.error("Charge error:", err);
    res.status(500).json({ error: "Failed to initiate charge" });
  }
});

app.post("/paystack/webhook", express.json(), async (req, res) => {
  // TODO before going live: verify x-paystack-signature against PAYSTACK_SECRET_KEY (see docs).
  const event = req.body;

  if (event.event === "charge.success") {
    const reference = event.data.reference;
    try {
      const txResult = await pool.query("SELECT * FROM transactions WHERE reference = $1", [reference]);
      const tx = txResult.rows[0];
      if (!tx) {
        console.warn(`Webhook for unknown reference: ${reference}`);
        return res.sendStatus(200);
      }

      const otp = generateOtp();
      const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);

      await pool.query(
        "UPDATE transactions SET status = 'paid', otp = $1, otp_expires_at = $2 WHERE reference = $3",
        [otp, expiresAt, reference]
      );

      await sendSms(tx.phone, `Payment received. Your toilet access code is ${otp}. Valid for 10 minutes.`);
      console.log(`Reference ${reference} paid. Code: ${otp}`);
    } catch (err) {
      console.error("Webhook processing error:", err);
    }
  }

  res.sendStatus(200);
});

app.post("/validate", requireSiteKey(pool), async (req, res) => {
  const { doorKey, otp } = req.body;
  const site = req.site;

  if (!doorKey || !otp) {
    return res.status(400).json({ valid: false, reason: "doorKey and otp are required" });
  }

  try {
    const result = await pool.query(
      `SELECT t.* FROM transactions t
       JOIN doors d ON d.id = t.door_id
       WHERE t.site_id = $1 AND d.door_key = $2 AND t.otp = $3 AND t.used = false
       ORDER BY t.created_at DESC LIMIT 1`,
      [site.id, doorKey, otp]
    );
    const tx = result.rows[0];

    if (!tx) return res.json({ valid: false, reason: "Invalid or already-used code" });
    if (new Date() > new Date(tx.otp_expires_at)) return res.json({ valid: false, reason: "Code expired" });

    await pool.query("UPDATE transactions SET used = true WHERE id = $1", [tx.id]);
    res.json({ valid: true, reference: tx.reference });
  } catch (err) {
    console.error("Validate error:", err);
    res.status(500).json({ valid: false, reason: "Internal error" });
  }
});

app.post("/nfc/validate", requireSiteKey(pool), async (req, res) => {
  const { uid } = req.body;
  const site = req.site;

  if (!uid) return res.status(400).json({ valid: false, reason: "uid is required" });

  try {
    const result = await pool.query(
      `SELECT nt.name FROM nfc_tags nt
       JOIN nfc_tag_sites nts ON nts.tag_id = nt.id
       WHERE nt.uid = $1 AND nt.active = true AND nts.site_id = $2`,
      [uid, site.id]
    );

    if (result.rows.length === 0) {
      return res.json({ valid: false, reason: "Unknown tag or not authorized for this site" });
    }

    res.json({ valid: true, name: result.rows[0].name });
  } catch (err) {
    console.error("NFC validate error:", err);
    res.status(500).json({ valid: false, reason: "Internal error" });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Toilet payment server running on port ${PORT}`));
