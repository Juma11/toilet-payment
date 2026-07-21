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
const rateLimit = require("express-rate-limit");
const cors = require("cors");
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
app.use(cors());

// Public endpoints have no login and no site-key secrecy protecting them from
// randoms on the internet — these limits keep them usable for real customers
// while blocking someone from hammering STK pushes or brute-forcing phone
// numbers against the lookup endpoints.
const chargeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many payment attempts from this device. Please wait a few minutes and try again." },
  standardHeaders: true,
  legacyHeaders: false,
});
const lookupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { error: "Too many lookup attempts. Please wait a few minutes and try again." },
  standardHeaders: true,
  legacyHeaders: false,
});
const generalPublicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: { error: "Too many requests. Please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; },
}));

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const OTP_EXPIRY_MS = 60 * 60 * 1000; // 60 min — enough time for someone paying remotely to travel and arrive
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
    // Check the main clients table first (super admins and client owners)
    const clientResult = await pool.query("SELECT * FROM clients WHERE email = $1", [email]);
    const client = clientResult.rows[0];

    if (client && (await comparePassword(password, client.password_hash))) {
      const token = signToken({
        id: client.id,
        role: client.role,
        clientId: client.role === "super_admin" ? null : client.id,
        name: client.name,
      });
      return res.json({ token, role: client.role, name: client.name });
    }

    // Fall back to staff logins
    const staffResult = await pool.query("SELECT * FROM client_staff WHERE email = $1 AND active = true", [email]);
    const staff = staffResult.rows[0];

    if (staff && (await comparePassword(password, staff.password_hash))) {
      const token = signToken({
        id: staff.id,
        role: "client_staff",
        clientId: staff.client_id,
        name: staff.name,
      });
      return res.json({ token, role: "client_staff", name: staff.name });
    }

    return res.status(401).json({ error: "Invalid email or password" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// Self-service: change your own password while logged in. Requires the
// current password, since no email/SMS delivery exists yet to verify
// identity any other way for a "forgot password" flow.
app.post("/auth/change-password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "currentPassword and a newPassword (6+ chars) are required" });
  }

  try {
    const table = req.user.role === "client_staff" ? "client_staff" : "clients";
    const result = await pool.query(`SELECT * FROM ${table} WHERE id = $1`, [req.user.id]);
    const account = result.rows[0];

    if (!account || !(await comparePassword(currentPassword, account.password_hash))) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    const newHash = await hashPassword(newPassword);
    await pool.query(`UPDATE ${table} SET password_hash = $1 WHERE id = $2`, [newHash, req.user.id]);
    res.json({ message: "Password changed" });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// Admin-triggered reset for someone actually locked out — super admin can
// reset any client owner's password.
app.put("/admin/clients/:id/reset-password", requireAuth, requireSuperAdmin, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "newPassword (6+ chars) is required" });
  }
  try {
    const newHash = await hashPassword(newPassword);
    const result = await pool.query(
      "UPDATE clients SET password_hash = $1 WHERE id = $2 AND role = 'client_admin' RETURNING id",
      [newHash, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Client not found" });
    res.json({ message: "Password reset" });
  } catch (err) {
    console.error("Reset client password error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// Same idea, scoped to a client's own staff — a client_admin can reset
// their own staff's password (or super admin can, via ?clientId=).
app.put("/staff/:id/reset-password", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "newPassword (6+ chars) is required" });
  }
  try {
    const newHash = await hashPassword(newPassword);
    const result = await pool.query(
      "UPDATE client_staff SET password_hash = $1 WHERE id = $2 AND ($3::int IS NULL OR client_id = $3) RETURNING id",
      [newHash, req.params.id, clientId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Staff account not found" });
    res.json({ message: "Password reset" });
  } catch (err) {
    console.error("Reset staff password error:", err);
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

// Global installer PIN — same value works to set up any reception device
// across every site. Only the super admin can see or change it.
app.get("/admin/installer-pin", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT installer_pin FROM system_settings WHERE id = 1");
    res.json({ installerPin: result.rows[0]?.installer_pin || null });
  } catch (err) {
    console.error("Get installer PIN error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.put("/admin/installer-pin", requireAuth, requireSuperAdmin, async (req, res) => {
  const { installerPin } = req.body;
  if (!installerPin || installerPin.length < 4) {
    return res.status(400).json({ error: "PIN must be at least 4 characters" });
  }
  try {
    await pool.query(
      `INSERT INTO system_settings (id, installer_pin) VALUES (1, $1)
       ON CONFLICT (id) DO UPDATE SET installer_pin = $1`,
      [installerPin]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("Update installer PIN error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// =====================================================================
// CLIENT-SCOPED: sites
// =====================================================================

app.post("/sites", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  if (!clientId) return res.status(400).json({ error: "clientId is required (super admin: pass ?clientId=)" });

  const { name, doors, address, latitude, longitude } = req.body;
  if (!name || !doors || typeof doors !== "object" || Object.keys(doors).length === 0) {
    return res.status(400).json({ error: "name and a non-empty doors object (doorKey -> price) are required" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const siteKey = generateSiteKey();
    const siteResult = await client.query(
      "INSERT INTO sites (client_id, name, site_key, address, latitude, longitude) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
      [clientId, name, siteKey, address || null, latitude || null, longitude || null]
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

app.patch("/sites/:id", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  const siteId = parseInt(req.params.id, 10);
  const { name, doors, removeDoors, address, latitude, longitude } = req.body;

  const client = await pool.connect();
  try {
    // Confirm the site belongs to this client (or, for super admin with no clientId filter, any site)
    const ownCheck = await client.query(
      "SELECT * FROM sites WHERE id = $1 AND ($2::int IS NULL OR client_id = $2)",
      [siteId, clientId]
    );
    if (ownCheck.rows.length === 0) return res.status(404).json({ error: "Site not found" });

    await client.query("BEGIN");

    if (name) {
      await client.query("UPDATE sites SET name = $1 WHERE id = $2", [name, siteId]);
    }
    if (address !== undefined || latitude !== undefined || longitude !== undefined) {
      await client.query(
        "UPDATE sites SET address = COALESCE($1, address), latitude = COALESCE($2, latitude), longitude = COALESCE($3, longitude) WHERE id = $4",
        [address || null, latitude ?? null, longitude ?? null, siteId]
      );
    }

    if (doors && typeof doors === "object") {
      for (const [doorKey, price] of Object.entries(doors)) {
        await client.query(
          `INSERT INTO doors (site_id, door_key, price_kes, active) VALUES ($1, $2, $3, true)
           ON CONFLICT (site_id, door_key) DO UPDATE SET price_kes = $3, active = true`,
          [siteId, doorKey, price]
        );
      }
    }

    if (Array.isArray(removeDoors)) {
      for (const doorKey of removeDoors) {
        await client.query(
          "UPDATE doors SET active = false WHERE site_id = $1 AND door_key = $2",
          [siteId, doorKey]
        );
      }
    }

    await client.query("COMMIT");

    const updated = await pool.query("SELECT * FROM sites WHERE id = $1", [siteId]);
    const doorsResult = await pool.query("SELECT door_key, price_kes FROM doors WHERE site_id = $1 AND active = true", [siteId]);
    res.json({
      ...updated.rows[0],
      doors: doorsResult.rows.reduce((acc, d) => ({ ...acc, [d.door_key]: d.price_kes }), {}),
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Update site error:", err);
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
      const doorsResult = await pool.query("SELECT door_key, price_kes FROM doors WHERE site_id = $1 AND active = true", [site.id]);
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

app.post("/charge", chargeLimiter, requireSiteKey(pool), async (req, res) => {
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
    const doorResult = await pool.query("SELECT * FROM doors WHERE site_id = $1 AND door_key = $2 AND active = true", [site.id, doorKey]);
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
      console.error("Paystack charge rejected:", JSON.stringify(data));
      return res.status(400).json({ error: data.message || "Charge initiation failed" });
    }

    await pool.query(
      "INSERT INTO transactions (reference, site_id, door_id, phone, amount_kes, status) VALUES ($1, $2, $3, $4, $5, 'pending')",
      [reference, site.id, door.id, normalizedPhone, door.price_kes]
    );

    res.json({ message: "STK push sent", reference, paystackStatus: data.data.status });
  } catch (err) {
    console.error("Charge error:", err);
    res.status(500).json({ error: "Failed to initiate charge" });
  }
});

app.post("/paystack/webhook", async (req, res) => {
  const signature = req.headers["x-paystack-signature"];
  const hash = crypto.createHmac("sha512", PAYSTACK_SECRET_KEY).update(req.rawBody).digest("hex");
  if (hash !== signature) {
    console.warn("Webhook signature mismatch — rejecting");
    return res.sendStatus(401);
  }

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

// Door units poll this periodically (every 30-60s) to keep a local cache of
// currently valid codes/tags, so a brief WiFi drop doesn't strand a paying
// customer at the door — the ESP32 falls back to this cache if the live
// /validate or /nfc/validate call times out.
app.get("/site-sync", requireSiteKey(pool), async (req, res) => {
  try {
    const otpResult = await pool.query(
      `SELECT d.door_key, t.otp, t.otp_expires_at
       FROM transactions t JOIN doors d ON d.id = t.door_id
       WHERE t.site_id = $1 AND t.status = 'paid' AND t.used = false AND t.otp_expires_at > now()`,
      [req.site.id]
    );
    const tagResult = await pool.query(
      `SELECT nt.uid, nt.name FROM nfc_tags nt
       JOIN nfc_tag_sites nts ON nts.tag_id = nt.id
       WHERE nts.site_id = $1 AND nt.active = true`,
      [req.site.id]
    );
    res.json({
      otps: otpResult.rows.map((r) => ({ doorKey: r.door_key, otp: r.otp, expiresAt: r.otp_expires_at })),
      tags: tagResult.rows.map((r) => ({ uid: r.uid, name: r.name })),
    });
  } catch (err) {
    console.error("Site sync error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// One-time device binding step — requires a technician PIN on top of the
// site key, so only someone who knows the installer PIN can connect a new
// reception device to a site. Once bound, the device only needs its site
// key for everyday use (see /site-info below) — no PIN required again.
app.post("/device-setup", lookupLimiter, requireSiteKey(pool), async (req, res) => {
  const { installerPin } = req.body;

  try {
    const settingsResult = await pool.query("SELECT installer_pin FROM system_settings WHERE id = 1");
    if (settingsResult.rows.length === 0) {
      return res.status(500).json({ error: "Installer PIN not configured on server" });
    }
    if (installerPin !== settingsResult.rows[0].installer_pin) {
      return res.status(401).json({ error: "Incorrect technician PIN" });
    }
    res.json({ ok: true, siteName: req.site.name });
  } catch (err) {
    console.error("Device setup PIN check error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.get("/site-info", requireSiteKey(pool), async (req, res) => {
  try {
    const doorsResult = await pool.query("SELECT door_key, price_kes FROM doors WHERE site_id = $1 AND active = true", [req.site.id]);
    const doors = doorsResult.rows.reduce((acc, d) => ({ ...acc, [d.door_key]: d.price_kes }), {});
    res.json({ name: req.site.name, doors });
  } catch (err) {
    console.error("Site info error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.get("/transactions", requireSiteKey(pool), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.reference, d.door_key, t.phone, t.status, t.otp, t.otp_expires_at, t.used, t.created_at
       FROM transactions t JOIN doors d ON d.id = t.door_id
       WHERE t.site_id = $1 AND t.created_at >= CURRENT_DATE
       ORDER BY t.created_at DESC LIMIT 50`,
      [req.site.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("List transactions error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.get("/finance/summary", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  try {
    const result = await pool.query(
      `SELECT s.id AS site_id, s.name AS site_name,
              COALESCE(SUM(t.amount_kes) FILTER (WHERE t.status = 'paid'), 0) AS revenue_kes,
              COUNT(*) FILTER (WHERE t.status = 'paid') AS paid_count,
              COUNT(*) FILTER (WHERE t.status = 'pending') AS pending_count
       FROM sites s
       LEFT JOIN transactions t ON t.site_id = s.id
       WHERE ($1::int IS NULL OR s.client_id = $1)
       GROUP BY s.id, s.name
       ORDER BY revenue_kes DESC`,
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Finance summary error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.get("/admin-transactions", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  const { siteId, status, phone, dateFrom, dateTo } = req.query;

  const conditions = ["($1::int IS NULL OR s.client_id = $1)"];
  const params = [clientId];

  if (siteId) { params.push(siteId); conditions.push(`t.site_id = $${params.length}`); }
  if (status) { params.push(status); conditions.push(`t.status = $${params.length}`); }
  if (phone) { params.push(`%${phone}%`); conditions.push(`t.phone ILIKE $${params.length}`); }
  if (dateFrom) { params.push(dateFrom); conditions.push(`t.created_at >= $${params.length}`); }
  if (dateTo) { params.push(dateTo); conditions.push(`t.created_at <= $${params.length}`); }

  try {
    const result = await pool.query(
      `SELECT t.reference, s.name AS site_name, d.door_key, t.phone, t.amount_kes,
              t.status, t.used, t.created_at
       FROM transactions t
       JOIN sites s ON s.id = t.site_id
       JOIN doors d ON d.id = t.door_id
       WHERE ${conditions.join(" AND ")}
       ORDER BY t.created_at DESC
       LIMIT 200`,
      params
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Admin transactions search error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// =====================================================================
// CLIENT-SCOPED: staff logins (added by the client owner, or by super admin on their behalf)
// =====================================================================

app.post("/staff", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  if (!clientId) return res.status(400).json({ error: "clientId is required (super admin: pass ?clientId=)" });

  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: "name, email and password are required" });
  }

  try {
    const passwordHash = await hashPassword(password);
    const result = await pool.query(
      "INSERT INTO client_staff (client_id, name, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, name, email, active, created_at",
      [clientId, name, email, passwordHash]
    );
    res.json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") return res.status(409).json({ error: "Email already in use" });
    console.error("Create staff error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.get("/staff", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  if (!clientId) return res.status(400).json({ error: "clientId is required (super admin: pass ?clientId=)" });

  try {
    const result = await pool.query(
      "SELECT id, name, email, active, created_at FROM client_staff WHERE client_id = $1 ORDER BY created_at DESC",
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("List staff error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.delete("/staff/:id", requireAuth, async (req, res) => {
  const clientId = resolveClientId(req);
  try {
    const result = await pool.query(
      "UPDATE client_staff SET active = false WHERE id = $1 AND ($2::int IS NULL OR client_id = $2) RETURNING id",
      [req.params.id, clientId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Staff account not found" });
    res.json({ message: "Staff account deactivated" });
  } catch (err) {
    console.error("Deactivate staff error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// =====================================================================
// PUBLIC: customer-facing nearby search + pay-in-advance (no auth — this is
// the point, anyone can browse sites and pay for themselves before arriving)
// =====================================================================

app.get("/public/sites/nearby", generalPublicLimiter, async (req, res) => {
  const lat = parseFloat(req.query.lat);
  const lng = parseFloat(req.query.lng);
  const radiusKm = parseFloat(req.query.radiusKm) || 10;

  if (isNaN(lat) || isNaN(lng)) {
    return res.status(400).json({ error: "lat and lng query params are required" });
  }

  try {
    const result = await pool.query(
      `SELECT * FROM (
         SELECT id, name, address, latitude, longitude,
                (6371 * acos(
                   LEAST(1, cos(radians($1)) * cos(radians(latitude)) * cos(radians(longitude) - radians($2))
                   + sin(radians($1)) * sin(radians(latitude)))
                )) AS distance_km
         FROM sites
         WHERE latitude IS NOT NULL AND longitude IS NOT NULL
       ) sub
       WHERE distance_km <= $3
       ORDER BY distance_km ASC
       LIMIT 50`,
      [lat, lng, radiusKm]
    );

    const sites = result.rows;
    for (const site of sites) {
      const doorsResult = await pool.query(
        "SELECT door_key, price_kes FROM doors WHERE site_id = $1 AND active = true",
        [site.id]
      );
      site.doors = doorsResult.rows.reduce((acc, d) => ({ ...acc, [d.door_key]: d.price_kes }), {});
      site.distance_km = Math.round(site.distance_km * 10) / 10;
    }
    res.json(sites);
  } catch (err) {
    console.error("Nearby sites error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.post("/public/charge", chargeLimiter, async (req, res) => {
  const { siteId, doorKey, phone, email } = req.body;
  if (!siteId || !doorKey || !phone) {
    return res.status(400).json({ error: "siteId, doorKey and phone are required" });
  }

  const normalizedPhone = normalizeKenyanPhone(phone);
  if (!normalizedPhone) {
    return res.status(400).json({ error: "Could not parse phone number" });
  }

  try {
    const doorResult = await pool.query(
      "SELECT * FROM doors WHERE site_id = $1 AND door_key = $2 AND active = true",
      [siteId, doorKey]
    );
    const door = doorResult.rows[0];
    if (!door) return res.status(400).json({ error: "Unknown or inactive door for this site" });

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
      console.error("Paystack charge rejected:", JSON.stringify(data));
      return res.status(400).json({ error: data.message || "Charge initiation failed" });
    }

    await pool.query(
      "INSERT INTO transactions (reference, site_id, door_id, phone, amount_kes, status) VALUES ($1, $2, $3, $4, $5, 'pending')",
      [reference, siteId, door.id, normalizedPhone, door.price_kes]
    );

    res.json({ message: "STK push sent", reference, paystackStatus: data.data.status });
  } catch (err) {
    console.error("Public charge error:", err);
    res.status(500).json({ error: "Failed to initiate charge" });
  }
});

// Public version of the phone lookup, for the customer app (which has no
// site-key or login at all). Same safety model: only returns results for
// the exact phone number given, across all sites, never a browsable list.
// IMPORTANT: this must be registered BEFORE /public/transactions/:reference
// below, or Express matches "by-phone" as if it were a :reference value.
app.get("/public/transactions/by-phone", lookupLimiter, async (req, res) => {
  const { phone } = req.query;
  if (!phone) return res.status(400).json({ error: "phone is required" });

  const normalizedPhone = normalizeKenyanPhone(phone);
  if (!normalizedPhone) return res.status(400).json({ error: "Could not parse phone number" });

  try {
    const result = await pool.query(
      `SELECT t.reference, s.name AS site_name, d.door_key, t.status, t.otp, t.otp_expires_at, t.used, t.created_at
       FROM transactions t
       JOIN sites s ON s.id = t.site_id
       JOIN doors d ON d.id = t.door_id
       WHERE t.phone = $1 AND t.created_at > now() - interval '24 hours'
       ORDER BY t.created_at DESC
       LIMIT 10`,
      [normalizedPhone]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Public phone lookup error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// The reference itself acts as a capability token — only someone who has it
// (the customer who just paid) can poll this, so no further auth is needed.
app.get("/public/transactions/:reference", generalPublicLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT status, otp, otp_expires_at, used FROM transactions WHERE reference = $1",
      [req.params.reference]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Not found" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Public transaction status error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

// Targeted lookup only — requires the phone number the customer themselves
// gives, unlike a browsable list. Safe for reception to use even though
// it's site-key (not login) authenticated, since a stranger would need to
// already know the exact phone number to retrieve anything.
app.get("/transactions/lookup", lookupLimiter, requireSiteKey(pool), async (req, res) => {
  const { phone } = req.query;
  if (!phone) return res.status(400).json({ error: "phone is required" });

  const normalizedPhone = normalizeKenyanPhone(phone);
  if (!normalizedPhone) return res.status(400).json({ error: "Could not parse phone number" });

  try {
    const result = await pool.query(
      `SELECT t.reference, d.door_key, t.status, t.otp, t.otp_expires_at, t.used, t.created_at
       FROM transactions t JOIN doors d ON d.id = t.door_id
       WHERE t.site_id = $1 AND t.phone = $2 AND t.created_at > now() - interval '24 hours'
       ORDER BY t.created_at DESC
       LIMIT 10`,
      [req.site.id, normalizedPhone]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Phone lookup error:", err);
    res.status(500).json({ error: "Internal error" });
  }
});

app.get("/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3001;
// =====================================================================
// FALLBACK: poll Paystack directly for pending transactions
// Doesn't rely on the webhook arriving at all — asks Paystack "did this
// succeed?" using the same secret key already in .env. Catches payments
// that succeeded but whose webhook never reached us for any reason.
// =====================================================================
async function pollPendingTransactions() {
  try {
    const pending = await pool.query(
      `SELECT * FROM transactions
       WHERE status = 'pending' AND created_at > now() - interval '30 minutes'`
    );

    for (const tx of pending.rows) {
      try {
        const verifyRes = await fetch(`https://api.paystack.co/transaction/verify/${tx.reference}`, {
          headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` },
        });
        const data = await verifyRes.json();

        if (data.status && data.data && data.data.status === "success") {
          const otp = generateOtp();
          const expiresAt = new Date(Date.now() + OTP_EXPIRY_MS);

          await pool.query(
            "UPDATE transactions SET status = 'paid', otp = $1, otp_expires_at = $2 WHERE id = $3",
            [otp, expiresAt, tx.id]
          );

          await sendSms(tx.phone, `Payment received. Your toilet access code is ${otp}. Valid for 10 minutes.`);
          console.log(`[poll] Reference ${tx.reference} confirmed paid via Paystack verify. Code: ${otp}`);
        }
      } catch (err) {
        console.error(`[poll] Verify failed for ${tx.reference}:`, err.message);
      }
    }
  } catch (err) {
    console.error("[poll] Error checking pending transactions:", err.message);
  }
}

setInterval(pollPendingTransactions, 20000); // check every 20 seconds

app.listen(PORT, () => console.log(`Toilet payment server running on port ${PORT}`));
