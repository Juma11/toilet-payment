/**
 * Public Toilet Payment System — Backend
 * Flow:
 *  1. POST /charge        -> triggers Paystack M-Pesa STK push
 *  2. POST /paystack/webhook -> Paystack confirms payment -> generate OTP -> send SMS
 *  3. POST /validate      -> ESP32 door checks OTP -> unlock or deny
 *
 * Storage: in-memory Map for MVP. Swap for SQLite/Postgres before going live
 * (in-memory state is lost on restart, and won't work if you run >1 server instance).
 */

require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const fetch = (...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(express.json());

// ---- Config ----
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const DOOR_PRICE_KES = {
  male: 10,
  female: 10,
  disabled_m: 10,
  disabled_f: 10,
  shower_m: 50,
  shower_f: 50,
};
const OTP_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes
const OTP_LENGTH = 6;

// ---- In-memory stores (swap for DB later) ----
const transactions = new Map(); // reference -> { phone, doorId, status, otp, expiresAt, used }

// ---- Helpers ----
function generateOtp(length = OTP_LENGTH) {
  const digits = "0123456789";
  let otp = "";
  for (let i = 0; i < length; i++) {
    otp += digits[crypto.randomInt(0, digits.length)];
  }
  return otp;
}

function generateReference() {
  return "toilet_" + crypto.randomBytes(8).toString("hex");
}

// Paystack requires Kenyan numbers as +254XXXXXXXXX.
// Accepts 07XXXXXXXX, 7XXXXXXXX, 254XXXXXXXXX, or +254XXXXXXXXX and normalizes to +254XXXXXXXXX.
function normalizeKenyanPhone(raw) {
  const digits = raw.replace(/[^\d]/g, ""); // strip spaces, +, dashes etc.

  if (digits.length === 12 && digits.startsWith("254")) {
    return "+" + digits; // 254768406807 -> +254768406807
  }
  if (digits.length === 10 && digits.startsWith("0")) {
    return "+254" + digits.slice(1); // 0768406807 -> +254768406807
  }
  if (digits.length === 9) {
    return "+254" + digits; // 768406807 -> +254768406807
  }
  return null; // couldn't confidently normalize
}

// Stub — replace with Africa's Talking / Twilio / your SMS gateway of choice
async function sendSms(phone, message) {
  console.log(`[SMS -> ${phone}]: ${message}`);
  // await africasTalking.sms.send({ to: [phone], message });
}

// ---- 1. Initiate payment (STK push) ----
app.post("/charge", async (req, res) => {
  const { phone, doorId, email } = req.body;

  if (!phone || !doorId) {
    return res.status(400).json({ error: "phone and doorId are required" });
  }
  if (!(doorId in DOOR_PRICE_KES)) {
    return res.status(400).json({ error: `Unknown doorId. Valid: ${Object.keys(DOOR_PRICE_KES).join(", ")}` });
  }

  const normalizedPhone = normalizeKenyanPhone(phone);
  if (!normalizedPhone) {
    return res.status(400).json({ error: "Could not parse phone number. Use format 07XXXXXXXX or +254XXXXXXXXX." });
  }

  const amount = DOOR_PRICE_KES[doorId];
  const reference = generateReference();

  try {
    const response = await fetch("https://api.paystack.co/charge", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: email || "info@vintechafrica.com", // Paystack requires a valid-looking email
        amount: amount * 100,
        currency: "KES",
        reference,
        mobile_money: {
          phone: normalizedPhone,
          provider: "mpesa",
        },
      }),
    });

    const data = await response.json();

    if (!data.status) {
      return res.status(400).json({ error: data.message || "Charge initiation failed" });
    }

    transactions.set(reference, {
      phone: normalizedPhone,
      doorId,
      status: "pending",
      otp: null,
      expiresAt: null,
      used: false,
    });

    return res.json({
      message: "STK push sent. Ask the customer to enter their M-Pesa PIN.",
      reference,
      paystackStatus: data.data.status,
    });
  } catch (err) {
    console.error("Charge error:", err);
    return res.status(500).json({ error: "Failed to initiate charge" });
  }
});

// ---- 2. Paystack webhook: payment confirmed -> generate OTP ----
app.post("/paystack/webhook", async (req, res) => {
  // IMPORTANT: verify the signature before trusting this payload in production.
  // const signature = req.headers["x-paystack-signature"];
  // const hash = crypto.createHmac("sha512", PAYSTACK_SECRET_KEY).update(JSON.stringify(req.body)).digest("hex");
  // if (hash !== signature) return res.sendStatus(401);

  const event = req.body;

  if (event.event === "charge.success") {
    const reference = event.data.reference;
    const tx = transactions.get(reference);

    if (!tx) {
      console.warn(`Webhook for unknown reference: ${reference}`);
      return res.sendStatus(200);
    }

    const otp = generateOtp();
    tx.status = "paid";
    tx.otp = otp;
    tx.expiresAt = Date.now() + OTP_EXPIRY_MS;
    transactions.set(reference, tx);

    await sendSms(
      tx.phone,
      `Payment received. Your toilet access code is ${otp}. Valid for 10 minutes. Enter it on the door keypad.`
    );
  }

  res.sendStatus(200);
});

// ---- 3. Door validates OTP ----
app.post("/validate", (req, res) => {
  const { doorId, otp } = req.body;

  if (!doorId || !otp) {
    return res.status(400).json({ valid: false, reason: "doorId and otp required" });
  }

  const match = [...transactions.entries()].find(
    ([, tx]) => tx.doorId === doorId && tx.otp === otp && !tx.used
  );

  if (!match) {
    return res.json({ valid: false, reason: "Invalid or already-used code" });
  }

  const [reference, tx] = match;

  if (Date.now() > tx.expiresAt) {
    return res.json({ valid: false, reason: "Code expired" });
  }

  tx.used = true;
  transactions.set(reference, tx);

  return res.json({ valid: true, reference });
});

// ---- Debug: list transactions (remove before going live) ----
app.get("/debug/transactions", (req, res) => {
  res.json([...transactions.entries()].map(([ref, tx]) => ({ reference: ref, ...tx })));
});

// ---- Health check ----
app.get("/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Toilet payment server running on port ${PORT}`));
