const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is not set. Add it to your .env before starting the server.");
}

async function hashPassword(plain) {
  return bcrypt.hash(plain, 12);
}

async function comparePassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "12h" });
}

// Verifies "Authorization: Bearer <token>" and attaches { id, role, clientId } to req.user
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

function requireSuperAdmin(req, res, next) {
  if (!req.user || req.user.role !== "super_admin") {
    return res.status(403).json({ error: "Super admin access required" });
  }
  next();
}

// Resolves which clientId a request should operate on:
// - client_admin: always their own clientId (ignores any query override)
// - super_admin: their own clientId is null, so they must pass ?clientId=<id> to act on a client
function resolveClientId(req) {
  if (req.user.role === "super_admin") {
    const q = req.query.clientId;
    return q ? parseInt(q, 10) : null;
  }
  return req.user.clientId;
}

// Authenticates devices (reception app, ESP32 doors) via "x-site-key" header.
// Looks up the site and attaches it to req.site — no login/session involved.
function requireSiteKey(pool) {
  return async (req, res, next) => {
    const siteKey = req.headers["x-site-key"];
    if (!siteKey) {
      return res.status(401).json({ error: "Missing x-site-key header" });
    }
    try {
      const result = await pool.query("SELECT * FROM sites WHERE site_key = $1", [siteKey]);
      if (result.rows.length === 0) {
        return res.status(401).json({ error: "Invalid site key" });
      }
      req.site = result.rows[0];
      next();
    } catch (err) {
      console.error("Site key lookup error:", err);
      res.status(500).json({ error: "Internal error" });
    }
  };
}

module.exports = {
  hashPassword,
  comparePassword,
  signToken,
  requireAuth,
  requireSuperAdmin,
  resolveClientId,
  requireSiteKey,
};
