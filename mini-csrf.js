// mini-csrf/index.js
import crypto from "crypto";

export default function csrfProtection({
  secret,
  fieldNames = { token: "_csrf_token", time: "_csrf_time" },
  ttl = 3600_000,
}) {
  if (!secret || secret.length < 32) {
    throw new Error("CSRF secret must be at least 32 characters long");
  }

  // Generate HMAC token
  function generateToken(userIdentifier, timestamp) {
    return crypto
      .createHmac("sha256", secret)
      .update(userIdentifier + timestamp)
      .digest("hex");
  }

  // Extract user identifier from request (IP + UA)
  function getUserIdentifier(req) {
    return (req.ip || "") + (req.headers["user-agent"] || "");
  }

  // Middleware to validate CSRF on unsafe methods
  function middleware(req, res, next) {
    const method = req.method.toUpperCase();
    if (["GET", "HEAD", "OPTIONS"].includes(method)) return next();

    const token = req.body?.[fieldNames.token];
    const time = req.body?.[fieldNames.time];
    const now = Date.now();

    if (!token || !time) {
      return next(makeCsrfError("Missing CSRF token or timestamp"));
    }

    const expected = generateToken(getUserIdentifier(req), time);
    const age = now - Number(time);

    if (token !== expected) {
      return next(makeCsrfError("Invalid CSRF token"));
    }

    if (isNaN(age) || age < 0 || age > ttl) {
      return next(makeCsrfError("Expired CSRF token"));
    }

    next();
  }

  // Helper: HTML string of hidden input fields
  function csrfTokenHtml(req) {
    const time = Date.now().toString();
    const userId = getUserIdentifier(req);
    const token = generateToken(userId, time);
    return `
      <input type="hidden" name="${fieldNames.token}" value="${token}" />
      <input type="hidden" name="${fieldNames.time}" value="${time}" />
    `;
  }

  function makeCsrfError(message) {
    const err = new Error(message);
    err.code = "EBADCSRFTOKEN";
    return err;
  }

  return {
    middleware,
    csrfTokenHtml,
  };
}
