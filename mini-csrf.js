import crypto from "crypto";

export function constantTimeEquals(a, b) {
  const strA = String(a || "");
  const strB = String(b || "");
  // result is an accumulator for all the errors
  let result = strA.length ^ strB.length;
  const maxLength = Math.max(strA.length, strB.length);
  for (let i = 0; i < maxLength; i++) {
    const charA = i < strA.length ? strA.charCodeAt(i) : 0;
    const charB = i < strB.length ? strB.charCodeAt(i) : 0;
    result |= charA ^ charB;
  }
  return result === 0;
}

export function validateFieldName(name, type) {
  if (typeof name !== "string" || !/^[a-zA-Z0-9_-]+$/.test(name)) {
    throw new Error(
      `Invalid ${type} field name: must contain only alphanumeric characters, underscores, or hyphens`
    );
  }
}

export default function csrfProtection(options) {
  // Validate options parameter
  if (!options || typeof options !== "object") {
    throw new Error("Options parameter is required and must be an object");
  }

  // Destructure with defaults after validation
  const {
    secret,
    fieldNames = { token: "_csrf_token", time: "_csrf_time" },
    ttl = 3600_000,
  } = options;

  // Validate secret
  if (!secret || typeof secret !== "string" || secret.length < 32) {
    throw new Error("CSRF secret must be at least 32 characters long");
  }

  // Validate fieldNames
  if (fieldNames !== null && typeof fieldNames !== "object") {
    throw new Error("fieldNames must be an object");
  }

  validateFieldName(fieldNames.token, "token");
  validateFieldName(fieldNames.time, "time");

  if (fieldNames.token === fieldNames.time) {
    throw new Error("Token and time field names must be different");
  }

  // Validate ttl
  if (typeof ttl !== "number" || ttl <= 0 || !Number.isFinite(ttl)) {
    throw new Error("ttl must be a positive finite number");
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

    // Skip validation for non-mutable methods
    if (["GET", "HEAD", "OPTIONS"].includes(method)) return next();

    const token = req.body?.[fieldNames.token];
    const time = req.body?.[fieldNames.time];
    const now = Date.now();

    if (!token || !time) {
      return next(makeCsrfError("Missing CSRF token or timestamp"));
    }

    const expected = generateToken(getUserIdentifier(req), time);
    const age = now - Number(time);

    if (!constantTimeEquals(token, expected)) {
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
    // field names are checked for safety at middleware creation
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
