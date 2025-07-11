import { describe, it, beforeEach } from "node:test";
import assert from "node:assert";
import csrfProtection, { constantTimeEquals } from "../mini-csrf.js";
import crypto from "crypto";

describe("CSRF Protection", () => {
  let csrf;
  let mockReq;
  let mockRes;
  let nextCalled;
  let nextError;

  beforeEach(() => {
    csrf = csrfProtection({
      secret: "supersecretkey123456789012345678901234567890",
    });
    mockReq = {
      method: "POST",
      ip: "127.0.0.1",
      headers: { "user-agent": "test-agent" },
      body: {},
    };
    mockRes = {};
    nextCalled = false;
    nextError = null;
  });

  function mockNext(err) {
    nextCalled = true;
    nextError = err || null;
  }

  function generateTestToken(userIdentifier, timestamp) {
    return crypto
      .createHmac("sha256", "supersecretkey123456789012345678901234567890")
      .update(userIdentifier + timestamp)
      .digest("hex");
  }

  function getUserIdentifier(req) {
    return (req.ip || "") + (req.headers["user-agent"] || "");
  }

  describe("Initialization", () => {
    it("should throw error if secret is too short", () => {
      assert.throws(() => {
        csrfProtection({ secret: "short" });
      }, /CSRF secret must be at least 32 characters long/);
    });

    it("should throw error if no secret provided", () => {
      assert.throws(() => {
        csrfProtection({});
      }, /CSRF secret must be at least 32 characters long/);
    });

    it("should accept valid secret", () => {
      assert.doesNotThrow(() => {
        csrfProtection({
          secret: "supersecretkey123456789012345678901234567890",
        });
      });
    });

    it("should use default field names", () => {
      const protection = csrfProtection({
        secret: "supersecretkey123456789012345678901234567890",
      });
      const html = protection.csrfTokenHtml(mockReq);
      assert.match(html, /name="_csrf_token"/);
      assert.match(html, /name="_csrf_time"/);
    });

    it("should use custom field names", () => {
      const protection = csrfProtection({
        secret: "supersecretkey123456789012345678901234567890",
        fieldNames: { token: "custom_token", time: "custom_time" },
      });
      const html = protection.csrfTokenHtml(mockReq);
      assert.match(html, /name="custom_token"/);
      assert.match(html, /name="custom_time"/);
    });
  });

  describe("Safe HTTP Methods", () => {
    ["GET", "HEAD", "OPTIONS"].forEach((method) => {
      it(`should allow ${method} requests without CSRF token`, () => {
        mockReq.method = method;
        csrf.middleware(mockReq, mockRes, mockNext);
        assert.strictEqual(nextCalled, true);
        assert.strictEqual(nextError, null);
      });
    });
  });

  describe("Unsafe HTTP Methods", () => {
    ["POST", "PUT", "DELETE", "PATCH"].forEach((method) => {
      it(`should reject ${method} requests without CSRF token`, () => {
        mockReq.method = method;
        csrf.middleware(mockReq, mockRes, mockNext);
        assert.strictEqual(nextCalled, true);
        assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
        assert.match(nextError.message, /Missing CSRF token or timestamp/);
      });
    });
  });

  describe("Token Generation and Validation", () => {
    it("should generate valid token HTML", () => {
      const html = csrf.csrfTokenHtml(mockReq);
      assert.match(
        html,
        /<input type="hidden" name="_csrf_token" value="[a-f0-9]{64}" \/>/
      );
      assert.match(
        html,
        /<input type="hidden" name="_csrf_time" value="\d+" \/>/
      );
    });

    it("should accept valid CSRF token", () => {
      const html = csrf.csrfTokenHtml(mockReq);
      const tokenMatch = html.match(/name="_csrf_token" value="([^"]+)"/);
      const timeMatch = html.match(/name="_csrf_time" value="([^"]+)"/);

      mockReq.body._csrf_token = tokenMatch[1];
      mockReq.body._csrf_time = timeMatch[1];

      csrf.middleware(mockReq, mockRes, mockNext);
      assert.strictEqual(nextCalled, true);
      assert.strictEqual(nextError, null);
    });

    it("should reject invalid CSRF token", () => {
      mockReq.body._csrf_token = "invalid_token";
      mockReq.body._csrf_time = Date.now().toString();

      csrf.middleware(mockReq, mockRes, mockNext);
      assert.strictEqual(nextCalled, true);
      assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
      assert.match(nextError.message, /Invalid CSRF token/);
    });

    it("should reject expired token", () => {
      const expiredTime = (Date.now() - 4000000).toString(); // 4000 seconds ago
      const userIdentifier = getUserIdentifier(mockReq);
      const expiredToken = generateTestToken(userIdentifier, expiredTime);

      mockReq.body._csrf_token = expiredToken;
      mockReq.body._csrf_time = expiredTime;

      csrf.middleware(mockReq, mockRes, mockNext);
      assert.strictEqual(nextCalled, true);
      assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
      assert.match(nextError.message, /Expired CSRF token/);
    });

    it("should reject token from future", () => {
      const futureTime = (Date.now() + 1000).toString(); // 1 second in future
      const userIdentifier = getUserIdentifier(mockReq);
      const futureToken = generateTestToken(userIdentifier, futureTime);

      mockReq.body._csrf_token = futureToken;
      mockReq.body._csrf_time = futureTime;

      csrf.middleware(mockReq, mockRes, mockNext);
      assert.strictEqual(nextCalled, true);
      assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
      assert.match(nextError.message, /Expired CSRF token/);
    });

    it("should reject invalid timestamp", () => {
      const userIdentifier = getUserIdentifier(mockReq);
      const validToken = generateTestToken(userIdentifier, "invalid_timestamp");

      mockReq.body._csrf_token = validToken;
      mockReq.body._csrf_time = "invalid_timestamp";

      csrf.middleware(mockReq, mockRes, mockNext);
      assert.strictEqual(nextCalled, true);
      assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
      assert.match(nextError.message, /Expired CSRF token/);
    });
  });

  describe("User Identification", () => {
    it("should generate different tokens for different IPs", () => {
      const req1 = { ...mockReq, ip: "127.0.0.1" };
      const req2 = { ...mockReq, ip: "192.168.1.1" };

      const html1 = csrf.csrfTokenHtml(req1);
      const html2 = csrf.csrfTokenHtml(req2);

      const token1 = html1.match(/name="_csrf_token" value="([^"]+)"/)[1];
      const token2 = html2.match(/name="_csrf_token" value="([^"]+)"/)[1];

      assert.notStrictEqual(token1, token2);
    });

    it("should generate different tokens for different user agents", () => {
      const req1 = { ...mockReq, headers: { "user-agent": "browser1" } };
      const req2 = { ...mockReq, headers: { "user-agent": "browser2" } };

      const html1 = csrf.csrfTokenHtml(req1);
      const html2 = csrf.csrfTokenHtml(req2);

      const token1 = html1.match(/name="_csrf_token" value="([^"]+)"/)[1];
      const token2 = html2.match(/name="_csrf_token" value="([^"]+)"/)[1];

      assert.notStrictEqual(token1, token2);
    });

    it("should handle missing IP and user agent", () => {
      const req = { method: "POST", body: {}, headers: {} };
      assert.doesNotThrow(() => {
        csrf.csrfTokenHtml(req);
      });
    });
  });

  describe("Custom TTL", () => {
    it("should respect custom TTL", (t, done) => {
      const shortTtl = csrfProtection({
        secret: "supersecretkey123456789012345678901234567890",
        ttl: 100, // 100ms
      });

      const html = shortTtl.csrfTokenHtml(mockReq);
      const tokenMatch = html.match(/name="_csrf_token" value="([^"]+)"/);
      const timeMatch = html.match(/name="_csrf_time" value="([^"]+)"/);

      mockReq.body._csrf_token = tokenMatch[1];
      mockReq.body._csrf_time = timeMatch[1];

      // Wait for token to expire
      setTimeout(() => {
        shortTtl.middleware(mockReq, mockRes, (err) => {
          try {
            assert.strictEqual(err.code, "EBADCSRFTOKEN");
            assert.match(err.message, /Expired CSRF token/);
            done();
          } catch (e) {
            done(e);
          }
        });
      }, 200);
    });
  });

  describe("Error Handling", () => {
    it("should create CSRF error with correct code", () => {
      mockReq.body._csrf_token = "invalid";
      mockReq.body._csrf_time = Date.now().toString();

      csrf.middleware(mockReq, mockRes, mockNext);
      assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
      assert(nextError instanceof Error);
    });

    it("should handle missing token field", () => {
      mockReq.body._csrf_time = Date.now().toString();

      csrf.middleware(mockReq, mockRes, mockNext);
      assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
      assert.match(nextError.message, /Missing CSRF token or timestamp/);
    });

    it("should handle missing time field", () => {
      mockReq.body._csrf_token = "some_token";

      csrf.middleware(mockReq, mockRes, mockNext);
      assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
      assert.match(nextError.message, /Missing CSRF token or timestamp/);
    });
  });

  describe("Cross-Request Validation", () => {
    it("should reject token generated for different user", () => {
      const req1 = { ...mockReq, ip: "127.0.0.1" };
      const req2 = { ...mockReq, ip: "192.168.1.1" };

      const html = csrf.csrfTokenHtml(req1);
      const tokenMatch = html.match(/name="_csrf_token" value="([^"]+)"/);
      const timeMatch = html.match(/name="_csrf_time" value="([^"]+)"/);

      req2.body = {
        _csrf_token: tokenMatch[1],
        _csrf_time: timeMatch[1],
      };

      csrf.middleware(req2, mockRes, mockNext);
      assert.strictEqual(nextCalled, true);
      assert.strictEqual(nextError.code, "EBADCSRFTOKEN");
      assert.match(nextError.message, /Invalid CSRF token/);
    });
  });
});

describe("constantTimeEquals", () => {
  it("should return true for identical strings", () => {
    assert.strictEqual(constantTimeEquals("hello", "hello"), true);
  });

  it("should return false for different strings same length", () => {
    assert.strictEqual(constantTimeEquals("hello", "world"), false);
  });

  it("should return false for different lengths", () => {
    assert.strictEqual(constantTimeEquals("hello", "hi"), false);
  });

  it("should return true for empty strings", () => {
    assert.strictEqual(constantTimeEquals("", ""), true);
  });

  it("should handle null/undefined values", () => {
    assert.strictEqual(constantTimeEquals(null, null), true);
    assert.strictEqual(constantTimeEquals(undefined, undefined), true);
    assert.strictEqual(constantTimeEquals(null, ""), true);
    assert.strictEqual(constantTimeEquals("", undefined), true);
    assert.strictEqual(constantTimeEquals("hello", null), false);
  });

  it("should handle long strings correctly", () => {
    const longStr1 = "a".repeat(300);
    const longStr2 = "a".repeat(300);
    const longStr3 = "a".repeat(299) + "b";
    
    assert.strictEqual(constantTimeEquals(longStr1, longStr2), true);
    assert.strictEqual(constantTimeEquals(longStr1, longStr3), false);
  });

  it("should work with typical CSRF tokens", () => {
    const token1 = "abc123def456ghi789";
    const token2 = "abc123def456ghi789";
    const token3 = "abc123def456ghi788";
    
    assert.strictEqual(constantTimeEquals(token1, token2), true);
    assert.strictEqual(constantTimeEquals(token1, token3), false);
  });
});
