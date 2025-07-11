# mini-csrf [![NPM version](https://img.shields.io/npm/v/mini-csrf.svg?style=flat)](https://www.npmjs.com/package/mini-csrf) [![NPM total downloads](https://img.shields.io/npm/dt/mini-csrf.svg?style=flat)](https://npmjs.org/package/mini-csrf)

A smol CSRF protection middleware for Express applications using a stateless, session-less, HMAC token.

## Introduction

This implementation is probably the smallest possible stateless Cross-Site Request Forgery (CSRF) protection for your Node.js/Express applications that's usably secure. It does _not_ comply with the [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

The use case for it would be when you need light-weight stateless non-session based CSRF protection. If you are using sessions you should use [small-csrf](https://www.npmjs.com/package/small-csrf) instead since it implements an OWASP compliant Double-Submit Cookie Pattern.

### Method

The CSRF token is a [HMAC](https://en.wikipedia.org/wiki/HMAC) hash of the browser user-agent, IP address, the time and a server secret. The token and the time are inserted into the web page that calls a mutating route. The server is able to confirm the correctness of the token by re-creating it, then the time provided is checked to ensure its within the tolerance.

Token comparisons are done in constant time to avoid timing attacks.

### Comparisons

| Feature                               | mini-csrf                       | Double Submit Cookies | Synchronizer Token             |
| ------------------------------------- | ------------------------------- | --------------------- | ------------------------------ |
| **Session required**                  | ❌                              | ❌                    | ✅                             |
| **Stateless**                         | ✅                              | ✅                    | ❌                             |
| **Forgery resistance**                | ✅ (via HMAC)                   | ✅ (via cross-check)  | ✅ (via match to stored value) |
| **Tied to browser**                   | Partially (IP/UA)               | ✅ (via cookie)       | ✅ (via session cookie)        |
| **Resistant to replay**               | ❌ (within time window)         | ❌                    | ❌                             |
| **Prevents CSRF with stolen cookies** | ❌ (attacker can guess context) | ✅                    | ✅                             |

## Installation

```bash
npm install mini-csrf
```

## Quick Start

Basic integration with Express:

```javascript
// npm install express mini-csrf
import express from "express";
import csrfProtection from "mini-csrf";

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// CSRF protection middleware
const csrf = csrfProtection({
  secret: "at-least-32-characters-long-csrf-secret",
});

app.use(csrf.middleware);

// render a form with CSRF token
// the csrf Token Html actually contains the token and time
app.get("/form", (req, res) => {
  res.send(`
    <form action="/submit" method="POST">
      ${csrf.csrfTokenHtml(req)}
      <input type="text" name="data">
      <button type="submit">Submit</button>
    </form>
  `);
});

app.post("/submit", (req, res) => {
  // if the request reaches here, CSRF validation passed since
  // it's done in the middleware
  res.send("Form submitted successfully!");
});

// handler for CSRF errors
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Invalid CSRF token. Form submission failed.");
  }
  next(err);
});

app.listen(3000);
```

## Configuration

The `csrfProtection` function accepts a configuration object with the following options:

### Required Parameters

#### `secret` (string)

The server secret used to generate HMAC tokens. Must be at least 32 characters long.

```javascript
const csrf = csrfProtection({
  secret: "at-least-32-characters-long-csrf-secret",
});
```

### Optional Parameters

#### `fieldNames` (object)

Customize the names of the hidden form fields. Default values shown below:

```javascript
const csrf = csrfProtection({
  secret: "at-least-32-characters-long-csrf-secret",
  fieldNames: {
    token: "_csrf_token", // default
    time: "_csrf_time", // default
  },
});
```

#### `ttl` (number)

Time-to-live for tokens in milliseconds. Tokens older than this will be rejected. Default is 3600000 (1 hour).

```javascript
const csrf = csrfProtection({
  secret: "at-least-32-characters-long-csrf-secret",
  ttl: 1800000, // 30 minutes
});
```

### Complete Configuration Example

```javascript
const csrf = csrfProtection({
  secret: "at-least-32-characters-long-csrf-secret",
  fieldNames: {
    token: "csrf_token",
    time: "csrf_timestamp",
  },
  ttl: 900000, // 15 minutes
});
```

## Contributing

Contributions and issues are [welcome](https://github.com/IanKulin/mini-csrf/issues), especially for security concerns.

## Tests

Uses the built-in Node test runner - available from Node 20
`npm test` to run

## Example App

To run a local demo of `mini-csrf` in an Express app from a cloned repo:

```bash
cd example && npm install && npm start
```

The visit http://localhost:3000

## License

[MIT](LICENSE)

## Versions

- 1.0.0 - initial
- 1.0.1 - README fixes
- 1.0.2 - ReaDmE fIXeS 
