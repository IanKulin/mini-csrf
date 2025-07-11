# mini-csrf

A tiny CSRF protection middleware for Express applications using a stateless HMAC token.

## Introduction

This implementation is probably the smallest possible stateless Cross-Site Request Forgery (CSRF) protection for your Node.js/Express applications that's usably secure. It does *not* comply with the [OWASP]((https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)).

The use case for it would be when you need light-weight stateless non-session based CSRF protection. If you are using sessions you should use [small-csrf](https://www.npmjs.com/package/small-csrf) instead since it implements an OWASP compliant Double-Submit Cookie Pattern.

### Method
The CSRF token is a [HMAC](https://en.wikipedia.org/wiki/HMAC) hash of the browser user-agent, IP address, the time and a server secret. The token and the time are inserted into the web page that calls a mutating route. The server is able to confirm the correctness of the token by re-creating it, then the time provided is checked to ensure its within the tolerance.

### Comparisons

| Feature                               | mini-csrf                      | Double Submit Cookies | Synchronizer Token            |
| ------------------------------------- | ------------------------------ | --------------------- | ----------------------------- |
| **Session required**                  | ❌                              | ❌                     | ✅                             |
| **Stateless**                         | ✅                              | ✅                     | ❌                             |
| **Forgery resistance**                | ✅ (via HMAC)                   | ✅ (via cross-check)   | ✅ (via match to stored value) |
| **Tied to browser**                   | Partially (IP/UA)              | ✅ (via cookie)        | ✅ (via session cookie)        |
| **Susceptible to replay**             | ✅ (within time window)         | ✅                     | ✅                             |
| **Prevents CSRF with stolen cookies** | ❌ (attacker can guess context) | ✅                     | ✅                             |


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

## Contributing

Contributions and issues are welcome, especially for security issues.

## Tests

Uses the built-in Node test runner - available from Node 20
`npm test` to run

## Example App

To run a local demo of `mini-csrf` in an Express app from a cloned repo:

```bash
cd example
npm install
npm start
```

## License

[MIT](LICENSE)

## Versions
- 1.0.0 - initial

