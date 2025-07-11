import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import csrfProtection from "../mini-csrf.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware setup
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

// CSRF protection middleware
const csrf = csrfProtection({
  secret: "at-least-32-characters-long-csrf-secret-for-guest-book-app",
});

app.use(csrf.middleware);

// In-memory guest book storage (in a real app, you'd use a database)
const guestBook = [];

// Routes
app.get("/", (req, res) => {
  res.render("index", { 
    csrfTokenHtml: csrf.csrfTokenHtml(req)
  });
});

app.post("/", (req, res) => {
  const { name } = req.body;
  
  if (!name || name.trim() === "") {
    return res.render("index", { 
      csrfTokenHtml: csrf.csrfTokenHtml(req),
      error: "Please enter your name"
    });
  }
  
  // Add to guest book
  guestBook.push({
    name: name.trim(),
    timestamp: new Date().toISOString()
  });
  
  res.redirect("/guestbook");
});

app.get("/guestbook", (req, res) => {
  res.render("guestbook", { 
    entries: guestBook
  });
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).render("error", { 
      message: "Invalid CSRF token. Please try again." 
    });
  }
  next(err);
});

// Generic error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render("error", { 
    message: "Something went wrong!" 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render("error", { 
    message: "Page not found" 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Guest book app running on http://localhost:${PORT}`);
});