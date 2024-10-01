const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cors = require("cors");
require("dotenv").config();
const MySQLStore = require("express-mysql-session")(session);
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

const app = express();

// Middleware
app.use(
  cors({
    origin: "https://ucebnicafun.emax-controls.eu", // Frontend URL
    credentials: true, // Must be enabled for cross-origin cookies
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10, // Adjust based on your server capacity
  queueLimit: 0,
});

// Session store configuration
const sessionStore = new MySQLStore({}, pool);

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-secret-key",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      secure: true, // Must be true since you're using HTTPS
      httpOnly: true, // Prevent client-side JS from accessing the cookie
      sameSite: "none", // Required for cross-origin requests
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
    },
  })
);

// Rate limiter middleware for login route
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit to 10 requests per windowMs
  message: "Too many login attempts, please try again later.",
});

// Root route
app.get("/", (req, res) => {
  res.send("Backend server is running");
});

// Login route
app.post(
  "/login",
  loginLimiter,
  [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("surname").trim().notEmpty().withMessage("Surname is required"),
    body("password").notEmpty().withMessage("Password is required"),
    body("role_id").isInt().withMessage("Role ID must be an integer"),
    body("city_id").isInt().withMessage("City ID must be an integer"),
  ],
  async (req, res) => {
    // Validate input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.error("Validation errors:", errors.array());
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, surname, password, role_id, city_id } = req.body;

    try {
      const query = `
        SELECT id, name, surname, password, role_id, city_id, age, category
        FROM front_users
        WHERE name = ? AND surname = ? AND role_id = ? AND city_id = ?`;

      const [results] = await pool.execute(query, [
        name,
        surname,
        role_id,
        city_id,
      ]);

      if (results.length === 0) {
        console.log("User not found with provided credentials");
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const user = results[0];

      // Check password
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        console.log("Incorrect password");
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // Set session after successful login
      req.session.user = {
        id: user.id,
        name: user.name,
        surname: user.surname,
        role_id: user.role_id,
        city_id: user.city_id,
        age: user.age,
        category: user.category,
      };

      res.status(200).json({ user: req.session.user });
    } catch (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ message: "Internal server error" });
    }
  }
);

// Check authentication
app.get("/check-auth", (req, res) => {
  if (req.session.user) {
    res.status(200).json(req.session.user);
  } else {
    res.status(401).json({ message: "Not authenticated" });
  }
});

// Logout route
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Failed to log out" });
    }
    res.clearCookie("connect.sid");
    res.status(200).json({ message: "Logged out" });
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
