const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cors = require("cors");
require("dotenv").config();

const app = express();

// Middleware
app.use(
  cors({
    origin: "https://ucebnicafun.emax-controls.eu/",
    credentials: true, // Allow credentials (cookies) to be sent
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set up session management
app.use(
  session({
    secret: "secret-key", // Replace with your own secret key
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: true, // Set true if using HTTPS, false for localhost dev
      httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
      maxAge: 1000 * 60 * 60 * 24, // 24 hours in milliseconds
    },
  })
);

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
});

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.stack);
    return;
  }
  console.log("Connected to MySQL database");
});

// Root route to test the server
app.get("/", (req, res) => {
  res.send("Backend server is running");
});

// lgoin route
app.post("/login", (req, res) => {
  const { name, surname, password, role_id, city_id } = req.body;

  const query =
    "SELECT id, name, surname, password, role_id, city_id, age, category FROM front_users WHERE name = ? AND surname = ? AND role_id = ? AND city_id = ?";

  db.query(query, [name, surname, role_id, city_id], async (err, results) => {
    if (err) return res.status(500).send("Database error");

    if (results.length === 0) {
      return res.status(401).send("User not found");
    }

    const user = results[0];

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send("Incorrect password");
    }

    // Set session after successful login, including age and category
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
  });
});

// Check if user is authenticated
app.get("/check-auth", (req, res) => {
  if (req.session.user) {
    res.status(200).json(req.session.user);
  } else {
    res.status(401).send("Not authenticated");
  }
});

// Logout route
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Failed to log out");
    }
    res.clearCookie("connect.sid"); // Clear the session cookie
    res.status(200).send("Logged out");
  });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
