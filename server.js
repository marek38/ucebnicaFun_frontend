const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cors = require("cors");
require("dotenv").config();

const app = express();

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost", // Replace with your host
  user: process.env.DB_USER || "root", // Replace with your database user
  password: process.env.DB_PASSWORD || "", // Replace with your database password
  database: process.env.DB_NAME || "your_database", // Replace with your database name
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Session middleware configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true if using HTTPS
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
    },
  })
);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configuration
app.use(
  cors({
    origin: ["https://ucebnicafun.emax-controls.eu"], // Replace with your frontend URL
    credentials: true,
  })
);

// Test route
app.get("/", (req, res) => {
  res.send("Backend server is running");
});

// Login route
app.post("/login", async (req, res) => {
  const { name, surname, password, role_id, city_id } = req.body;

  if (!name || !surname || !password || !role_id || !city_id) {
    return res.status(400).json({ message: "Please fill in all fields" });
  }

  try {
    const query = `
      SELECT id, name, surname, password, role_id, city_id, age, category
      FROM front_users
      WHERE name = ? AND surname = ? AND role_id = ? AND city_id = ?
    `;

    const [results] = await pool.execute(query, [
      name,
      surname,
      role_id,
      city_id,
    ]);

    if (results.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = results[0];

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Set session
    req.session.user = {
      id: user.id,
      name: user.name,
      surname: user.surname,
      role_id: user.role_id,
      city_id: user.city_id,
      age: user.age,
      category: user.category,
    };

    res.status(200).json({ message: "Login successful" });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Check authentication status
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
      console.error("Error destroying session:", err);
      return res.status(500).json({ message: "Logout failed" });
    }
    res.clearCookie("connect.sid"); // Default cookie name
    res.status(200).json({ message: "Logout successful" });
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
