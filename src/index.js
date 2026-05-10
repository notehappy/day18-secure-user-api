require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const https = require("https");
const fs = require("fs");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

app.use(helmet());
app.use(cors());
app.use(express.json());

function generateAccessToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }

    req.user = user;
    next();
  });
}

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: "Access denied: insufficient permission",
      });
    }

    next();
  };
}

async function csrfProtection(req, res, next) {
  try {
    const csrfToken = req.headers["x-csrf-token"];

    if (!csrfToken) {
      return res.status(403).json({ message: "CSRF token required" });
    }

    const result = await pool.query(
      "SELECT token FROM csrf_tokens WHERE user_id = $1",
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ message: "CSRF token not found" });
    }

    const savedToken = result.rows[0].token;

    if (csrfToken !== savedToken) {
      return res.status(403).json({ message: "Invalid CSRF token" });
    }

    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "CSRF validation error" });
  }
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(50) DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS csrf_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      token TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  const existingAdmin = await pool.query(
    "SELECT id FROM users WHERE email = $1",
    [adminEmail]
  );

  if (existingAdmin.rows.length === 0) {
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    await pool.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4)",
      ["Admin", adminEmail, hashedPassword, "admin"]
    );

    console.log("Default admin created");
  }
}

app.get("/", (req, res) => {
  res.json({
    message: "Secure User API is running with HTTPS",
    endpoints: {
      register: "POST /auth/register",
      login: "POST /auth/login",
      getUsers: "GET /users",
      getUserById: "GET /users/:id",
      createUser: "POST /users",
      updateUser: "PUT /users/:id",
      deleteUser: "DELETE /users/:id",
    },
  });
});

// Register normal user
app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Name, email, and password are required",
      });
    }

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, created_at",
      [name, email, hashedPassword, "user"]
    );

    res.status(201).json({
      message: "User registered successfully",
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Login and get JWT + CSRF token
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = result.rows[0];

    const isPasswordValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const accessToken = generateAccessToken(user);
    const csrfToken = crypto.randomBytes(32).toString("hex");

    await pool.query(
      `
      INSERT INTO csrf_tokens (user_id, token)
      VALUES ($1, $2)
      ON CONFLICT (user_id)
      DO UPDATE SET token = EXCLUDED.token, created_at = CURRENT_TIMESTAMP
      `,
      [user.id, csrfToken]
    );

    res.json({
      message: "Login successful",
      accessToken,
      csrfToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// GET /users - admin only
app.get(
  "/users",
  authenticateToken,
  authorizeRoles("admin"),
  async (req, res) => {
    try {
      const result = await pool.query(
        "SELECT id, name, email, role, created_at FROM users ORDER BY id ASC"
      );

      res.json(result.rows);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// GET /users/:id - admin or own account
app.get("/users/:id", authenticateToken, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (req.user.role !== "admin" && req.user.userId !== id) {
      return res.status(403).json({ message: "Access denied" });
    }

    const result = await pool.query(
      "SELECT id, name, email, role, created_at FROM users WHERE id = $1",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// POST /users - admin only, CSRF protected
app.post(
  "/users",
  authenticateToken,
  authorizeRoles("admin"),
  csrfProtection,
  async (req, res) => {
    try {
      const { name, email, password, role } = req.body;

      if (!name || !email || !password) {
        return res.status(400).json({
          message: "Name, email, and password are required",
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const result = await pool.query(
        "INSERT INTO users (name, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, created_at",
        [name, email, hashedPassword, role || "user"]
      );

      res.status(201).json({
        message: "User created successfully",
        user: result.rows[0],
      });
    } catch (error) {
      console.error(error);

      if (error.code === "23505") {
        return res.status(400).json({ message: "Email already exists" });
      }

      res.status(500).json({ message: "Server error" });
    }
  }
);

// PUT /users/:id - admin or own account, CSRF protected
app.put("/users/:id", authenticateToken, csrfProtection, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (req.user.role !== "admin" && req.user.userId !== id) {
      return res.status(403).json({ message: "Access denied" });
    }

    const existingUser = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [id]
    );

    if (existingUser.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const currentUser = existingUser.rows[0];

    const { name, email, password, role } = req.body;

    const newName = name || currentUser.name;
    const newEmail = email || currentUser.email;
    const newRole =
      req.user.role === "admin" ? role || currentUser.role : currentUser.role;

    let newPasswordHash = currentUser.password_hash;

    if (password) {
      newPasswordHash = await bcrypt.hash(password, 10);
    }

    const result = await pool.query(
      `
      UPDATE users
      SET name = $1, email = $2, password_hash = $3, role = $4
      WHERE id = $5
      RETURNING id, name, email, role, created_at
      `,
      [newName, newEmail, newPasswordHash, newRole, id]
    );

    res.json({
      message: "User updated successfully",
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);

    if (error.code === "23505") {
      return res.status(400).json({ message: "Email already exists" });
    }

    res.status(500).json({ message: "Server error" });
  }
});

// DELETE /users/:id - admin only, CSRF protected
app.delete(
  "/users/:id",
  authenticateToken,
  authorizeRoles("admin"),
  csrfProtection,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const result = await pool.query(
        "DELETE FROM users WHERE id = $1 RETURNING id, name, email, role",
        [id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({
        message: "User deleted successfully",
        user: result.rows[0],
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server error" });
    }
  }
);

initDatabase()
  .then(() => {
    const sslOptions = {
      key: fs.readFileSync("./certs/key.pem"),
      cert: fs.readFileSync("./certs/cert.pem"),
    };

    https.createServer(sslOptions, app).listen(PORT, () => {
      console.log(`HTTPS server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });