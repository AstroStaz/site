import express from "express";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import path from "path";
import { fileURLToPath } from "url";

const PORT = 3000;
const JWT_SECRET = "change_this_secret_key";
const REWARD_USD = 0.01;
const MIN_PAYOUT = 5.0;

// ==== INIT APP ====
const app = express();
app.use(bodyParser.json());

// ==== SERVE FRONTEND (index.html & static assets) ====
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname + "/public")); 
// Put index.html in a folder called "public"

// ==== DATABASE ====
let db;
async function initDB() {
  db = await open({
    filename: "./watch2earn.sqlite",
    driver: sqlite3.Database,
  });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      balance REAL DEFAULT 0
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS rewards (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS payouts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      status TEXT DEFAULT 'pending',
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);
}

// ==== HELPERS ====
function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: "2h",
  });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Missing token" });
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ==== ROUTES ====

// Signup
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Missing fields" });

  const hash = await bcrypt.hash(password, 10);
  try {
    const result = await db.run(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, hash]
    );
    const user = { id: result.lastID, username, balance: 0 };
    res.json({ token: generateToken(user) });
  } catch {
    res.status(400).json({ error: "Username already exists" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE username=?", [username]);
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(400).json({ error: "Invalid credentials" });

  res.json({ token: generateToken(user) });
});

// Get balance
app.get("/balance", authMiddleware, async (req, res) => {
  const user = await db.get("SELECT balance FROM users WHERE id=?", [
    req.user.id,
  ]);
  res.json({ balance: user.balance });
});

// Add reward
app.post("/reward", authMiddleware, async (req, res) => {
  const { tx } = req.body;
  if (!tx) return res.status(400).json({ error: "Missing tx id" });

  await db.run("UPDATE users SET balance = balance + ? WHERE id=?", [
    REWARD_USD,
    req.user.id,
  ]);
  await db.run("INSERT INTO rewards (user_id, amount) VALUES (?, ?)", [
    req.user.id,
    REWARD_USD,
  ]);

  res.json({ success: true, reward: REWARD_USD });
});

// Request payout
app.post("/payout", authMiddleware, async (req, res) => {
  const user = await db.get("SELECT balance FROM users WHERE id=?", [
    req.user.id,
  ]);
  if (user.balance < MIN_PAYOUT)
    return res.status(400).json({ error: "Not enough balance for payout" });

  await db.run("UPDATE users SET balance = balance - ? WHERE id=?", [
    user.balance,
    req.user.id,
  ]);
  await db.run("INSERT INTO payouts (user_id, amount) VALUES (?, ?)", [
    req.user.id,
    user.balance,
  ]);

  res.json({ success: true, amount: user.balance });
});

// ==== START ====
initDB().then(() => {
  app.listen(PORT, () =>
    console.log(`✅ Backend + frontend running at http://localhost:${PORT}`)
  );
});