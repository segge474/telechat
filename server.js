const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new Database("telechat.db");

app.use(express.json({ limit: "20kb" }));
app.use(express.static(__dirname));

// Создаём таблицы
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const findUser = db.prepare(
  "SELECT id, username, password FROM users WHERE username = ?"
);
const createUser = db.prepare(
  "INSERT INTO users (username, password) VALUES (?, ?)"
);
const createSession = db.prepare(
  "INSERT INTO sessions (token, user_id) VALUES (?, ?)"
);
const findSession = db.prepare(`
  SELECT users.id, users.username
  FROM sessions
  JOIN users ON users.id = sessions.user_id
  WHERE sessions.token = ?
`);
const getMessages = db.prepare(`
  SELECT id, username, text, created_at AS createdAt
  FROM messages ORDER BY id DESC LIMIT 100
`);
const saveMessage = db.prepare(
  "INSERT INTO messages (user_id, username, text) VALUES (?, ?, ?)"
);

function getAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  const user = token ? findSession.get(token) : null;

  if (!user) {
    return res.status(401).json({ error: "Войди в аккаунт" });
  }

  req.user = user;
  req.token = token;
  next();
}

// Регистрация
app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "Имя: 3–20 символов, латинские буквы, цифры или _"
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Пароль должен содержать от 8 до 72 символов"
      });
    }

    if (findUser.get(username)) {
      return res.status(409).json({
        error: "Это имя уже занято"
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = createUser.run(username, hash);
    const token = crypto.randomBytes(32).toString("hex");

    createSession.run(token, result.lastInsertRowid);

    res.json({
      token,
      user: { id: result.lastInsertRowid, username }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Не удалось создать аккаунт" });
  }
});

// Вход
app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const user = findUser.get(username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        error: "Неверное имя пользователя или пароль"
      });
    }

    const token = crypto.randomBytes(32).toString("hex");
    createSession.run(token, user.id);

    res.json({
      token,
      user: { id: user.id, username: user.username }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Ошибка входа" });
  }
});

// Информация о текущем пользователе
app.get("/api/me", getAuth, (req, res) => {
  res.json({ user: req.user });
});

// История сообщений
app.get("/api/messages", getAuth, (req, res) => {
  const messages = getMessages.all().reverse();
  res.json({ messages });
});

// Выход
app.post("/api/logout", getAuth, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(req.token);
  res.json({ ok: true });
});

// Проверка токена для Socket.IO
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  const user = token ? findSession.get(token) : null;

  if (!user) return next(new Error("Нужно войти в аккаунт"));

  socket.user = user;
  next();
});

// Обмен сообщениями в реальном времени
io.on("connection", (socket) => {
  socket.on("chat:send", (value, callback) => {
    const text = typeof value === "string" ? value.trim() : "";

    if (!text || text.length > 2000) {
      if (typeof callback === "function") {
        callback({ error: "Сообщение должно содержать 1–2000 символов" });
      }
      return;
    }

    const result = saveMessage.run(
      socket.user.id,
      socket.user.username,
      text
    );

    const message = {
      id: result.lastInsertRowid,
      username: socket.user.username,
      text,
      createdAt: new Date().toISOString()
    };

    io.emit("chat:new", message);

    if (typeof callback === "function") {
      callback({ ok: true });
    }
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`TeleChat запущен: http://localhost:${PORT}`);
});