const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "127.0.0.1";
const ROOT = __dirname;
const DB_FILE = path.join(ROOT, "scores.json");
const sessions = new Map();

function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    return { users: [] };
  }

  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch (error) {
    return { users: [] };
  }
}

function saveDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function hashPassword(password, salt = crypto.randomBytes(12).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  return hashPassword(password, salt) === `${salt}:${hash}`;
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body)
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) {
        reject(new Error("请求内容过大"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(new Error("JSON 格式不正确"));
      }
    });
  });
}

function getUserFromRequest(req) {
  const authorization = req.headers.authorization || "";
  const token = authorization.replace(/^Bearer\s+/i, "");
  const username = sessions.get(token);
  if (!username) return null;

  const db = loadDb();
  return db.users.find((user) => user.username === username) || null;
}

function publicUser(user) {
  return {
    username: user.username,
    bestScore: user.bestScore || 0
  };
}

async function handleApi(req, res) {
  if (req.method === "POST" && req.url === "/api/login") {
    try {
      const { username, password } = await readBody(req);
      const cleanName = String(username || "").trim();
      const cleanPassword = String(password || "");

      if (!/^[\w\u4e00-\u9fa5]{2,16}$/.test(cleanName)) {
        return sendJson(res, 400, { message: "用户名需为 2-16 位中文、英文、数字或下划线" });
      }

      if (cleanPassword.length < 4) {
        return sendJson(res, 400, { message: "密码至少 4 位" });
      }

      const db = loadDb();
      let user = db.users.find((item) => item.username === cleanName);

      if (!user) {
        user = {
          username: cleanName,
          passwordHash: hashPassword(cleanPassword),
          bestScore: 0,
          gameData: null,
          createdAt: new Date().toISOString()
        };
        db.users.push(user);
        saveDb(db);
      } else if (!verifyPassword(cleanPassword, user.passwordHash)) {
        return sendJson(res, 401, { message: "密码错误" });
      }

      const token = crypto.randomUUID();
      sessions.set(token, user.username);
      return sendJson(res, 200, { token, user: publicUser(user) });
    } catch (error) {
      return sendJson(res, 400, { message: error.message });
    }
  }

  if (req.method === "GET" && req.url === "/api/me") {
    const user = getUserFromRequest(req);
    if (!user) {
      return sendJson(res, 401, { message: "请先登录" });
    }
    return sendJson(res, 200, { user: publicUser(user) });
  }

  if (req.method === "POST" && req.url === "/api/score") {
    const currentUser = getUserFromRequest(req);
    if (!currentUser) {
      return sendJson(res, 401, { message: "请先登录" });
    }

    try {
      const { score } = await readBody(req);
      const numericScore = Math.max(0, Math.floor(Number(score) || 0));
      const db = loadDb();
      const user = db.users.find((item) => item.username === currentUser.username);
      user.bestScore = Math.max(user.bestScore || 0, numericScore);
      user.lastScore = numericScore;
      user.updatedAt = new Date().toISOString();
      saveDb(db);
      return sendJson(res, 200, { bestScore: user.bestScore });
    } catch (error) {
      return sendJson(res, 400, { message: error.message });
    }
  }

  if (req.method === "POST" && req.url === "/api/game/save") {
    const currentUser = getUserFromRequest(req);
    if (!currentUser) {
      return sendJson(res, 401, { message: "请先登录" });
    }

    try {
      const gameData = await readBody(req);
      const db = loadDb();
      const user = db.users.find((item) => item.username === currentUser.username);
      user.gameData = gameData;
      user.lastGameTime = new Date().toISOString();
      user.bestScore = Math.max(user.bestScore || 0, gameData.gpa || 0);
      saveDb(db);
      return sendJson(res, 200, { message: "游戏已保存" });
    } catch (error) {
      return sendJson(res, 400, { message: error.message });
    }
  }

  if (req.method === "GET" && req.url === "/api/game/load") {
    const currentUser = getUserFromRequest(req);
    if (!currentUser) {
      return sendJson(res, 401, { message: "请先登录" });
    }

    try {
      const db = loadDb();
      const user = db.users.find((item) => item.username === currentUser.username);
      return sendJson(res, 200, { gameData: user.gameData || null });
    } catch (error) {
      return sendJson(res, 400, { message: error.message });
    }
  }

  sendJson(res, 404, { message: "接口不存在" });
}

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(req.url.split("?")[0]);
  const safePath = urlPath === "/" ? "/大战期末周.html" : urlPath;
  const filePath = path.normalize(path.join(ROOT, safePath));

  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    return res.end("Forbidden");
  }

  fs.readFile(filePath, (error, content) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("页面不存在");
    }

    const ext = path.extname(filePath);
    const types = {
      ".html": "text/html; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".js": "application/javascript; charset=utf-8",
      ".json": "application/json; charset=utf-8"
    };
    res.writeHead(200, { "Content-Type": types[ext] || "application/octet-stream" });
    res.end(content);
  });
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/api/")) {
    handleApi(req, res);
    return;
  }

  serveStatic(req, res);
});

server.listen(PORT, HOST, () => {
  console.log(`ChatGPT大战期末周已启动：http://${HOST}:${PORT}`);
});
