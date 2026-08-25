require("dotenv").config();

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const { initializeApp, cert } = require("firebase-admin/app");
const { getMessaging } = require("firebase-admin/messaging");
const Sentry = require("@sentry/node");

if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    tracesSampleRate: 1.0,
  });
}

const app = express();

// Render (ve benzeri) tek katmanli reverse proxy arkasinda calisirken,
// express-rate-limit'in gercek istemci IP'sini (X-Forwarded-For) dogru
// okuyabilmesi icin gerekli. Olmadan herkes ayni IP'den geliyormus gibi
// davranilir / rate-limit hata verebilir.
app.set("trust proxy", 1);

// ── CORS: production domain'leri (CORS_ORIGIN env değişkeninden, virgülle ayrılmış)
// + geliştirme sırasında HER localhost portuna otomatik izin verir ─────────
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((origin) => origin.trim())
  : [];

app.use(cors({
  origin: function (origin, callback) {
    // origin yoksa (mobil uygulama, Postman, curl gibi) izin ver
    if (!origin) return callback(null, true);
    // production listesinde varsa izin ver
    if (allowedOrigins.includes(origin)) return callback(null, true);
    // herhangi bir localhost portu ise izin ver (flutter run -d chrome her seferinde port değiştiriyor)
    if (/^http:\/\/localhost(:\d+)?$/.test(origin)) return callback(null, true);
    if (/^http:\/\/127\.0\.0\.1(:\d+)?$/.test(origin)) return callback(null, true);
    return callback(new Error("CORS engellendi: " + origin));
  },
  credentials: true,
}));

app.use(express.json({ limit: "10mb" }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla istek gönderildi, lütfen daha sonra tekrar deneyin" },
});
app.use(apiLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla deneme yapıldı, lütfen daha sonra tekrar deneyin" },
});

// /routes/optimize her çağrıda ücretli Google Distance Matrix isteği atıyor
// (durak sayısının karesi kadar element) — genel apiLimiter'dan çok daha
// sıkı bir limit koyup maliyet-DoS riskini azaltıyoruz.
const optimizeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Rota optimizasyonu için çok fazla istek gönderildi, lütfen daha sonra tekrar deneyin" },
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || "{}");
let messaging = null;
if (serviceAccount.project_id) {
  const firebaseApp = initializeApp({
    credential: cert(serviceAccount),
  });
  messaging = getMessaging(firebaseApp);
}

async function initDB() {
  try {
    await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email VARCHAR(255),
        reset_code VARCHAR(10),
        reset_code_expires TIMESTAMP,
        vehicle_id INTEGER,
        created_at TIMESTAMP DEFAULT NOW()
      );
      ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_code VARCHAR(10);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_code_expires TIMESTAMP;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS vehicle_id INTEGER;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS fcm_token TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
      CREATE TABLE IF NOT EXISTS routes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id INTEGER REFERENCES users(id),
        vehicle_id INTEGER,
        name VARCHAR(200),
        route_json JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
      ALTER TABLE routes ADD COLUMN IF NOT EXISTS vehicle_id INTEGER;
      CREATE TABLE IF NOT EXISTS driver_locations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        latitude DOUBLE PRECISION,
        longitude DOUBLE PRECISION,
        recorded_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS fleet_workspace (
        singleton_id INTEGER PRIMARY KEY DEFAULT 1,
        vehicles JSONB,
        updated_at TIMESTAMP DEFAULT NOW()
      );
      -- "Araç" soyutlaması kaldırıldı (mobil zaten her zaman sürücünün
      -- kendi hesabı üzerinden çalışıyordu, ayrı bir slot/atama katmanı
      -- gereksizdi) — web panelindeki her sürücünün çalışma alanı artık
      -- doğrudan kendi user_id'siyle burada tutulur. Eski fleet_workspace
      -- tablosu geriye dönük uyumluluk için siliniyor değil, sadece
      -- kullanılmıyor.
      CREATE TABLE IF NOT EXISTS driver_workspace (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        workspace JSONB,
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log("Veritabanı tabloları hazır");
  } catch (err) {
    console.error("DB init hatası:", err.message);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
  }
}

initDB();

function parseRouteJson(value) {
  if (!value) return {};
  if (typeof value === "string") {
    try { return JSON.parse(value); } catch (_) { return {}; }
  }
  return value;
}

function normalizeRoute(row) {
  const routeJson = parseRouteJson(row.route_json);
  return {
    id: row.id,
    user_id: row.user_id,
    name: row.name,
    created_at: row.created_at,
    updated_at: routeJson.updatedAt || routeJson.updated_at || row.created_at,
    status: routeJson.status || "active",
    route_json: routeJson,
  };
}

// ── JWT Doğrulama Middleware ───────────────────────────────────────────
// İmza + süre doğrulamasının ardından, token'daki token_version'ı DB'deki
// güncel değerle karşılaştırır. Bu sayede admin bir kullanıcının şifresini
// sıfırladığında (bkz. admin-reset-password) o kullanıcının önceden alınmış
// tüm token'ları anında geçersiz olur — aksi halde JWT süresi (30 gün)
// dolana kadar çalınmış/eski bir token geçerli kalırdı.
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Giriş yapmanız gerekiyor", code: "SESSION_EXPIRED" });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Oturum geçersiz veya süresi dolmuş", code: "SESSION_EXPIRED" });
    }
    try {
      const result = await pool.query(
        "SELECT token_version FROM users WHERE id = $1",
        [decoded.user_id]
      );
      if (result.rows.length === 0 || result.rows[0].token_version !== decoded.token_version) {
        return res.status(403).json({ error: "Oturum geçersiz veya süresi dolmuş", code: "SESSION_EXPIRED" });
      }
      req.user = decoded;
      next();
    } catch (dbErr) {
      console.error("Token doğrulama hatası:", dbErr);
      if (process.env.SENTRY_DSN) Sentry.captureException(dbErr);
      res.status(500).json({ error: "Sunucu hatası" });
    }
  });
}

// ── Rol Kontrolü Middleware — authenticateToken'dan SONRA kullanılmalı ──
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: "Bu işlem için yetkiniz yok" });
    }
    next();
  };
}

const STAFF_ROLES = ["admin"];

// Sahiplik kontrolü: admin her zaman erişebilir, driver sadece
// kendi user_id'sine ait kaynağa. authenticateToken'dan sonra kullanılmalı.
function canAccessUser(req, targetUserId) {
  if (!req.user) return false;
  if (STAFF_ROLES.includes(req.user.role)) return true;
  return String(req.user.user_id) === String(targetUserId);
}

// Bir rotaya erişim: rotanın sahibiyim (canAccessUser). Eskiden ayrıca
// "araç" üzerinden dolaylı bir erişim yolu da vardı (canAccessVehicle) —
// araç soyutlaması kaldırıldığı için artık tek kaynak user_id.
async function canAccessRoute(req, route) {
  return canAccessUser(req, route.user_id);
}

function forbidden(res) {
  return res.status(403).json({ error: "Bu veriye erişim yetkiniz yok" });
}

app.get("/", (req, res) => {
  res.json({ message: "Rota360 backend çalışıyor", version: "1.5.0" });
});

// Yalnizca giris yapmis admin yeni kullanici olusturabilir —
// role bilgisi disaridan serbestce belirlenemesin diye.
app.post("/register", authLimiter, authenticateToken, requireRole("admin"), async (req, res) => {
  const { username, password, role, email } = req.body;
  try {
    await pool.query(
      "INSERT INTO users (username, password_hash, role, email) VALUES ($1, crypt($2, gen_salt('bf')), $3, $4)",
      [username, password, role || "driver", email || null]
    );
    res.json({ message: "Kullanıcı oluşturuldu" });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Sürücü listesi kurum personeline (web panelindeki sürücü sekmeleri) ait
// — sürücülerin birbirini görebilmesine gerek yok. Eskiden burada ayrıca
// vehicle_id (araç ataması) de dönüyordu; araç soyutlaması kaldırıldığı
// için artık sadece kimlik bilgisi dönüyor.
app.get("/users/drivers", authenticateToken, requireRole("admin"), async (req, res) => {
  try {
    // Düz "ORDER BY username" sözlüksel sıralar: sürücü10, sürücü2'den önce
    // gelirdi ("1" < "2"). Önce uzunluğa göre sıralamak sürücü1..sürücü9'u
    // (8 karakter) sürücü10'dan (9 karakter) önce getiriyor — bu isimlendirme
    // düzeninde doğal sayısal sırayla aynı sonucu veriyor.
    const result = await pool.query(
      "SELECT id, username FROM users WHERE role = 'driver' OR role IS NULL ORDER BY length(username), username"
    );
    res.json(result.rows);
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Mobil admin ekranı için: her sürücünün bugünkü en son rotasının özeti
// (toplam/tamamlanan durak, mesafe, süre). Tek seferde tüm filoyu göstermek
// için — sürücü sayısı kadar ayrı /routes/:id/active çağrısı yapmak yerine.
app.get("/routes/today/summary", authenticateToken, requireRole("admin"), async (req, res) => {
  try {
    const driversResult = await pool.query(
      "SELECT id, username FROM users WHERE role = 'driver' OR role IS NULL ORDER BY length(username), username"
    );
    const todayStr = new Date().toISOString().slice(0, 10);
    const summaries = [];
    for (const driver of driversResult.rows) {
      const routeResult = await pool.query(
        "SELECT route_json, created_at FROM routes WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
        [driver.id]
      );
      if (routeResult.rows.length === 0) {
        summaries.push({
          userId: driver.id,
          username: driver.username,
          hasRouteToday: false,
          totalStops: 0,
          completedStops: 0,
          totalKm: 0,
          totalMin: 0,
        });
        continue;
      }
      const row = routeResult.rows[0];
      const routeJson = parseRouteJson(row.route_json);
      const isToday = new Date(row.created_at).toISOString().slice(0, 10) === todayStr;
      const stops = Array.isArray(routeJson.stops)
        ? routeJson.stops
        : Array.isArray(routeJson.addresses)
          ? routeJson.addresses
          : [];
      summaries.push({
        userId: driver.id,
        username: driver.username,
        hasRouteToday: isToday && stops.length > 0,
        totalStops: stops.length,
        completedStops: stops.filter((s) => s.completed).length,
        totalKm: routeJson.totalKm ?? 0,
        totalMin: routeJson.totalMin ?? 0,
      });
    }
    res.json(summaries);
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Yönetici (admin), giriş yapmış personelin şifresini sıfırlar.
// E-posta gerektirmez — sadece giriş yapmış (token'lı) biri çağırabilir.
app.post("/users/:user_id/admin-reset-password", authenticateToken, requireRole("admin"), async (req, res) => {
  const { user_id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "Yeni şifre en az 6 karakter olmalı" });
  }
  try {
    const result = await pool.query(
      // token_version'ı da artırıyoruz ki şifre sıfırlandığında bu
      // kullanıcının önceden alınmış tüm oturumları anında düşsün.
      "UPDATE users SET password_hash = crypt($1, gen_salt('bf')), token_version = token_version + 1 WHERE id = $2 RETURNING username",
      [newPassword, user_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Kullanıcı bulunamadı" });
    }
    res.json({ message: `${result.rows[0].username} kullanıcısının şifresi sıfırlandı` });
  } catch (err) {
    console.error(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Şifre sıfırlanamadı" });
  }
});

app.post("/users/:user_id/fcm-token", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  if (!canAccessUser(req, user_id)) return forbidden(res);
  const { fcm_token } = req.body;
  try {
    await pool.query("UPDATE users SET fcm_token = $1 WHERE id = $2", [
      fcm_token,
      user_id,
    ]);
    res.json({ message: "Bildirim token'ı kaydedildi" });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.post("/routes", authenticateToken, async (req, res) => {
  const { user_id, name, route_json } = req.body;
  if (!user_id || !route_json) {
    return res.status(400).json({ error: "user_id ve route_json zorunlu" });
  }
  // Bir sürücü sadece kendi adına rota oluşturabilir; başkası adına rota
  // (ve o kişiye giden push bildirimi) sadece admin atayabilir.
  if (!canAccessUser(req, user_id)) return forbidden(res);
  const now = new Date().toISOString();
  const parsedRouteJson = parseRouteJson(route_json);
  const normalizedRouteJson = {
    ...parsedRouteJson,
    status: parsedRouteJson.status || "active",
    createdAt: parsedRouteJson.createdAt || now,
    updatedAt: now,
  };
  try {
    const result = await pool.query(
      "INSERT INTO routes (id, user_id, name, route_json) VALUES (gen_random_uuid(), $1, $2, $3) RETURNING *",
      [user_id, name || "Rota360 Rota", normalizedRouteJson]
    );

    if (messaging) {
      try {
        const driverResult = await pool.query(
          "SELECT fcm_token FROM users WHERE id = $1 AND fcm_token IS NOT NULL",
          [user_id]
        );
        for (const row of driverResult.rows) {
          await messaging.send({
            token: row.fcm_token,
            notification: {
              title: "Yeni Rota Atandı",
              body: "Sizin için yeni bir rota oluşturuldu.",
            },
          });
        }
      } catch (notifErr) {
        console.log("Bildirim gönderilemedi:", notifErr.message);
        if (process.env.SENTRY_DSN) Sentry.captureException(notifErr);
      }
    }

    res.status(201).json({ message: "Rota kaydedildi", route: normalizeRoute(result.rows[0]) });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.get("/routes/:user_id", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  if (!canAccessUser(req, user_id)) return forbidden(res);
  try {
    const result = await pool.query(
      "SELECT * FROM routes WHERE user_id = $1 ORDER BY created_at DESC",
      [user_id]
    );
    res.json(result.rows.map(normalizeRoute));
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.get("/routes/:user_id/active", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  if (!canAccessUser(req, user_id)) return forbidden(res);
  try {
    const result = await pool.query(
      "SELECT * FROM routes WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
      [user_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Aktif rota bulunamadı" });
    }
    res.json(normalizeRoute(result.rows[0]));
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Bir sürücüye atanmış TÜM rotaları siler — sürücü hesabına (users tablosu)
// dokunmaz. Sadece admin çağırabilir; onay adımı web panelinde alınır.
app.delete("/routes/:user_id", authenticateToken, requireRole("admin"), async (req, res) => {
  const { user_id } = req.params;
  try {
    const result = await pool.query("DELETE FROM routes WHERE user_id = $1", [user_id]);
    res.json({ message: "Rotalar silindi", count: result.rowCount });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Bir sürücü hesabını tamamen siler (users satırı + ona ait rotalar,
// konum geçmişi ve çalışma alanı). Admin hesabı bu uçtan silinemez.
// Not: hedef "sürücü1".."sürücü10" ise, backend bir sonraki başlangıçta
// (Render deploy/restart) setupDrivers() sabit 10 hesabı yeniden
// oluşturur — bu isimlerden biri silinirse restart sonrası geri gelir.
app.delete("/users/:user_id", authenticateToken, requireRole("admin"), async (req, res) => {
  const { user_id } = req.params;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const userResult = await client.query(
      "SELECT id, username, role FROM users WHERE id = $1",
      [user_id]
    );
    if (userResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Sürücü bulunamadı" });
    }
    const target = userResult.rows[0];
    if (target.role === "admin") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Admin hesabı silinemez" });
    }
    await client.query("DELETE FROM routes WHERE user_id = $1", [user_id]);
    await client.query("DELETE FROM driver_workspace WHERE user_id = $1", [user_id]);
    await client.query("DELETE FROM driver_locations WHERE user_id = $1", [user_id]);
    await client.query("DELETE FROM users WHERE id = $1", [user_id]);
    await client.query("COMMIT");
    res.json({ message: "Sürücü silindi", username: target.username });
  } catch (err) {
    await client.query("ROLLBACK");
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  } finally {
    client.release();
  }
});

// Web panelinin bir sürücü için hazırladığı çalışma alanını (adres
// kuyruğu, sabit ev adresi, takvim planı) kaydeder/getirir. Eskiden bu
// "araç" bazlı tek bir singleton satırdaydı (fleet_workspace); artık her
// sürücünün kendi user_id'siyle ayrı bir satırı var (driver_workspace).
app.post("/fleet/:user_id", authenticateToken, requireRole("admin"), async (req, res) => {
  const { user_id } = req.params;
  const { workspace } = req.body;
  try {
    await pool.query(
      `INSERT INTO driver_workspace (user_id, workspace, updated_at)
       VALUES ($1, $2, NOW())
       ON CONFLICT (user_id)
       DO UPDATE SET workspace = $2, updated_at = NOW()`,
      [user_id, workspace]
    );
    res.json({ message: "Çalışma alanı kaydedildi" });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Çalışma alanı kaydedilemedi" });
  }
});

app.get("/fleet/:user_id", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  // Artık her sürücünün kendi gerçek çalışma verisi (adres/plan) burada
  // tutulduğu için (eskiki paylaşımlı "filo" bloğunun aksine) sahiplik
  // kontrolü şart — aksi halde bir sürücü başka bir sürücünün verisini
  // okuyabilirdi.
  if (!canAccessUser(req, user_id)) return forbidden(res);
  try {
    const result = await pool.query(
      "SELECT workspace, updated_at FROM driver_workspace WHERE user_id = $1",
      [user_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Çalışma alanı bulunamadı" });
    }
    res.json({
      workspace: result.rows[0].workspace,
      updatedAt: result.rows[0].updated_at,
    });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Çalışma alanı alınamadı" });
  }
});

app.patch("/routes/:route_id/stops/:stop_id/complete", authenticateToken, async (req, res) => {
  const { route_id, stop_id } = req.params;
  const { completed = true } = req.body;
  try {
    const result = await pool.query("SELECT * FROM routes WHERE id = $1", [route_id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Rota bulunamadı" });
    }
    const route = result.rows[0];
    if (!(await canAccessRoute(req, route))) return forbidden(res);
    const routeJson = parseRouteJson(route.route_json);
    const stops = Array.isArray(routeJson.stops)
      ? routeJson.stops
      : Array.isArray(routeJson.addresses)
        ? routeJson.addresses
        : [];
    let found = false;
    const updatedStops = stops.map((stop, index) => {
      const stopMatches =
        String(stop.id ?? "") === String(stop_id) ||
        String(stop.code ?? "") === String(stop_id) ||
        String(stop.order ?? "") === String(stop_id) ||
        String(index + 1) === String(stop_id);
      if (!stopMatches) return stop;
      found = true;
      return { ...stop, completed, completed_at: completed ? new Date().toISOString() : null };
    });
    if (!found) {
      return res.status(404).json({ error: "Durak bulunamadı" });
    }
    const updatedRouteJson = { ...routeJson, stops: updatedStops, updatedAt: new Date().toISOString() };
    const updateResult = await pool.query(
      "UPDATE routes SET route_json = $1 WHERE id = $2 RETURNING *",
      [updatedRouteJson, route_id]
    );
    res.json({ message: "Durak güncellendi", route: normalizeRoute(updateResult.rows[0]) });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.patch("/routes/:route_id/stops/:stop_id/note", authenticateToken, async (req, res) => {
  const { route_id, stop_id } = req.params;
  const { note } = req.body;
  if (typeof note !== "string") {
    return res.status(400).json({ error: "note (string) zorunlu" });
  }
  try {
    const result = await pool.query("SELECT * FROM routes WHERE id = $1", [route_id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Rota bulunamadı" });
    }
    const route = result.rows[0];
    if (!(await canAccessRoute(req, route))) return forbidden(res);
    const routeJson = parseRouteJson(route.route_json);
    const stops = Array.isArray(routeJson.stops)
      ? routeJson.stops
      : Array.isArray(routeJson.addresses)
        ? routeJson.addresses
        : [];
    let found = false;
    const updatedStops = stops.map((stop, index) => {
      const stopMatches =
        String(stop.id ?? "") === String(stop_id) ||
        String(stop.code ?? "") === String(stop_id) ||
        String(stop.order ?? "") === String(stop_id) ||
        String(index + 1) === String(stop_id);
      if (!stopMatches) return stop;
      found = true;
      return { ...stop, notes: note };
    });
    if (!found) {
      return res.status(404).json({ error: "Durak bulunamadı" });
    }
    const updatedRouteJson = { ...routeJson, stops: updatedStops, updatedAt: new Date().toISOString() };
    const updateResult = await pool.query(
      "UPDATE routes SET route_json = $1 WHERE id = $2 RETURNING *",
      [updatedRouteJson, route_id]
    );
    res.json({ message: "Not güncellendi", route: normalizeRoute(updateResult.rows[0]) });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Mobil sürücünün sürükleme ile değiştirdiği stop sırasını kalıcı kaydeder.
// Body: { stops: [ { id, order, ... } ] }  — sadece id ve order zorunlu,
// geri kalan alanlar mevcut değerleri koruyor.
app.patch("/routes/:route_id/stops", authenticateToken, async (req, res) => {
  const { route_id } = req.params;
  const { stops: newOrder } = req.body;
  if (!Array.isArray(newOrder) || newOrder.length === 0) {
    return res.status(400).json({ error: "stops dizisi gerekli" });
  }
  try {
    const result = await pool.query("SELECT * FROM routes WHERE id = $1", [route_id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Rota bulunamadı" });
    }
    const route = result.rows[0];
    if (!(await canAccessRoute(req, route))) return forbidden(res);

    const routeJson = parseRouteJson(route.route_json);
    const currentStops = Array.isArray(routeJson.stops)
      ? routeJson.stops
      : Array.isArray(routeJson.addresses)
        ? routeJson.addresses
        : [];

    // newOrder'daki id→order eşleşmesini uygula; bilinmeyen id'ler görmezden geliniyor.
    const orderMap = {};
    newOrder.forEach((s) => {
      if (s.id != null) orderMap[String(s.id)] = s.order;
    });

    const updatedStops = currentStops
      .map((stop) => {
        const key = String(stop.id ?? stop.code ?? "");
        return key && orderMap[key] != null
          ? { ...stop, order: orderMap[key] }
          : stop;
      })
      .sort((a, b) => (a.order ?? 0) - (b.order ?? 0));

    const updatedRouteJson = { ...routeJson, stops: updatedStops, updatedAt: new Date().toISOString() };
    const updateResult = await pool.query(
      "UPDATE routes SET route_json = $1 WHERE id = $2 RETURNING *",
      [updatedRouteJson, route_id]
    );
    res.json({ message: "Durak sırası güncellendi", route: normalizeRoute(updateResult.rows[0]) });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Mobil sürücünün harita üzerinden eklediği yeni durağı rotaya ekler.
// Body: { stop: { street, latitude, longitude, customerName?, customerType?, ... } }
app.post("/routes/:route_id/stops", authenticateToken, async (req, res) => {
  const { route_id } = req.params;
  const { stop } = req.body;
  if (!stop || typeof stop.latitude !== "number" || typeof stop.longitude !== "number") {
    return res.status(400).json({ error: "stop.latitude ve stop.longitude (number) zorunlu" });
  }
  try {
    const result = await pool.query("SELECT * FROM routes WHERE id = $1", [route_id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Rota bulunamadı" });
    }
    const route = result.rows[0];
    if (!(await canAccessRoute(req, route))) return forbidden(res);

    const routeJson = parseRouteJson(route.route_json);
    const currentStops = Array.isArray(routeJson.stops)
      ? routeJson.stops
      : Array.isArray(routeJson.addresses)
        ? routeJson.addresses
        : [];

    // Mevcut en büyük sayısal ID'nin üzerine yeni ID üret
    const maxId = currentStops.reduce((max, s) => {
      const n = parseInt(String(s.id ?? s.code ?? "0"), 10);
      return isNaN(n) ? max : Math.max(max, n);
    }, 0);

    const newStop = {
      id: maxId + 1,
      order: currentStops.length + 1,
      street: stop.street ?? "",
      district: stop.district ?? "",
      city: stop.city ?? "",
      postalCode: stop.postalCode ?? "",
      latitude: stop.latitude,
      longitude: stop.longitude,
      customerName: stop.customerName ?? `Yeni Durak ${currentStops.length + 1}`,
      customerType: stop.customerType ?? "Müşteri",
      completed: false,
      addedByDriver: true,
      addedAt: new Date().toISOString(),
    };

    const updatedRouteJson = {
      ...routeJson,
      stops: [...currentStops, newStop],
      updatedAt: new Date().toISOString(),
    };
    const updateResult = await pool.query(
      "UPDATE routes SET route_json = $1 WHERE id = $2 RETURNING *",
      [updatedRouteJson, route_id]
    );
    res.status(201).json({
      message: "Durak eklendi",
      stop: newStop,
      route: normalizeRoute(updateResult.rows[0]),
    });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.patch("/routes/:route_id/complete", authenticateToken, async (req, res) => {
  const { route_id } = req.params;
  try {
    const result = await pool.query("SELECT * FROM routes WHERE id = $1", [route_id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Rota bulunamadı" });
    }
    const route = result.rows[0];
    if (!(await canAccessRoute(req, route))) return forbidden(res);
    const routeJson = parseRouteJson(route.route_json);
    const updatedRouteJson = {
      ...routeJson,
      status: "completed",
      completedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    const updateResult = await pool.query(
      "UPDATE routes SET route_json = $1 WHERE id = $2 RETURNING *",
      [updatedRouteJson, route_id]
    );
    res.json({ message: "Rota tamamlandı", route: normalizeRoute(updateResult.rows[0]) });
  } catch (err) {
    console.log(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.post("/login", authLimiter, async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    // Kullanıcı adı ile şifre hatası aynı mesajı dönmeli — aksi halde
    // saldırgan hangi kullanıcı adlarının var olduğunu (username
    // enumeration) tespit edebilir.
    const invalidCredentials = () =>
      res.status(401).json({ error: "Kullanıcı adı veya şifre hatalı" });

    if (result.rows.length === 0) {
      return invalidCredentials();
    }
    const user = result.rows[0];
    const passwordCheck = await pool.query(
      "SELECT crypt($1, $2) = $2 AS match",
      [password, user.password_hash]
    );
    if (!passwordCheck.rows[0].match) {
      return invalidCredentials();
    }

    const token = jwt.sign(
      { user_id: user.id, username: user.username, role: user.role, token_version: user.token_version },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({
      message: "Giriş başarılı",
      user_id: user.id,
      username: user.username,
      role: user.role,
      token: token,
    });
  } catch (err) {
    console.error(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

app.post("/drivers/:user_id/location", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  if (!canAccessUser(req, user_id)) return forbidden(res);
  const { latitude, longitude } = req.body;
  try {
    await pool.query(
      "INSERT INTO driver_locations (user_id, latitude, longitude) VALUES ($1, $2, $3)",
      [user_id, latitude, longitude]
    );
    res.json({ message: "Konum güncellendi" });
  } catch (err) {
    console.error(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Konum güncellenemedi" });
  }
});

app.get("/drivers/:user_id/location", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  if (!canAccessUser(req, user_id)) return forbidden(res);
  try {
    const result = await pool.query(
      "SELECT * FROM driver_locations WHERE user_id = $1 ORDER BY recorded_at DESC LIMIT 1",
      [user_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Konum bulunamadı" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Konum alınamadı" });
  }
});

// ── Exact TSP (Held-Karp) — veri kaynağından bağımsız ─────────────────
function solveExactTsp(cost) {
  const n = cost.length;
  const m = n - 1;
  if (m <= 0) return { order: [], totalCost: 0 };
  if (m === 1) return { order: [1], totalCost: cost[0][1] + cost[1][0] };

  const FULL = 1 << m;
  const dp = Array.from({ length: FULL }, () => new Array(m).fill(Infinity));
  const parent = Array.from({ length: FULL }, () => new Array(m).fill(-1));

  for (let i = 0; i < m; i++) {
    dp[1 << i][i] = cost[0][i + 1];
  }

  for (let mask = 1; mask < FULL; mask++) {
    for (let i = 0; i < m; i++) {
      if (!(mask & (1 << i))) continue;
      const current = dp[mask][i];
      if (current === Infinity) continue;
      for (let j = 0; j < m; j++) {
        if (mask & (1 << j)) continue;
        const nextMask = mask | (1 << j);
        const candidate = current + cost[i + 1][j + 1];
        if (candidate < dp[nextMask][j]) {
          dp[nextMask][j] = candidate;
          parent[nextMask][j] = i;
        }
      }
    }
  }

  const fullMask = FULL - 1;
  let best = Infinity;
  let bestLast = -1;
  for (let i = 0; i < m; i++) {
    const candidate = dp[fullMask][i] + cost[i + 1][0];
    if (candidate < best) {
      best = candidate;
      bestLast = i;
    }
  }

  const order = [];
  let mask = fullMask;
  let last = bestLast;
  while (last !== -1) {
    order.push(last);
    const prevLast = parent[mask][last];
    mask ^= 1 << last;
    last = prevLast;
  }
  order.reverse();

  return { order: order.map((i) => i + 1), totalCost: best };
}

async function fetchGoogleMatrix(nodes) {
  const coordStr = nodes.map((n) => `${n.latitude},${n.longitude}`).join("|");
  const url =
    `https://maps.googleapis.com/maps/api/distancematrix/json` +
    `?origins=${encodeURIComponent(coordStr)}` +
    `&destinations=${encodeURIComponent(coordStr)}` +
    `&departure_time=now` +
    `&key=${process.env.GOOGLE_MAPS_API_KEY}`;

  const response = await fetch(url);
  const data = await response.json();

  if (data.status !== "OK") {
    throw new Error(`Google Distance Matrix hatası: ${data.status}`);
  }

  const n = nodes.length;
  const durations = Array.from({ length: n }, () => new Array(n).fill(null));
  const distances = Array.from({ length: n }, () => new Array(n).fill(null));

  for (let i = 0; i < n; i++) {
    const elements = data.rows[i].elements;
    for (let j = 0; j < n; j++) {
      const el = elements[j];
      if (el.status !== "OK") continue;
      durations[i][j] = el.duration_in_traffic
        ? el.duration_in_traffic.value
        : el.duration.value;
      distances[i][j] = el.distance.value;
    }
  }

  return { durations, distances };
}

const MAX_OPTIMIZE_STOPS = Number(process.env.MAX_OPTIMIZE_STOPS) || 15;

app.post("/routes/optimize", optimizeLimiter, authenticateToken, async (req, res) => {
  const { origin, stops } = req.body;

  if (!origin || !stops || stops.length === 0) {
    return res.status(400).json({ error: "origin ve stops gerekli" });
  }

  if (stops.length > MAX_OPTIMIZE_STOPS) {
    return res.status(400).json({
      error: `Rota optimizasyonu en fazla ${MAX_OPTIMIZE_STOPS} durak destekler (gönderilen: ${stops.length})`,
    });
  }

  try {
    const nodes = [
      { latitude: origin.latitude, longitude: origin.longitude },
      ...stops.map((s) => ({ latitude: s.latitude, longitude: s.longitude })),
    ];

    const { durations, distances } = await fetchGoogleMatrix(nodes);

    const cost = durations.map((row) =>
      row.map((v) => (v === null ? 1e15 : v))
    );

    const { order, totalCost } = solveExactTsp(cost);

    const optimizedOrder = order.map((nodeIdx) => nodeIdx - 1);
    const reorderedStops = optimizedOrder.map((i) => stops[i]);

    let totalDistanceMeters = 0;
    let prev = 0;
    for (const nodeIdx of order) {
      totalDistanceMeters += distances[prev][nodeIdx] ?? 0;
      prev = nodeIdx;
    }
    totalDistanceMeters += distances[prev][0] ?? 0;

    res.json({
      optimizedOrder,
      reorderedStops,
      totalDistanceKm: (totalDistanceMeters / 1000).toFixed(1),
      totalDurationMin: Math.round(totalCost / 60),
    });
  } catch (err) {
    console.error("Optimize hatası:", err);
    if (process.env.SENTRY_DSN) Sentry.captureException(err);
    res.status(500).json({ error: "Rota optimizasyonu başarısız" });
  }
});

if (process.env.SENTRY_DSN) {
  Sentry.setupExpressErrorHandler(app);
}

// ── Genel hata yakalayıcı — mutlaka en sonda ────────────────────────────
// CORS reddi (cors middleware'in callback(new Error(...)) çağırması) ve
// beklenmeyen diğer tüm hatalar buraya düşer. NODE_ENV ne olursa olsun
// istemciye stack trace / dosya yolu gibi iç detay asla dönülmez.
app.use((err, req, res, _next) => {
  if (err && typeof err.message === "string" && err.message.startsWith("CORS engellendi")) {
    return res.status(403).json({ error: "Bu kaynağa erişim izni yok" });
  }
  console.error("Beklenmeyen hata:", err);
  // SENTRY_DSN tanımlıysa Sentry.setupExpressErrorHandler (yukarıda) bu
  // hatayı zaten yakalayıp raporladı — burada tekrar capture etmiyoruz.
  if (res.headersSent) return;
  res.status(err?.status || 500).json({ error: "Sunucu hatası" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server ${PORT} portunda çalışıyor`);
});