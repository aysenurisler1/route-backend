require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const { initializeApp, cert } = require("firebase-admin/app");
const { getMessaging } = require("firebase-admin/messaging");

const app = express();

app.use(cors());
app.use(express.json({ limit: "10mb" }));

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
    `);
    console.log("Veritabanı tabloları hazır");
  } catch (err) {
    console.error("DB init hatası:", err.message);
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
    vehicle_id: row.vehicle_id,
    name: row.name,
    created_at: row.created_at,
    updated_at: routeJson.updatedAt || routeJson.updated_at || row.created_at,
    status: routeJson.status || "active",
    route_json: routeJson,
  };
}

// ── JWT Doğrulama Middleware ───────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Giriş yapmanız gerekiyor" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Oturum geçersiz veya süresi dolmuş" });
    }
    req.user = user;
    next();
  });
}

app.get("/", (req, res) => {
  res.json({ message: "Rota360 backend çalışıyor", version: "1.5.0" });
});

app.post("/register", async (req, res) => {
  const { username, password, role, email } = req.body;
  try {
    await pool.query(
      "INSERT INTO users (username, password_hash, role, email) VALUES ($1, crypt($2, gen_salt('bf')), $3, $4)",
      [username, password, role || "driver", email || null]
    );
    res.json({ message: "Kullanıcı oluşturuldu" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.post("/users/:user_id/assign-vehicle", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  const { vehicle_id } = req.body;
  try {
    const result = await pool.query(
      "UPDATE users SET vehicle_id = $1 WHERE id = $2 RETURNING id, username, vehicle_id",
      [vehicle_id ?? null, user_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Kullanıcı bulunamadı" });
    }
    res.json({ message: "Araç ataması güncellendi", user: result.rows[0] });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.get("/users/drivers", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, vehicle_id FROM users WHERE role = 'driver' OR role IS NULL ORDER BY username"
    );
    res.json(result.rows);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Yönetici (dispatcher), giriş yapmış personelin şifresini sıfırlar.
// E-posta gerektirmez — sadece giriş yapmış (token'lı) biri çağırabilir.
app.post("/users/:user_id/admin-reset-password", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: "Yeni şifre en az 6 karakter olmalı" });
  }
  try {
    const result = await pool.query(
      "UPDATE users SET password_hash = crypt($1, gen_salt('bf')) WHERE id = $2 RETURNING username",
      [newPassword, user_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Kullanıcı bulunamadı" });
    }
    res.json({ message: `${result.rows[0].username} kullanıcısının şifresi sıfırlandı` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Şifre sıfırlanamadı" });
  }
});

app.post("/users/:user_id/fcm-token", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  const { fcm_token } = req.body;
  try {
    await pool.query("UPDATE users SET fcm_token = $1 WHERE id = $2", [
      fcm_token,
      user_id,
    ]);
    res.json({ message: "Bildirim token'ı kaydedildi" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.post("/routes", authenticateToken, async (req, res) => {
  const { user_id, name, route_json, vehicle_id } = req.body;
  if (!user_id || !route_json) {
    return res.status(400).json({ error: "user_id ve route_json zorunlu" });
  }
  const now = new Date().toISOString();
  const parsedRouteJson = parseRouteJson(route_json);
  const resolvedVehicleId = vehicle_id ?? parsedRouteJson.vehicleId ?? null;
  const normalizedRouteJson = {
    ...parsedRouteJson,
    vehicleId: resolvedVehicleId,
    status: parsedRouteJson.status || "active",
    createdAt: parsedRouteJson.createdAt || now,
    updatedAt: now,
  };
  try {
    const result = await pool.query(
      "INSERT INTO routes (id, user_id, vehicle_id, name, route_json) VALUES (gen_random_uuid(), $1, $2, $3, $4) RETURNING *",
      [user_id, resolvedVehicleId, name || "Rota360 Rota", normalizedRouteJson]
    );

    if (resolvedVehicleId !== null && messaging) {
      try {
        const driverResult = await pool.query(
          "SELECT fcm_token FROM users WHERE vehicle_id = $1 AND fcm_token IS NOT NULL",
          [resolvedVehicleId]
        );
        for (const row of driverResult.rows) {
          await messaging.send({
            token: row.fcm_token,
            notification: {
              title: "Yeni Rota Atandı",
              body: `Araç ${resolvedVehicleId + 1} için yeni bir rota oluşturuldu.`,
            },
          });
        }
      } catch (notifErr) {
        console.log("Bildirim gönderilemedi:", notifErr.message);
      }
    }

    res.status(201).json({ message: "Rota kaydedildi", route: normalizeRoute(result.rows[0]) });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.get("/routes/:user_id", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM routes WHERE user_id = $1 ORDER BY created_at DESC",
      [user_id]
    );
    res.json(result.rows.map(normalizeRoute));
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.get("/routes/:user_id/active", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
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
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.get("/vehicles/:vehicle_id/active-route", authenticateToken, async (req, res) => {
  const { vehicle_id } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM routes WHERE vehicle_id = $1 ORDER BY created_at DESC LIMIT 1",
      [vehicle_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Bu araca atanmış aktif rota bulunamadı" });
    }
    res.json(normalizeRoute(result.rows[0]));
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.post("/fleet/:user_id", authenticateToken, async (req, res) => {
  const { vehicles } = req.body;
  try {
    await pool.query(
      `INSERT INTO fleet_workspace (singleton_id, vehicles, updated_at)
       VALUES (1, $1, NOW())
       ON CONFLICT (singleton_id)
       DO UPDATE SET vehicles = $1, updated_at = NOW()`,
      [vehicles]
    );
    res.json({ message: "Filo bilgisi kaydedildi" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Filo bilgisi kaydedilemedi" });
  }
});

app.get("/fleet/:user_id", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT vehicles, updated_at FROM fleet_workspace WHERE singleton_id = 1"
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Filo bilgisi bulunamadı" });
    }
    res.json({
      vehicles: result.rows[0].vehicles,
      updatedAt: result.rows[0].updated_at,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Filo bilgisi alınamadı" });
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
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Kullanıcı bulunamadı" });
    }
    const user = result.rows[0];
    const passwordCheck = await pool.query(
      "SELECT crypt($1, $2) = $2 AS match",
      [password, user.password_hash]
    );
    if (!passwordCheck.rows[0].match) {
      return res.status(401).json({ error: "Şifre hatalı" });
    }

    const token = jwt.sign(
      { user_id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({
      message: "Giriş başarılı",
      user_id: user.id,
      username: user.username,
      vehicle_id: user.vehicle_id,
      role: user.role,
      token: token,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

app.post("/drivers/:user_id/location", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  const { latitude, longitude } = req.body;
  try {
    await pool.query(
      "INSERT INTO driver_locations (user_id, latitude, longitude) VALUES ($1, $2, $3)",
      [user_id, latitude, longitude]
    );
    res.json({ message: "Konum güncellendi" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Konum güncellenemedi" });
  }
});

app.get("/drivers/:user_id/location", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
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

app.post("/routes/optimize", authenticateToken, async (req, res) => {
  const { origin, stops } = req.body;

  if (!origin || !stops || stops.length === 0) {
    return res.status(400).json({ error: "origin ve stops gerekli" });
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
    res.status(500).json({ error: "Rota optimizasyonu başarısız" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server ${PORT} portunda çalışıyor`);
});