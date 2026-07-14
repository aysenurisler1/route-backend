require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json({ limit: "10mb" }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function sendResetEmail(toEmail, code) {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: "Rota360 <onboarding@resend.dev>",
      to: [toEmail],
      subject: "Rota360 Şifre Sıfırlama Kodu",
      text: `Şifrenizi sıfırlamak için kodunuz: ${code}\nBu kod 15 dakika geçerlidir.`,
    }),
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`Resend API hatası: ${response.status} - ${errBody}`);
  }
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

app.get("/", (req, res) => {
  res.json({ message: "Rota360 backend çalışıyor", version: "1.3.0" });
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, crypt($2, gen_salt('bf')))",
      [username, password]
    );
    res.json({ message: "Kullanıcı oluşturuldu" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.post("/users/:user_id/assign-vehicle", async (req, res) => {
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

app.get("/users/drivers", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, vehicle_id FROM users ORDER BY username"
    );
    res.json(result.rows);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.post("/routes", async (req, res) => {
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
    res.status(201).json({ message: "Rota kaydedildi", route: normalizeRoute(result.rows[0]) });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.get("/routes/:user_id", async (req, res) => {
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

app.get("/routes/:user_id/active", async (req, res) => {
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

app.get("/vehicles/:vehicle_id/active-route", async (req, res) => {
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

app.patch("/routes/:route_id/stops/:stop_id/complete", async (req, res) => {
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

app.post("/forgot-password", async (req, res) => {
  const { username, email } = req.body;
  if (!username || !email) {
    return res.status(400).json({ error: "Kullanıcı adı ve e-posta gerekli" });
  }
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Kullanıcı bulunamadı" });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      "UPDATE users SET email = $1, reset_code = $2, reset_code_expires = $3 WHERE username = $4",
      [email, code, expires, username]
    );

    await sendResetEmail(email, code);

    res.json({ message: "Doğrulama kodu e-posta adresinize gönderildi" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Kod gönderilemedi" });
  }
});

app.post("/reset-password", async (req, res) => {
  const { username, code, newPassword } = req.body;
  if (!username || !code || !newPassword) {
    return res.status(400).json({ error: "Tüm alanlar gerekli" });
  }
  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Kullanıcı bulunamadı" });
    }
    const user = result.rows[0];

    if (user.reset_code !== code) {
      return res.status(400).json({ error: "Kod hatalı" });
    }
    if (!user.reset_code_expires || new Date() > new Date(user.reset_code_expires)) {
      return res.status(400).json({ error: "Kodun süresi dolmuş, tekrar isteyin" });
    }

    await pool.query(
      "UPDATE users SET password_hash = crypt($1, gen_salt('bf')), reset_code = NULL, reset_code_expires = NULL WHERE username = $2",
      [newPassword, username]
    );

    res.json({ message: "Şifreniz başarıyla güncellendi" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Şifre güncellenemedi" });
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
    res.json({
      message: "Giriş başarılı",
      user_id: user.id,
      username: user.username,
      vehicle_id: user.vehicle_id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

app.post("/drivers/:user_id/location", async (req, res) => {
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

app.get("/drivers/:user_id/location", async (req, res) => {
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
// cost: NxN süre matrisi (saniye), node 0 = sabit başlangıç/bitiş.
// Masaüstündeki Dart _tsp.solveExact() ile birebir aynı algoritma.
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

// ── Google Distance Matrix (trafik dahil) ile NxN süre/mesafe matrisi ──
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
      // Trafik verisi varsa onu kullan, yoksa normal süreye düş.
      durations[i][j] = el.duration_in_traffic
        ? el.duration_in_traffic.value
        : el.duration.value;
      distances[i][j] = el.distance.value;
    }
  }

  return { durations, distances };
}

// ── Rota optimizasyonu: Google trafik verisi + exact TSP ──────────────
app.post("/routes/optimize", async (req, res) => {
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