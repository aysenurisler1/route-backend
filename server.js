require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map((origin) => origin.trim())
  : true;

app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json({ limit: "10mb" }));

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Tabloları otomatik oluştur
async function initDB() {
  try {
    await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS routes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(200),
        route_json JSONB,
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS driver_locations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        latitude DOUBLE PRECISION,
        longitude DOUBLE PRECISION,
        recorded_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await pool.query("ALTER TABLE routes ADD COLUMN IF NOT EXISTS vehicle_id INTEGER");
    await pool.query(`
      CREATE TABLE IF NOT EXISTS fleet_state (
        user_id INTEGER NOT NULL,
        vehicle_id INTEGER NOT NULL,
        workspace JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (user_id, vehicle_id)
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
  res.json({ message: "Rota360 backend çalışıyor", version: "1.1.0" });
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

app.post("/routes", async (req, res) => {
  const { user_id, name, route_json, vehicle_id } = req.body;
  if (!user_id || !route_json) {
    return res.status(400).json({ error: "user_id ve route_json zorunlu" });
  }
  const now = new Date().toISOString();
  const parsedRouteJson = parseRouteJson(route_json);
  const normalizedRouteJson = {
    ...parsedRouteJson,
    status: parsedRouteJson.status || "active",
    createdAt: parsedRouteJson.createdAt || now,
    updatedAt: now,
  };

  const vehicleIdValue =
    vehicle_id === undefined || vehicle_id === null ? null : Number(vehicle_id);

  try {
    const result = await pool.query(
      "INSERT INTO routes (id, user_id, name, route_json, vehicle_id) VALUES (gen_random_uuid(), $1, $2, $3, $4) RETURNING *",
      [user_id, name || "Rota360 Rota", normalizedRouteJson, vehicleIdValue]
    );
    res.status(201).json({ message: "Rota kaydedildi", route: normalizeRoute(result.rows[0]) });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

app.get("/routes/:user_id", async (req, res) => {
  const { user_id } = req.params;
  const { vehicle_id } = req.query;

  try {
    const result =
      vehicle_id === undefined
        ? await pool.query(
            "SELECT * FROM routes WHERE user_id = $1 ORDER BY created_at DESC",
            [user_id]
          )
        : await pool.query(
            "SELECT * FROM routes WHERE user_id = $1 AND vehicle_id = $2 ORDER BY created_at DESC",
            [user_id, Number(vehicle_id)]
          );

    res.json(result.rows.map(normalizeRoute));
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Mobilin kullanacağı aktif rota: şimdilik en son oluşturulan rota (opsiyonel vehicle_id filtresiyle)
app.get("/routes/:user_id/active", async (req, res) => {
  const { user_id } = req.params;
  const { vehicle_id } = req.query;

  try {
    const result =
      vehicle_id === undefined
        ? await pool.query(
            "SELECT * FROM routes WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1",
            [user_id]
          )
        : await pool.query(
            "SELECT * FROM routes WHERE user_id = $1 AND vehicle_id = $2 ORDER BY created_at DESC LIMIT 1",
            [user_id, Number(vehicle_id)]
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

// Masaüstünden gelen filo (araç bazlı çalışma alanı) durumunu kaydet
app.post("/fleet/:user_id", async (req, res) => {
  const { user_id } = req.params;
  const { vehicles } = req.body;

  if (!vehicles || typeof vehicles !== "object") {
    return res.status(400).json({ error: "vehicles zorunlu" });
  }

  try {
    await Promise.all(
      Object.entries(vehicles).map(([vehicleId, workspace]) =>
        pool.query(
          `INSERT INTO fleet_state (user_id, vehicle_id, workspace, updated_at)
           VALUES ($1, $2, $3, now())
           ON CONFLICT (user_id, vehicle_id)
           DO UPDATE SET workspace = $3, updated_at = now()`,
          [user_id, Number(vehicleId), workspace || {}]
        )
      )
    );

    res.json({ message: "Filo durumu kaydedildi" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Mobilin araç seçiciyle okuyacağı filo durumu (tüm araçlar)
app.get("/fleet/:user_id", async (req, res) => {
  const { user_id } = req.params;

  try {
    const result = await pool.query(
      "SELECT vehicle_id, workspace, updated_at FROM fleet_state WHERE user_id = $1",
      [user_id]
    );

    const vehicles = {};
    for (const row of result.rows) {
      vehicles[row.vehicle_id] = {
        workspace: row.workspace,
        updatedAt: row.updated_at,
      };
    }

    res.json({ vehicles });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Mobilde adres tamamlandı bilgisini kaydetme
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
    res.json({ message: "Giriş başarılı", user_id: user.id, username: user.username });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server ${PORT} portunda çalışıyor`);
});
