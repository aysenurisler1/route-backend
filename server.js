require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cors({
  origin: process.env.CORS_ORIGIN,
  credentials: true
}));app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

});

app.get("/", (req, res) => {
  res.send("Backend çalışıyor 🚀");
});

// Kullanıcı oluşturma
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
      [username, password]
    );
    res.json({ message: "Kullanıcı oluşturuldu" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});


// Rota ekleme
app.post("/routes", async (req, res) => {
  const { user_id, name, route_json } = req.body;

  try {
    await pool.query(
      "INSERT INTO routes (id, user_id, name, route_json) VALUES (gen_random_uuid(), $1, $2, $3)",
      [user_id, name, route_json]
    );

    res.json({ message: "Rota kaydedildi" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Kullanıcının rotalarını getir
app.get("/routes/:user_id", async (req, res) => {
  const { user_id } = req.params;

  try {
    const result = await pool.query(
      "SELECT * FROM routes WHERE user_id = $1 ORDER BY created_at DESC",
      [user_id]
    );

    res.json(result.rows);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Hata oluştu" });
  }
});

// Kullanıcı giriş
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Kullanıcı bulunamadı" });
    }

    const user = result.rows[0];

    // bcrypt doğrulama
    const passwordCheck = await pool.query(
      "SELECT crypt($1, $2) = $2 AS match",
      [password, user.password_hash]
    );

    if (!passwordCheck.rows[0].match) {
      return res.status(401).json({ error: "Şifre hatalı" });
    }

    res.json({ message: "Giriş başarılı", user_id: user.id });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Sunucu hatası" });
  }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server ${PORT} portunda çalışıyor`);
});
