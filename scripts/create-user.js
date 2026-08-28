// Tek kullanıcı ekler / şifresini sıfırlar (idempotent).
//
// Kullanım:
//   DATABASE_URL="<render postgres url>" node scripts/create-user.js <username> <password> [role]
//
// role verilmezse "driver". Kullanıcı zaten varsa şifresi güncellenir ve
// token_version artırılır (eski oturumlar düşer).
//
// Örnek:
//   DATABASE_URL="postgres://..." node scripts/create-user.js test2 'Test1234!' driver

require("dotenv").config();
const { Pool } = require("pg");

const [username, password, role = "driver"] = process.argv.slice(2);

if (!username || !password) {
  console.error("Kullanım: node scripts/create-user.js <username> <password> [role]");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL tanımlı değil.");
  process.exit(1);
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

(async () => {
  try {
    await pool.query("CREATE EXTENSION IF NOT EXISTS pgcrypto;");
    const { rows } = await pool.query(
      `INSERT INTO users (username, password_hash, role)
       VALUES ($1, crypt($2, gen_salt('bf')), $3)
       ON CONFLICT (username) DO UPDATE
         SET password_hash = crypt($2, gen_salt('bf')),
             role = $3,
             token_version = users.token_version + 1
       RETURNING id, username, role`,
      [username, password, role]
    );
    console.log("Tamam:", rows[0]);
  } catch (err) {
    console.error("Hata:", err.message);
    process.exit(2);
  } finally {
    await pool.end();
  }
})();
