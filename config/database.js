// config/database.js
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '28012547',
  database: process.env.DB_NAME || 'certificate_system',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

// ทดสอบการเชื่อมต่อ
pool.getConnection()
  .then(conn => {
    console.log('✅ เชื่อมต่อฐานข้อมูลสำเร็จ');
    conn.release();
  })
  .catch(err => {
    console.error('❌ ไม่สามารถเชื่อมต่อฐานข้อมูลได้:', err);
  });

module.exports = pool;