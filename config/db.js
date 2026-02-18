// config/db.js
const mysql = require('mysql2');
const util = require('util');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '28012547',
  database: 'certificate_system'
});

// ทดสอบการเชื่อมต่อ (ไม่บังคับ แต่ดีมาก)
db.connect((err) => {
  if (err) {
    console.error('❌ เชื่อมต่อฐานข้อมูลไม่ได้:', err);
    return;
  }
  console.log('✅ เชื่อมต่อ MySQL สำเร็จ (ฐานข้อมูล: certificate_system)');
});

// ✅ เพิ่ม Promise wrapper สำหรับ async/await
db.query = util.promisify(db.query);
db.execute = util.promisify(db.execute);

module.exports = db;