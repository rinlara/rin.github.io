// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
const router = express.Router();

// เชื่อมต่อฐานข้อมูล
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '28012547',
  database: process.env.DB_NAME || 'certificate_system'
});

db.connect((err) => {
  if (err) {
    console.error('❌ ไม่สามารถเชื่อมต่อ MySQL ได้:', err.message);
  } else {
    console.log('✅ เชื่อมต่อ MySQL สำเร็จ (auth routes)');
  }
});

// หน้าล็อกอิน
router.get('/login', (req, res) => {
  res.render('login', { error: null, user: null });
});

// หน้าลงทะเบียน
router.get('/register', (req, res) => {
  res.render('register', { error: null, user: null });
});

// ลงทะเบียน (POST) — ให้ผู้ใช้ตั้งรหัสผ่านเอง
router.post('/register', async (req, res) => {
  const { 
    full_name, 
    email, 
    phone, 
    position, 
    subject, 
    district, 
    school_name, 
    password, 
    confirm_password 
  } = req.body;

  // ตรวจสอบข้อมูลทุกช่อง
  if (!full_name || !email || !phone || !position || !subject || !district || !school_name || !password || !confirm_password) {
    return res.render('register', { 
      error: 'กรุณากรอกข้อมูลให้ครบถ้วนทุกช่อง', 
      user: null 
    });
  }

  // ตรวจสอบรหัสผ่าน
  if (password !== confirm_password) {
    return res.render('register', { 
      error: 'รหัสผ่านไม่ตรงกัน', 
      user: null 
    });
  }

  if (password.length < 8) {
    return res.render('register', { 
      error: 'รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร', 
      user: null 
    });
  }

  try {
    // เข้ารหัสรหัสผ่าน
    const hashedPassword = await bcrypt.hash(password, 10);

    // บันทึกลงฐานข้อมูล
    const sql = `INSERT INTO users 
      (full_name, email, phone, position, subject, district, school_name, password_hash, role)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'teacher')`;

    db.query(sql, [full_name, email, phone, position, subject, district, school_name, hashedPassword], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.render('register', { 
            error: 'อีเมลนี้ลงทะเบียนแล้ว', 
            user: null 
          });
        }
        console.error('❌ ข้อผิดพลาดฐานข้อมูล:', err);
        return res.render('register', { 
          error: 'ระบบขัดข้อง กรุณาลองใหม่ภายหลัง', 
          user: null 
        });
      }

      // ลงทะเบียนสำเร็จ
      res.render('login', { 
        error: '✅ ลงทะเบียนสำเร็จ! คุณสามารถล็อกอินด้วยอีเมลและรหัสผ่านของคุณได้เลย', 
        user: null 
      });
    });
  } catch (err) {
    console.error('❌ ข้อผิดพลาด bcrypt:', err);
    res.render('register', { 
      error: 'เกิดข้อผิดพลาดภายในระบบ', 
      user: null 
    });
  }
});

// ล็อกอิน (POST)
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render('login', { 
      error: 'กรุณากรอกอีเมลและรหัสผ่าน', 
      user: null 
    });
  }

  const sql = `SELECT 
    id, full_name, email, phone, position, subject, district, school_name, role, password_hash 
    FROM users WHERE email = ?`;
  
  db.query(sql, [email], async (err, results) => {
    if (err) {
      console.error('❌ ข้อผิดพลาดการล็อกอิน:', err);
      return res.render('login', { 
        error: 'ระบบขัดข้อง', 
        user: null 
      });
    }

    if (results.length === 0) {
      return res.render('login', { 
        error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง', 
        user: null 
      });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.render('login', { 
        error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง', 
        user: null 
      });
    }

    // ล็อกอินสำเร็จ — บันทึก session
    req.session.user = {
      id: user.id,
      full_name: user.full_name,
      email: user.email,
      phone: user.phone,
      position: user.position,
      subject: user.subject,
      district: user.district,
      school_name: user.school_name,
      role: user.role
    };

    // เปลี่ยนเส้นทางตามบทบาท
    if (user.role === 'admin') {
      return res.redirect('/admin');
    } else {
      return res.redirect('/teacher');
    }
  });
});

// ออกจากระบบ
router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('❌ ข้อผิดพลาดตอนออกจากระบบ:', err);
    }
    res.redirect('/');
  });
});

module.exports = router;