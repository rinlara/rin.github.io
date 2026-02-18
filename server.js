// server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const multer = require('multer');
const db = require('./config/db');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public'))); // ให้บริการไฟล์ HTML/CSS

// ตั้งค่า multer สำหรับอัปโหลดไฟล์
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // จำกัด 10 MB
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|pdf/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype && extname) return cb(null, true);
    cb(new Error('เฉพาะไฟล์ .jpeg, .jpg, .png, .pdf เท่านั้น'));
  }
});

// =============== Routes ===============

// หน้าหลัก (public)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ลงทะเบียน
app.post('/api/register', async (req, res) => {
  const { full_name, email, phone, position, subject, district, school_name } = req.body;
  const defaultPassword = "12345678"; // หรือให้ผู้ใช้ตั้งเอง
  
  try {
    const hashedPassword = await bcrypt.hash(defaultPassword, 10);
    const sql = `INSERT INTO users (full_name, email, phone, position, subject, district, school_name, password_hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    db.query(sql, [full_name, email, phone, position, subject, district, school_name, hashedPassword], (err) => {
      if (err && err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ error: 'อีเมลนี้ลงทะเบียนแล้ว' });
      }
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'ลงทะเบียนไม่สำเร็จ' });
      }
      res.status(201).json({ message: 'ลงทะเบียนสำเร็จ! รหัสผ่านเริ่มต้นคือ: 12345678' });
    });
  } catch (err) {
    res.status(500).json({ error: 'เกิดข้อผิดพลาด' });
  }
});

// ล็อกอิน (ตรวจสอบ email + password)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).json({ error: 'ระบบขัดข้อง' });
    if (results.length === 0) return res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(400).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });

    // ส่งข้อมูลผู้ใช้ (ไม่รวมรหัสผ่าน)
    const { password_hash, ...safeUser } = user;
    res.json({ user: safeUser });
  });
});

// อัปโหลดเกียรติบัตร (ต้องล็อกอิน — ในระบบจริงควรเพิ่ม auth middleware)
app.post('/api/upload', upload.single('certificate'), (req, res) => {
  const { title, description, issue_date, user_id } = req.body;
  const filePath = req.file ? `/uploads/${req.file.filename}` : null;

  if (!filePath) return res.status(400).json({ error: 'ต้องอัปโหลดไฟล์' });

  const sql = `INSERT INTO certificates (user_id, title, description, file_path, issue_date)
               VALUES (?, ?, ?, ?, ?)`;
  db.query(sql, [user_id, title, description, filePath, issue_date], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'อัปโหลดไม่สำเร็จ' });
    }
    res.json({ message: 'อัปโหลดเกียรติบัตรสำเร็จ', filePath });
  });
});

// ดึงเกียรติบัตรของผู้ใช้
app.get('/api/certificates/:userId', (req, res) => {
  const userId = req.params.userId;
  const sql = 'SELECT * FROM certificates WHERE user_id = ? ORDER BY upload_date DESC';
  db.query(sql, [userId], (err, results) => {
    if (err) return res.status(500).json({ error: 'ดึงข้อมูลไม่ได้' });
    res.json(results);
  });
});

// ดึงข้อมูลผู้ใช้ (โปรไฟล์)
app.get('/api/user/:id', (req, res) => {
  const sql = 'SELECT id, full_name, email, phone, position, subject, district, school_name, role FROM users WHERE id = ?';
  db.query(sql, [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
    res.json(results[0]);
  });
});

// สำหรับแอดมิน: สถิติทั้งหมด
app.get('/api/admin/stats', (req, res) => {
  const queries = [
    'SELECT COUNT(*) AS total_teachers FROM users WHERE role = "teacher"',
    'SELECT COUNT(*) AS total_certificates FROM certificates',
    'SELECT district, COUNT(*) AS teacher_count FROM users WHERE role = "teacher" GROUP BY district',
    'SELECT school_name, COUNT(*) AS teacher_count FROM users WHERE role = "teacher" GROUP BY school_name'
  ];

  let results = {};
  let completed = 0;

  queries.forEach((sql, i) => {
    db.query(sql, (err, data) => {
      if (err) return res.status(500).json({ error: 'ดึงสถิติไม่ได้' });
      const keys = ['total_teachers', 'total_certificates', 'districts', 'schools'];
      results[keys[i]] = data;
      completed++;
      if (completed === queries.length) res.json(results);
    });
  });
});

// =============== Start Server ===============
// เปลี่ยนจาก 3000 เป็น 3001 หรือ 8080
app.listen(3001, () => {
  console.log('🚀 ระบบทำงานที่ http://localhost:3003');

  console.log(`📁 โฟลเดอร์อัปโหลด: /uploads`);
});