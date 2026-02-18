// routes/teacher.js
const express = require('express');
const multer = require('multer');
const path = require('path');
const pool = require('../config/db');
const router = express.Router();

// ✅ ตั้งค่า multer สำหรับอัปโหลด
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// ✅ ตรวจสอบสิทธิ์ครู
const requireTeacher = (req, res, next) => {
  if (!req.session.userId || req.session.user.role !== 'teacher') {
    return res.redirect('/login');
  }
  next();
};

// ✅ หน้าหลักแดชบอร์ด
router.get('/dashboard', requireTeacher, (req, res) => {
  res.render('teacher/dashboard', {
    layout: 'layouts/teacher/main',
    user: req.session.user
  });
});

// ✅ หน้าอัปโหลดเกียรติบัตร
router.get('/upload', requireTeacher, (req, res) => {
  res.render('teacher/upload', {
    layout: 'layouts/teacher/main',
    user: req.session.user,
    message: null
  });
});

router.post('/upload', requireTeacher, upload.single('certificate'), async (req, res) => {
  const { title, description, certificate_number, issuing_agency, issue_date } = req.body;
  
  if (!req.file) {
    return res.render('teacher/upload', {
      layout: 'layouts/teacher/main',
      user: req.session.user,
      error: '❌ กรุณาเลือกไฟล์เกียรติบัตร'
    });
  }

  const filePath = '/uploads/' + req.file.filename;

  try {
    // บันทึกข้อมูลพื้นฐาน และให้ status = 'pending' รอการอนุมัติ
    const result = await pool.query(
      `INSERT INTO certificates 
       (user_id, title, description, certificate_number, issuing_agency, issue_date, file_path, status) 
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
      [req.session.user.id, title, description, certificate_number, issuing_agency, issue_date || null, filePath]
    );

    const certificateId = result[0].insertId;

    // บันทึก audit log
    await pool.query(
      `INSERT INTO certificate_audit_log (certificate_id, user_id, action, details) 
       VALUES (?, ?, 'uploaded', ?)`,
      [certificateId, req.session.user.id, JSON.stringify({ 
        title, 
        certificate_number, 
        issuing_agency,
        file_name: req.file.filename
      })]
    );

    return res.render('teacher/upload', {
      layout: 'layouts/teacher/main',
      user: req.session.user,
      success: '✅ อัปโหลดสำเร็จ! รอการตรวจสอบจากผู้ดูแลระบบ'
    });
  } catch (err) {
    console.error('Upload error:', err);
    return res.render('teacher/upload', {
      layout: 'layouts/teacher/main',
      user: req.session.user,
      error: '❌ เกิดข้อผิดพลาด: ' + err.message
    });
  }
});

// ✅ หน้าดูเกียรติบัตรของฉัน
router.get('/certificates', requireTeacher, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM certificates WHERE user_id = $1 ORDER BY upload_date DESC',
    [req.session.user.id]
  );
  res.render('teacher/certificates', {
    layout: 'layouts/teacher/main',
    user: req.session.user,
    certificates: result.rows
  });
});

// ✅ หน้าโปรไฟล์ครู
router.get('/profile', requireTeacher, async (req, res) => {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.user.id]);
  const user = result.rows[0];
  const safeUser = {
    id: user.id,
    full_name: user.full_name,
    position: user.position,
    subject: user.subject,
    district: user.district,
    school_name: user.school_name,
    created_at: user.created_at
  };
  res.render('teacher/profile', {
    layout: 'layouts/teacher/main',
    user: req.session.user,
    profile: safeUser
  });
});

// ✅ หน้าแสดงสถิติส่วนตัว
router.get('/stats', requireTeacher, async (req, res) => {
  const certResult = await pool.query('SELECT COUNT(*) FROM certificates WHERE user_id = $1', [req.session.user.id]);
  const count = certResult.rows[0].count;
  res.render('teacher/stats', {
    layout: 'layouts/teacher/main',
    user: req.session.user,
    certificateCount: count
  });
});

// ✅ หน้าอ่านคู่มือ
router.get('/guide', requireTeacher, (req, res) => {
  res.render('teacher/guide', {
    layout: 'layouts/teacher/main',
    user: req.session.user
  });
});

module.exports = router;
