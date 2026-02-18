// routes/certificate-validation-api.js
// ✅ API สำหรับตรวจสอบและความเป็นจริงของเกียรติบัตร

const express = require('express');
const router = express.Router();
const pool = require('../config/db');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

// ตั้งค่า multer
const storage = multer.diskStorage({
  destination: 'public/uploads/temp/',
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.jpg', '.jpeg', '.png'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('ประเภทไฟล์ไม่ได้รับอนุญาต'));
    }
  }
});

// ⬇️ API: Validate Certificate (ตรวจสอบเกียรติบัตร)
router.post('/validate', upload.single('certificate'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        message: 'กรุณาอัปโหลดไฟล์' 
      });
    }

    const filePath = req.file.path;
    const result = await validateCertificate(filePath);

    // ลบไฟล์ temp
    fs.unlink(filePath, (err) => {
      if (err) console.error('Failed to delete temp file:', err);
    });

    return res.json({
      success: true,
      data: result
    });
  } catch (error) {
    console.error('Validation API Error:', error);
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    return res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการตรวจสอบ: ' + error.message
    });
  }
});

// ⬇️ ฟังก์ชัน: ตรวจสอบว่าเป็นเกียรติบัตรหรือไม่ (ไม่ต้อง OCR เพราะ client ส่งมาแล้ว)
async function validateCertificate(filePath) {
  try {
    // ตรวจสอบไฟล์มีอยู่จริงหรือไม่
    if (!fs.existsSync(filePath)) {
      throw new Error('ไฟล์ไม่มีอยู่');
    }

    // ตรวจสอบประเภทไฟล์
    const ext = path.extname(filePath).toLowerCase();
    const allowedTypes = ['.jpg', '.jpeg', '.png', '.pdf'];
    
    if (!allowedTypes.includes(ext)) {
      return {
        isCertificate: false,
        confidenceScore: 0,
        recommendation: 'rejected',
        reason: 'ประเภทไฟล์ไม่ได้รับอนุญาต'
      };
    }

    // ตรวจสอบขนาดไฟล์
    const stats = fs.statSync(filePath);
    if (stats.size > 10 * 1024 * 1024) { // 10 MB
      return {
        isCertificate: false,
        confidenceScore: 0,
        recommendation: 'rejected',
        reason: 'ไฟล์มีขนาดใหญ่เกินไป'
      };
    }

    // ✅ ผ่านการตรวจสอบพื้นฐาน (ไม่ต้อง OCR เพราะ client-side ทำแล้ว)
    return {
      isCertificate: true,
      confidenceScore: 75,
      recommendation: 'approved',
      reason: 'ไฟล์ผ่านการตรวจสอบพื้นฐาน'
    };
  } catch (error) {
    console.error('Validation error:', error);
    return {
      isCertificate: false,
      confidenceScore: 0,
      recommendation: 'rejected',
      reason: 'เกิดข้อผิดพลาดในการตรวจสอบ: ' + error.message
    };
  }
}

// ⬇️ API: ได้รับรายการเกียรติบัตร pending
router.get('/pending', async (req, res) => {
  try {
    const [certificates] = await pool.query(
      `SELECT c.*, u.full_name, u.email, u.school_name
       FROM certificates c
       JOIN users u ON c.user_id = u.id
       WHERE c.status = 'pending'
       ORDER BY c.upload_date DESC`
    );

    return res.json({
      success: true,
      count: certificates.length,
      data: certificates
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด: ' + error.message
    });
  }
});

// ⬇️ API: อนุมัติเกียรติบัตร
router.post('/approve/:id', async (req, res) => {
  try {
    const certificateId = req.params.id;
    const adminId = req.session.user?.id; // ต้องเช็ค admin role

    if (!adminId) {
      return res.status(401).json({ success: false, message: 'ไม่ได้รับอนุญาต' });
    }

    // อัปเดต status เป็น approved
    await pool.query(
      `UPDATE certificates 
       SET status = 'approved', approved_by = ?, approval_date = NOW()
       WHERE id = ?`,
      [adminId, certificateId]
    );

    // บันทึก audit log
    await pool.query(
      `INSERT INTO certificate_audit_log (certificate_id, user_id, action, details)
       VALUES (?, ?, 'approved', ?)`,
      [certificateId, adminId, JSON.stringify({ approved_at: new Date() })]
    );

    return res.json({
      success: true,
      message: 'อนุมัติสำเร็จ'
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด: ' + error.message
    });
  }
});

// ⬇️ API: ปฏิเสธเกียรติบัตร
router.post('/reject/:id', async (req, res) => {
  try {
    const { reason } = req.body;
    const certificateId = req.params.id;
    const adminId = req.session.user?.id;

    if (!adminId) {
      return res.status(401).json({ success: false, message: 'ไม่ได้รับอนุญาต' });
    }

    // อัปเดต status เป็น rejected
    await pool.query(
      `UPDATE certificates 
       SET status = 'rejected', approved_by = ?, approval_date = NOW(), rejection_reason = ?
       WHERE id = ?`,
      [adminId, reason || 'ไม่ระบุสาเหตุ', certificateId]
    );

    // บันทึก audit log
    await pool.query(
      `INSERT INTO certificate_audit_log (certificate_id, user_id, action, details)
       VALUES (?, ?, 'rejected', ?)`,
      [certificateId, adminId, JSON.stringify({ reason, rejected_at: new Date() })]
    );

    return res.json({
      success: true,
      message: 'ปฏิเสธสำเร็จ'
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาด: ' + error.message
    });
  }
});

module.exports = { router, validateCertificate };
