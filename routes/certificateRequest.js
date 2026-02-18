// routes/certificateRequest.js
const express = require('express');
const router = express.Router();
const db = require('../config/database');

// ========================================
// Middleware ตรวจสอบสิทธิ์
// ========================================

// ตรวจสอบการเข้าสู่ระบบ
const requireLogin = (req, res, next) => {
  if (!req.session?.user) {
    return res.redirect('/login?error=กรุณาเข้าสู่ระบบ');
  }
  next();
};

// ตรวจสอบสิทธิ์ครูหรือบุคลากร
const requireTeacherOrStaff = (req, res, next) => {
  if (!req.session?.user || !['teacher', 'staff'].includes(req.session.user.role)) {
    return res.redirect('/login?error=ต้องเข้าสู่ระบบในฐานะครูหรือบุคลากร');
  }
  next();
};

// ตรวจสอบสิทธิ์แอดมิน
const requireAdmin = (req, res, next) => {
  if (!req.session?.user || req.session.user.role !== 'admin') {
    return res.redirect('/login?error=ต้องเข้าสู่ระบบในฐานะแอดมิน');
  }
  next();
};

// ========================================
// Helper Function: แปลงข้อมูลจาก DB ให้ตรงกับ Frontend
// ========================================
const formatRequestForFrontend = (request) => {
  return {
    ...request,
    // ✅ แปลง u.role -> user_type เพื่อความสอดคล้องกับ frontend
    user_type: request.role,
    // แปลง certificate_numbers จาก string เป็น array (ถ้ามี)
    certificate_numbers: request.cert_numbers 
      ? request.cert_numbers.split(',').filter(n => n && n.trim() !== '')
      : []
  };
};

// ========================================
// Routes สำหรับครูและบุคลากร
// ========================================

// หน้าขอหมายเลขเกียรติบัตร
router.get('/request-certificate', requireLogin, requireTeacherOrStaff, async (req, res) => {
  try {
    const user = req.session.user;
    
    // ดึงประวัติการขอ
    const [requests] = await db.query(`
      SELECT cr.*, 
             (SELECT COUNT(*) FROM certificate_numbers WHERE request_id = cr.id) as generated_count
      FROM certificate_requests cr
      WHERE cr.user_id = ? AND cr.user_type = ?
      ORDER BY cr.created_at DESC
    `, [user.id, user.role]);
    
    const pendingCount = requests.filter(r => r.status === 'pending').length;
    const approvedCount = requests.filter(r => r.status === 'approved').length;
    
    res.render('request-certificate', {
      layout: user.role === 'teacher' ? 'layouts/main' : 'layouts/staff',
      title: 'ขอหมายเลขเกียรติบัตร',
      user: user,
      requests: requests,
      pendingCount: pendingCount,
      approvedCount: approvedCount,
      activePage: 'request-certificate'
    });
  } catch (error) {
    console.error('❌ Error loading request page:', error);
    res.redirect(`/${req.session.user.role}?error=เกิดข้อผิดพลาด`);
  }
});

// ส่งคำขอหมายเลขเกียรติบัตร
router.post('/request-certificate', requireLogin, requireTeacherOrStaff, async (req, res) => {
  try {
    const { event_name, request_date, event_date, requester_name, signature_owner, certificate_count, description } = req.body;
    const user = req.session.user;
    
    if (!event_name || !request_date || !event_date || !signature_owner || !certificate_count) {
      return res.redirect(`/request-certificate?error=กรุณากรอกข้อมูลให้ครบถ้วน`);
    }
    
    const count = parseInt(certificate_count);
    if (isNaN(count) || count <= 0) {
      return res.redirect(`/request-certificate?error=จำนวนหมายเลขเกียรติบัตรต้องมากกว่า 0`);
    }
    
    const [result] = await db.query(
      `INSERT INTO certificate_requests 
       (user_id, user_type, event_name, request_date, event_date, requester_name, signature_owner, certificate_count, description) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [user.id, user.role, event_name, request_date, event_date, requester_name || user.full_name, signature_owner, count, description || null]
    );
    
    res.redirect(`/request-certificate?success=ส่งคำขอเรียบร้อยแล้ว รอการตรวจสอบจากเจ้าหน้าที่`);
    
  } catch (error) {
    console.error('❌ Error submitting request:', error);
    res.redirect(`/request-certificate?error=เกิดข้อผิดพลาดในการส่งคำขอ`);
  }
});

// ดูรายละเอียดคำขอ
router.get('/request-detail/:id', requireLogin, requireTeacherOrStaff, async (req, res) => {
  try {
    const requestId = req.params.id;
    const user = req.session.user;
    
    const [request] = await db.query(
      'SELECT * FROM certificate_requests WHERE id = ? AND user_id = ? AND user_type = ?',
      [requestId, user.id, user.role]
    );
    
    if (request.length === 0) {
      return res.redirect(`/request-certificate?error=ไม่พบข้อมูล`);
    }
    
    res.render('request-detail', {
      layout: user.role === 'teacher' ? 'layouts/main' : 'layouts/staff',
      title: 'รายละเอียดการอนุมัติ',
      user: user,
      request: request[0],
      activePage: 'request-certificate'
    });
  } catch (error) {
    console.error('❌ Error loading request detail:', error);
    res.redirect(`/request-certificate?error=เกิดข้อผิดพลาด`);
  }
});

// ========================================
// แสดงหมายเลขเกียรติบัตร
// ========================================
router.get('/certificates/:requestId', requireLogin, requireTeacherOrStaff, async (req, res) => {
  try {
    const requestId = req.params.requestId;
    const user = req.session.user;
    
    // ตรวจสอบสิทธิ์และดึงข้อมูลคำขอ
    const [request] = await db.query(
      'SELECT * FROM certificate_requests WHERE id = ? AND (user_id = ? OR ? = "admin")',
      [requestId, user.id, user.role]
    );
    
    if (request.length === 0) {
      return res.redirect(`/request-certificate?error=ไม่พบข้อมูล`);
    }
    
    // ตรวจสอบสถานะคำขอ
    if (request[0].status !== 'approved') {
      return res.redirect(`/request-certificate?error=คำขอนี้ยังไม่ได้รับการอนุมัติ`);
    }
    
    // ดึงหมายเลขเกียรติบัตรทั้งหมด
    const [certificates] = await db.query(`
      SELECT cn.*, 
             cu.recipient_name,
             cu.recipient_school,
             cu.issued_date,
             cu.id as usage_id,
             CASE 
               WHEN cu.id IS NOT NULL THEN TRUE 
               ELSE FALSE 
             END as used
      FROM certificate_numbers cn
      LEFT JOIN certificate_usage cu ON cn.id = cu.certificate_id
      WHERE cn.request_id = ?
      ORDER BY cn.sequence_number ASC
    `, [requestId]);
    
    if (certificates.length === 0) {
      return res.redirect(`/request-certificate?error=ไม่พบหมายเลขเกียรติบัตรสำหรับคำขอนี้`);
    }
    
    res.render('certificates/show', {
      layout: user.role === 'teacher' ? 'layouts/main' : 'layouts/staff',
      title: 'หมายเลขเกียรติบัตร',
      user: user,
      request: request[0],
      certificates: certificates,
      activePage: 'certificates'
    });
  } catch (error) {
    console.error('❌ Error loading certificates:', error);
    res.redirect(`/request-certificate?error=เกิดข้อผิดพลาด`);
  }
});

// ========================================
// ทำเครื่องหมายว่าใช้แล้ว
// ========================================
router.post('/certificates/:id/mark-used', requireLogin, async (req, res) => {
  try {
    const { id } = req.params;
    const { used_by, recipient_name, recipient_school } = req.body;
    const userId = req.session.user.id;
    
    if (!recipient_name || recipient_name.trim() === '') {
      return res.status(400).json({ 
        success: false, 
        message: 'กรุณาระบุชื่อผู้รับเกียรติบัตร' 
      });
    }
    
    // ตรวจสอบว่าหมายเลขเกียรติบัตรนี้มีอยู่จริง
    const [certResult] = await db.query(
      `SELECT cn.*, cr.user_id, cr.user_type 
       FROM certificate_numbers cn
       JOIN certificate_requests cr ON cn.request_id = cr.id
       WHERE cn.id = ?`,
      [id]
    );
    
    if (certResult.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'ไม่พบหมายเลขเกียรติบัตร' 
      });
    }
    
    const certificate = certResult[0];
    
    // ตรวจสอบสิทธิ์
    if (certificate.user_id !== userId && req.session.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'ไม่มีสิทธิ์ทำเครื่องหมาย' 
      });
    }
    
    // ตรวจสอบว่าหมายเลขถูกใช้ไปแล้วหรือไม่
    const [usageCheck] = await db.query(
      `SELECT * FROM certificate_usage WHERE certificate_id = ?`,
      [id]
    );
    
    if (usageCheck.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'หมายเลขเกียรติบัตรนี้ถูกใช้งานไปแล้ว' 
      });
    }
    
    // ทำเครื่องหมายว่าใช้แล้ว
    const [result] = await db.query(
      `INSERT INTO certificate_usage 
       (certificate_id, recipient_name, recipient_school, issued_by, issued_date, user_id) 
       VALUES (?, ?, ?, ?, CURDATE(), ?)`,
      [id, recipient_name, recipient_school || null, used_by || req.session.user.full_name, userId]
    );
    
    if (result.affectedRows === 0) {
      return res.status(500).json({ 
        success: false, 
        message: 'ไม่สามารถทำเครื่องหมายได้' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'ทำเครื่องหมายว่าใช้แล้วเรียบร้อย' 
    });
  } catch (error) {
    console.error('Error marking as used:', error);
    res.status(500).json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาดในการทำเครื่องหมาย: ' + error.message
    });
  }
});

// ========================================
// ยกเลิกการทำเครื่องหมาย (สำหรับแอดมิน)
// ========================================
router.post('/certificates/:id/unmark-used', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [result] = await db.query(
      `DELETE FROM certificate_usage WHERE certificate_id = ?`,
      [id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'ไม่พบหมายเลขเกียรติบัตรที่ถูกใช้งาน' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'ยกเลิกการทำเครื่องหมายเรียบร้อย' 
    });
  } catch (error) {
    console.error('Error unmarking as used:', error);
    res.status(500).json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาดในการยกเลิกการทำเครื่องหมาย' 
    });
  }
});

// ========================================
// API: ดึงข้อมูลหมายเลขเกียรติบัตรแบบ JSON
// ========================================
router.get('/certificates/:id/api', requireLogin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // ตรวจสอบสิทธิ์
    const [requestResult] = await db.query(
      `SELECT cr.user_id 
       FROM certificate_requests cr
       JOIN certificate_numbers cn ON cr.id = cn.request_id
       WHERE cn.id = ?`,
      [id]
    );
    
    if (requestResult.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'ไม่พบคำขอ' 
      });
    }
    
    const request = requestResult[0];
    
    if (request.user_id !== req.session.user.id && req.session.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'ไม่มีสิทธิ์เข้าถึง' 
      });
    }
    
    // ดึงข้อมูล
    const [certificates] = await db.query(`
      SELECT cn.*, 
             cu.recipient_name,
             cu.recipient_school,
             cu.issued_date,
             CASE 
               WHEN cu.id IS NOT NULL THEN TRUE 
               ELSE FALSE 
             END as used
      FROM certificate_numbers cn
      LEFT JOIN certificate_usage cu ON cn.id = cu.certificate_id
      WHERE cn.request_id = (
        SELECT request_id FROM certificate_numbers WHERE id = ?
      )
      ORDER BY cn.sequence_number ASC
    `, [id]);
    
    res.json({
      success: true,
      data: certificates
    });
  } catch (error) {
    console.error('Error fetching certificates API:', error);
    res.status(500).json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาด' 
    });
  }
});

// ========================================
// API: นับสถิติการใช้งาน
// ========================================
router.get('/certificates/:id/stats', requireLogin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // ตรวจสอบสิทธิ์
    const [requestResult] = await db.query(
      `SELECT cr.user_id 
       FROM certificate_requests cr
       JOIN certificate_numbers cn ON cr.id = cn.request_id
       WHERE cn.id = ?`,
      [id]
    );
    
    if (requestResult.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'ไม่พบคำขอ' 
      });
    }
    
    const request = requestResult[0];
    
    if (request.user_id !== req.session.user.id && req.session.user.role !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'ไม่มีสิทธิ์เข้าถึง' 
      });
    }
    
    // นับสถิติ
    const [stats] = await db.query(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN cu.id IS NOT NULL THEN 1 ELSE 0 END) as used,
        SUM(CASE WHEN cu.id IS NULL THEN 1 ELSE 0 END) as unused
      FROM certificate_numbers cn
      LEFT JOIN certificate_usage cu ON cn.id = cu.certificate_id
      WHERE cn.request_id = (
        SELECT request_id FROM certificate_numbers WHERE id = ?
      )
    `, [id]);
    
    res.json({
      success: true,
      stats: stats[0]
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาด' 
    });
  }
});

// ========================================
// API: ค้นหาหมายเลขเกียรติบัตร
// ========================================
router.get('/certificates/search/:number', requireLogin, async (req, res) => {
  try {
    const { number } = req.params;
    
    // ค้นหาหมายเลข
    const [certificates] = await db.query(`
      SELECT cn.*, 
             cr.event_name, 
             cr.event_date, 
             cr.signature_owner,
             u.full_name as requester_name,
             cu.recipient_name,
             cu.recipient_school,
             cu.issued_date,
             CASE 
               WHEN cu.id IS NOT NULL THEN TRUE 
               ELSE FALSE 
             END as used
      FROM certificate_numbers cn
      JOIN certificate_requests cr ON cn.request_id = cr.id
      JOIN users u ON cr.user_id = u.id
      LEFT JOIN certificate_usage cu ON cn.id = cu.certificate_id
      WHERE cn.certificate_number LIKE ? 
      ORDER BY cn.created_at DESC
      LIMIT 50
    `, [`%${number}%`]);
    
    // กรองเฉพาะที่ผู้ใช้มีสิทธิ์เข้าถึง
    const filteredCertificates = certificates.filter(cert => {
      return cert.user_id === req.session.user.id || req.session.user.role === 'admin';
    });
    
    res.json({
      success: true,
      data: filteredCertificates
    });
  } catch (error) {
    console.error('Error searching certificates:', error);
    res.status(500).json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาดในการค้นหา' 
    });
  }
});

// ========================================
// API: รายงานการใช้งาน (สำหรับแอดมิน)
// ========================================
router.get('/certificates/report/usage', requireAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let query = `
      SELECT 
        DATE(cu.issued_date) as date,
        COUNT(*) as count,
        u.full_name as issuer_name,
        cr.event_name
      FROM certificate_usage cu
      JOIN certificate_numbers cn ON cu.certificate_id = cn.id
      JOIN certificate_requests cr ON cn.request_id = cr.id
      JOIN users u ON cu.user_id = u.id
      WHERE 1=1
    `;
    
    const params = [];
    
    if (startDate && endDate) {
      query += ` AND cu.issued_date BETWEEN ? AND ?`;
      params.push(startDate, endDate);
    }
    
    query += ` GROUP BY DATE(cu.issued_date), u.full_name, cr.event_name ORDER BY date DESC`;
    
    const [usageReport] = await db.query(query, params);
    
    res.json({
      success: true,
      data: usageReport
    });
  } catch (error) {
    console.error('Error generating usage report:', error);
    res.status(500).json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาดในการสร้างรายงาน' 
    });
  }
});

// ========================================
// 🎯 Routes สำหรับแอดมิน (แก้ไขแล้ว!)
// ========================================

// ✅ หน้าจัดการคำขอหมายเลขเกียรติบัตร (Admin)
router.get('/admin/certificate-requests', requireLogin, requireAdmin, async (req, res) => {
  try {
    // Pagination parameters
    const page = parseInt(req.query.page) > 0 ? parseInt(req.query.page) : 1;
    const perPage = parseInt(req.query.perPage) > 0 ? parseInt(req.query.perPage) : 25;
    const offset = (page - 1) * perPage;

    // ✅ ดึงข้อมูลคำขอที่รอตรวจสอบ (ใช้ u.role แทน u.user_type)
    const [pendingResults] = await db.query(`
      SELECT cr.*, 
             u.full_name, 
             u.email,
             u.school_name,
             u.role,
             CASE 
               WHEN cr.user_type = 'teacher' THEN u.subject 
               ELSE u.position 
             END as position_or_subject
      FROM certificate_requests cr
      JOIN users u ON cr.user_id = u.id
      WHERE cr.status = 'pending'
      ORDER BY cr.created_at DESC
    `);
    
    // ✅ แปลงข้อมูลให้ตรงกับ frontend
    const pendingRequests = pendingResults.map(formatRequestForFrontend);

    // ✅ ดึงจำนวนรวมสำหรับ pagination
    const [countResult] = await db.query(`SELECT COUNT(*) as total FROM certificate_requests`);
    const total = countResult[0] ? countResult[0].total : 0;

    // ✅ ดึงข้อมูลคำขอทั้งหมดแบบแบ่งหน้า (ใช้ u.role แทน u.user_type)
    const [allResults] = await db.query(`
      SELECT cr.*, 
             u.full_name, 
             u.email,
             u.school_name,
             u.role,
             CASE 
               WHEN cr.user_type = 'teacher' THEN u.subject 
               ELSE u.position 
             END as position_or_subject,
             GROUP_CONCAT(cn.certificate_number ORDER BY cn.sequence_number ASC SEPARATOR ',') as cert_numbers
      FROM certificate_requests cr
      JOIN users u ON cr.user_id = u.id
      LEFT JOIN certificate_numbers cn ON cr.id = cn.request_id
      GROUP BY cr.id
      ORDER BY cr.created_at DESC
      LIMIT ? OFFSET ?
    `, [perPage, offset]);
    
    // ✅ แปลงข้อมูลทั้งหมดให้ตรงกับ frontend
    const allRequests = allResults.map(formatRequestForFrontend);
    
    // ✅ ดึงสถิติ
    const [statsResult] = await db.query(`
      SELECT 
        (SELECT COUNT(*) FROM certificate_requests WHERE status = 'pending') as pending_count,
        (SELECT COUNT(*) FROM certificate_requests WHERE status = 'approved') as approved_count,
        (SELECT COUNT(*) FROM certificate_requests WHERE status = 'rejected') as rejected_count,
        COALESCE((SELECT COUNT(*) FROM certificate_numbers), 0) as total_certificates
    `);
    
    const stats = statsResult[0] || {
      pending_count: 0,
      approved_count: 0,
      rejected_count: 0,
      total_certificates: 0
    };
    
    res.render('admin/certificate-requests', {
      layout: 'layouts/admin',
      title: 'จัดการคำขอหมายเลขเกียรติบัตร',
      user: req.session.user,
      pendingRequests: pendingRequests,
      allRequests: allRequests,
      stats: stats,
      pagination: {
        page,
        perPage,
        total,
        totalPages: Math.ceil(total / perPage)
      },
      error: null,
      success: null,
      activePage: 'certificate-requests'
    });
  } catch (error) {
    console.error('❌ Error loading admin requests page:', error);
    res.status(500).render('error', {
      message: 'เกิดข้อผิดพลาดในการโหลดข้อมูล: ' + error.message,
      error: error
    });
  }
});

// ✅ อนุมัติคำขอ (Admin)
router.post('/admin/approve-request/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const requestId = req.params.id;
    const adminId = req.session.user.id;
    
    // ตรวจสอบสถานะปัจจุบันก่อน เพื่อไม่ให้อนุมัติซ้ำ
    const [existing] = await db.query('SELECT * FROM certificate_requests WHERE id = ?', [requestId]);
    if (existing.length === 0) {
      return res.json({ success: false, message: 'ไม่พบคำขอ' });
    }
    if (existing[0].status !== 'pending') {
      return res.json({ success: false, message: 'คำขอนี้ได้รับการดำเนินการแล้ว' });
    }

    await db.query(
      'UPDATE certificate_requests SET status = "approved", approved_by = ?, approved_at = NOW() WHERE id = ?',
      [adminId, requestId]
    );

    // ดึงข้อมูลคำขอ
    const [request] = await db.query(
      'SELECT * FROM certificate_requests WHERE id = ?',
      [requestId]
    );
    
    if (request.length === 0) {
      return res.json({ success: false, message: 'ไม่พบคำขอ' });
    }
    
    // สร้างหมายเลขเกียรติบัตรในรูปแบบ 1/2569, 2/2569, ...
    const currentYear = new Date().getFullYear() + 543; // พ.ศ.
    const count = request[0].certificate_count;
    
    // ดึงหมายเลขลำดับล่าสุด
    const [sequence] = await db.query(
      'SELECT last_sequence FROM certificate_sequence WHERE year = ?',
      [currentYear]
    );
    
    let lastSequence = 0;
    if (sequence.length > 0) {
      lastSequence = sequence[0].last_sequence;
    } else {
      // สร้างเรกคอร์ดปีใหม่ถ้ายังไม่มี
      await db.query(
        'INSERT INTO certificate_sequence (year, last_sequence) VALUES (?, 0)',
        [currentYear]
      );
    }
    
    // สร้างหมายเลขเกียรติบัตร
    const values = [];
    const generatedNumbers = [];
    for (let i = 1; i <= count; i++) {
      const sequenceNumber = lastSequence + i;
      const certNumber = `${sequenceNumber}/${currentYear}`;
      
      values.push([requestId, certNumber, sequenceNumber, currentYear]);
      generatedNumbers.push(certNumber);
    }
    
    await db.query(
      'INSERT INTO certificate_numbers (request_id, certificate_number, sequence_number, year) VALUES ?',
      [values]
    );
    
    // อัพเดทหมายเลขลำดับล่าสุด
    await db.query(
      'UPDATE certificate_sequence SET last_sequence = ? WHERE year = ?',
      [lastSequence + count, currentYear]
    );
    
    res.json({
      success: true,
      message: `อนุมัติคำขอเรียบร้อยแล้ว สร้างหมายเลขเกียรติบัตร ${count} หมายเลข`,
      count: count,
      numbers: generatedNumbers.slice(0, 3)
    });
  } catch (error) {
    console.error('❌ Error approving request:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการอนุมัติคำขอ: ' + error.message,
      code: error.code
    });
  }
});

// ✅ ปฏิเสธคำขอ (Admin)
router.post('/admin/reject-request/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const requestId = req.params.id;
    const { reason } = req.body;
    const adminId = req.session.user.id;

    // ตรวจสอบสถานะปัจจุบัน
    const [existing] = await db.query('SELECT * FROM certificate_requests WHERE id = ?', [requestId]);
    if (existing.length === 0) {
      return res.json({ success: false, message: 'ไม่พบคำขอ' });
    }
    if (existing[0].status !== 'pending') {
      return res.json({ success: false, message: 'คำขอนี้ได้รับการดำเนินการแล้ว' });
    }

    await db.query(
      'UPDATE certificate_requests SET status = "rejected", rejected_by = ?, rejected_at = NOW(), rejection_reason = ? WHERE id = ?',
      [adminId, reason || null, requestId]
    );

    res.json({ success: true, message: 'ปฏิเสธคำขอเรียบร้อยแล้ว' });
  } catch (error) {
    console.error('❌ Error rejecting request:', error);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการปฏิเสธคำขอ' });
  }
});

// ✅ ดูรายละเอียดคำขอ (Admin)
router.get('/admin/certificate-requests/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const requestId = req.params.id;
    
    const [request] = await db.query(`
      SELECT cr.*, 
             u.full_name, 
             u.email,
             u.school_name,
             u.role,
             CASE 
               WHEN cr.user_type = 'teacher' THEN u.subject 
               ELSE u.position 
             END as position_or_subject
      FROM certificate_requests cr
      JOIN users u ON cr.user_id = u.id
      WHERE cr.id = ?
    `, [requestId]);
    
    if (request.length === 0) {
      return res.redirect('/admin/certificate-requests?error=ไม่พบข้อมูล');
    }
    
    const [certificates] = await db.query(`
      SELECT cn.*, 
             cu.recipient_name,
             cu.recipient_school,
             cu.issued_date,
             CASE 
               WHEN cu.id IS NOT NULL THEN TRUE 
               ELSE FALSE 
             END as used
      FROM certificate_numbers cn
      LEFT JOIN certificate_usage cu ON cn.id = cu.certificate_id
      WHERE cn.request_id = ?
      ORDER BY cn.sequence_number ASC
    `, [requestId]);
    
    // ✅ แปลงข้อมูลให้ตรงกับ frontend
    const requestFormatted = formatRequestForFrontend(request[0]);
    
    res.render('admin/certificate-request-detail', {
      layout: 'layouts/admin',
      title: 'รายละเอียดคำขอ',
      user: req.session.user,
      request: requestFormatted,
      certificates: certificates,
      activePage: 'certificate-requests'
    });
  } catch (error) {
    console.error('❌ Error loading request detail:', error);
    res.redirect('/admin/certificate-requests?error=เกิดข้อผิดพลาด');
  }
});

module.exports = router;