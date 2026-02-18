// ============================================
// routes/admin-routes.js
// ============================================

const express = require('express');
const router = express.Router();

// Middleware: ตรวจสอบสิทธิ์แอดมิน
function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  req.db.execute('SELECT * FROM users WHERE id = ?', [req.session.userId])
    .then(([rows]) => {
      const user = rows[0];
      if (!user || user.role !== 'admin') {
        return res.status(403).send('ไม่มีสิทธิ์เข้าถึงหน้านี้');
      }
      req.user = user;
      next();
    })
    .catch(err => {
      console.error('Error checking admin role:', err);
      res.status(500).send('เกิดข้อผิดพลาด');
    });
}

// ============================================
// หน้าประวัติการขอหมายเลขเกียรติบัตรทั้งหมด
// ============================================

router.get('/certificate-history', requireAdmin, async (req, res) => {
  try {
    const { status = 'approved', year = 'all', search = '' } = req.query;
    
    // ดึงสถิติ
    const [statsRows] = await req.db.execute(`
      SELECT 
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_count,
        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_count,
        COUNT(*) as total_requests,
        COALESCE(SUM(certificate_count), 0) as total_certificates
      FROM certificate_requests
    `);
    const stats = statsRows[0] || { 
      pending_count: 0, 
      approved_count: 0, 
      rejected_count: 0, 
      total_requests: 0, 
      total_certificates: 0 
    };
    
    // สร้าง query สำหรับดึงข้อมูล
    let query = `
      SELECT 
        cr.*,
        u.full_name,
        u.school_name,
        u.role,
        u.position_or_subject,
        approver.full_name as approver_name,
        rejecter.full_name as rejecter_name
      FROM certificate_requests cr
      LEFT JOIN users u ON cr.user_id = u.id
      LEFT JOIN users approver ON cr.approved_by = approver.id
      LEFT JOIN users rejecter ON cr.rejected_by = rejecter.id
    `;
    
    const params = [];
    let whereClause = '';
    
    // กรองตามสถานะ
    if (status !== 'all') {
      whereClause = 'WHERE cr.status = ?';
      params.push(status);
    }
    
    // กรองตามปี (ถ้าระบุ)
    if (year !== 'all') {
      const gregorianYear = parseInt(year) - 543;
      if (whereClause === '') {
        whereClause = 'WHERE YEAR(cr.event_date) = ?';
      } else {
        whereClause += ' AND YEAR(cr.event_date) = ?';
      }
      params.push(gregorianYear);
    }
    
    // กรองตามคำค้นหา
    if (search.trim() !== '') {
      const searchPattern = `%${search.trim()}%`;
      if (whereClause === '') {
        whereClause = 'WHERE (cr.event_name LIKE ? OR u.full_name LIKE ? OR u.school_name LIKE ?)';
      } else {
        whereClause += ' AND (cr.event_name LIKE ? OR u.full_name LIKE ? OR u.school_name LIKE ?)';
      }
      params.push(searchPattern, searchPattern, searchPattern);
    }
    
    query += whereClause;
    query += ' ORDER BY cr.created_at DESC';
    
    const [requestsRows] = await req.db.execute(query, params);
    
    res.render('admin/certificate-history', {
      user: req.user,
      stats,
      allRequests: requestsRows,
      filterStatus: status,
      success: req.session.success || null,
      error: req.session.error || null,
      title: 'ประวัติการขอหมายเลขเกียรติบัตรทั้งหมด'
    });
    
    // ลบข้อความ flash
    delete req.session.success;
    delete req.session.error;
    
  } catch (error) {
    console.error('❌ Error loading certificate history:', error);
    req.session.error = 'เกิดข้อผิดพลาดในการโหลดข้อมูล: ' + error.message;
    res.redirect('/admin/dashboard');
  }
});

// ============================================
// หน้าจัดการคำขอ
// ============================================

router.get('/certificate-requests', requireAdmin, async (req, res) => {
  try {
    const { tab = 'pending' } = req.query;
    
    // ดึงสถิติ
    const [statsRows] = await req.db.execute(`
      SELECT 
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_count,
        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_count,
        COUNT(*) as total_requests,
        COALESCE(SUM(certificate_count), 0) as total_certificates
      FROM certificate_requests
    `);
    const stats = statsRows[0] || { 
      pending_count: 0, 
      approved_count: 0, 
      rejected_count: 0, 
      total_requests: 0, 
      total_certificates: 0 
    };
    
    // ดึงข้อมูลตามแท็บ
    let pendingRequests = [];
    let approvedRequests = [];
    let rejectedRequests = [];
    
    if (tab === 'pending' || tab === 'all') {
      const [pendingRows] = await req.db.execute(`
        SELECT 
          cr.*,
          u.full_name,
          u.school_name,
          u.role,
          u.position_or_subject
        FROM certificate_requests cr
        LEFT JOIN users u ON cr.user_id = u.id
        WHERE cr.status = 'pending'
        ORDER BY cr.created_at DESC
      `);
      pendingRequests = pendingRows;
    }
    
    if (tab === 'approved' || tab === 'all') {
      const [approvedRows] = await req.db.execute(`
        SELECT 
          cr.*,
          u.full_name,
          u.school_name,
          u.role,
          u.position_or_subject,
          admin.full_name as approver_name
        FROM certificate_requests cr
        LEFT JOIN users u ON cr.user_id = u.id
        LEFT JOIN users admin ON cr.approved_by = admin.id
        WHERE cr.status = 'approved'
        ORDER BY cr.approved_at DESC
      `);
      approvedRequests = approvedRows;
    }
    
    if (tab === 'rejected' || tab === 'all') {
      const [rejectedRows] = await req.db.execute(`
        SELECT 
          cr.*,
          u.full_name,
          u.school_name,
          u.role,
          u.position_or_subject,
          admin.full_name as rejecter_name
        FROM certificate_requests cr
        LEFT JOIN users u ON cr.user_id = u.id
        LEFT JOIN users admin ON cr.rejected_by = admin.id
        WHERE cr.status = 'rejected'
        ORDER BY cr.rejected_at DESC
      `);
      rejectedRequests = rejectedRows;
    }
    
    res.render('admin/certificate-requests', {
      user: req.user,
      stats,
      pendingRequests,
      approvedRequests,
      rejectedRequests,
      activeTab: tab,
      success: req.session.success || null,
      error: req.session.error || null,
      title: 'จัดการคำขอหมายเลขเกียรติบัตร'
    });
    
    // ลบข้อความ flash
    delete req.session.success;
    delete req.session.error;
    
  } catch (error) {
    console.error('❌ Error loading certificate requests:', error);
    req.session.error = 'เกิดข้อผิดพลาดในการโหลดข้อมูล: ' + error.message;
    res.redirect('/admin/dashboard');
  }
});

// ============================================
// API: ดูรายละเอียดคำขอ
// ============================================

router.get('/certificate-requests/:id/detail', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // ดึงข้อมูลคำขอ
    const [rows] = await req.db.execute(`
      SELECT 
        cr.*,
        u.full_name,
        u.school_name,
        u.role,
        u.position_or_subject,
        u.phone,
        u.email,
        approver.full_name as approver_name,
        rejecter.full_name as rejecter_name
      FROM certificate_requests cr
      LEFT JOIN users u ON cr.user_id = u.id
      LEFT JOIN users approver ON cr.approved_by = approver.id
      LEFT JOIN users rejecter ON cr.rejected_by = rejecter.id
      WHERE cr.id = ?
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).send('ไม่พบข้อมูลคำขอ');
    }
    
    const request = rows[0];
    const createdAt = new Date(request.created_at);
    const eventDate = new Date(request.event_date);
    const approvedAt = request.approved_at ? new Date(request.approved_at) : null;
    const rejectedAt = request.rejected_at ? new Date(request.rejected_at) : null;
    
    // Render HTML สำหรับ Modal
    let html = `
      <div class="row">
        <div class="col-md-6 mb-3">
          <div class="card border-primary">
            <div class="card-header bg-primary text-white">
              <i class="fas fa-user me-2"></i>ข้อมูลผู้ขอ
            </div>
            <div class="card-body">
              <p><strong>ชื่อ-สกุล:</strong> ${request.full_name || '-'}</p>
              <p><strong>ตำแหน่ง:</strong> ${request.position_or_subject || '-'}</p>
              <p><strong>โรงเรียน:</strong> ${request.school_name || '-'}</p>
              <p><strong>โทรศัพท์:</strong> ${request.phone || '-'}</p>
              <p><strong>อีเมล:</strong> ${request.email || '-'}</p>
              <p><strong>ประเภท:</strong> 
                ${request.user_type === 'teacher' 
                  ? '<span class="badge bg-success">ครู</span>' 
                  : '<span class="badge bg-secondary">บุคลากร</span>'}
              </p>
            </div>
          </div>
        </div>
        
        <div class="col-md-6 mb-3">
          <div class="card border-info">
            <div class="card-header bg-info text-white">
              <i class="fas fa-calendar-check me-2"></i>ข้อมูลโครงการ
            </div>
            <div class="card-body">
              <p><strong>ชื่อโครงการ/กิจกรรม:</strong> ${request.event_name || '-'}</p>
              <p><strong>วันที่จัด:</strong> ${eventDate.toLocaleDateString('th-TH', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
              <p><strong>ลงชื่อโดย:</strong> ${request.signature_owner || '-'}</p>
              <p><strong>วันที่ขอ:</strong> ${createdAt.toLocaleDateString('th-TH', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
              <p><strong>เวลา:</strong> ${createdAt.toLocaleTimeString('th-TH', { hour: '2-digit', minute: '2-digit' })}</p>
            </div>
          </div>
        </div>
        
        <div class="col-md-6 mb-3">
          <div class="card border-warning">
            <div class="card-header bg-warning text-dark">
              <i class="fas fa-certificate me-2"></i>ข้อมูลเกียรติบัตร
            </div>
            <div class="card-body">
              <p><strong>จำนวนเกียรติบัตร:</strong> ${request.certificate_count || '0'} ใบ</p>
              ${request.certificate_number 
                ? `
                  <p><strong>หมายเลขเริ่มต้น:</strong> ${request.certificate_number}</p>
                  <p><strong>หมายเลขสิ้นสุด:</strong> ${request.certificate_number_end || request.certificate_number}</p>
                `
                : '<p class="text-muted"><em>ยังไม่มีหมายเลขเกียรติบัตร</em></p>'
              }
            </div>
          </div>
        </div>
        
        <div class="col-md-6 mb-3">
          <div class="card ${request.status === 'approved' ? 'border-success' : request.status === 'rejected' ? 'border-danger' : 'border-warning'}">
            <div class="card-header bg-${request.status === 'approved' ? 'success' : request.status === 'rejected' ? 'danger' : 'warning'} text-white">
              <i class="fas ${request.status === 'approved' ? 'fa-check-circle' : request.status === 'rejected' ? 'fa-times-circle' : 'fa-clock'} me-2"></i>สถานะคำขอ
            </div>
            <div class="card-body">
              ${request.status === 'pending' 
                ? '<p class="text-warning fw-bold"><i class="fas fa-clock me-2"></i>รอการตรวจสอบ</p>'
                : request.status === 'approved' 
                ? `
                  <p class="text-success fw-bold"><i class="fas fa-check-circle me-2"></i>อนุมัติแล้ว</p>
                  ${request.approver_name ? `<p><strong>อนุมัติโดย:</strong> ${request.approver_name}</p>` : ''}
                  ${approvedAt ? `<p><strong>วันที่อนุมัติ:</strong> ${approvedAt.toLocaleDateString('th-TH', { year: 'numeric', month: 'long', day: 'numeric' })}</p>` : ''}
                `
                : `
                  <p class="text-danger fw-bold"><i class="fas fa-times-circle me-2"></i>ปฏิเสธ</p>
                  ${request.rejecter_name ? `<p><strong>ปฏิเสธโดย:</strong> ${request.rejecter_name}</p>` : ''}
                  ${rejectedAt ? `<p><strong>วันที่ปฏิเสธ:</strong> ${rejectedAt.toLocaleDateString('th-TH', { year: 'numeric', month: 'long', day: 'numeric' })}</p>` : ''}
                  ${request.rejection_reason ? `<div class="mt-2 p-2 bg-light rounded"><strong>เหตุผล:</strong> ${request.rejection_reason}</div>` : ''}
                `
              }
            </div>
          </div>
        </div>
      </div>
    `;
    
    res.send(html);
    
  } catch (error) {
    console.error('❌ Error loading request detail:', error);
    res.status(500).send('เกิดข้อผิดพลาดในการโหลดข้อมูล');
  }
});

// ============================================
// API: อนุมัติคำขอ
// ============================================

router.post('/approve-request/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // ดึงข้อมูลคำขอ
    const [requestRows] = await req.db.execute(`
      SELECT * FROM certificate_requests WHERE id = ? AND status = 'pending'
    `, [id]);
    
    if (requestRows.length === 0) {
      return res.json({
        success: false,
        message: 'ไม่พบคำขอที่รอการอนุมัติ หรือคำขอนี้ได้รับการดำเนินการไปแล้ว'
      });
    }
    
    const request = requestRows[0];
    const certificateCount = parseInt(request.certificate_count);
    const eventYear = new Date(request.event_date).getFullYear();
    const thaiYear = eventYear + 543;
    
    // ดึงหมายเลขล่าสุดของปีนี้
    const [lastNumberRows] = await req.db.execute(`
      SELECT certificate_number 
      FROM certificate_requests 
      WHERE status = 'approved' 
        AND YEAR(event_date) = ?
      ORDER BY certificate_number DESC 
      LIMIT 1
    `, [eventYear]);
    
    let startNumber = 10001; // เริ่มต้นที่ 10001
    
    if (lastNumberRows.length > 0) {
      const lastNumberStr = lastNumberRows[0].certificate_number;
      const lastNumber = parseInt(lastNumberStr.split('/')[0]);
      startNumber = lastNumber + 1;
    }
    
    // สร้างหมายเลขเกียรติบัตร
    const certificateNumber = `${startNumber}/${thaiYear}`;
    const certificateNumberEnd = `${startNumber + certificateCount - 1}/${thaiYear}`;
    
    // อัปเดตสถานะคำขอ
    await req.db.execute(`
      UPDATE certificate_requests 
      SET 
        status = 'approved',
        certificate_number = ?,
        certificate_number_end = ?,
        approved_by = ?,
        approved_at = NOW()
      WHERE id = ?
    `, [certificateNumber, certificateNumberEnd, req.user.id, id]);
    
    // สร้างตัวอย่างหมายเลขสำหรับแสดง
    const numbers = [];
    for (let i = 0; i < Math.min(certificateCount, 5); i++) {
      numbers.push(`${startNumber + i}/${thaiYear}`);
    }
    
    res.json({
      success: true,
      message: `อนุมัติคำขอเรียบร้อยแล้ว สร้างหมายเลขเกียรติบัตร ${certificateCount} หมายเลข`,
      numbers: numbers,
      count: certificateCount
    });
    
  } catch (error) {
    console.error('❌ Error approving request:', error);
    res.json({
      success: false,
      message: error.message || 'เกิดข้อผิดพลาดในการอนุมัติคำขอ'
    });
  }
});

// ============================================
// API: ปฏิเสธคำขอ
// ============================================

router.post('/reject-request/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    
    // ตรวจสอบว่าคำขออยู่ในสถานะรอตรวจสอบ
    const [requestRows] = await req.db.execute(`
      SELECT * FROM certificate_requests WHERE id = ? AND status = 'pending'
    `, [id]);
    
    if (requestRows.length === 0) {
      return res.json({
        success: false,
        message: 'ไม่พบคำขอที่รอการตรวจสอบ หรือคำขอนี้ได้รับการดำเนินการไปแล้ว'
      });
    }
    
    // อัปเดตสถานะคำขอ
    await req.db.execute(`
      UPDATE certificate_requests 
      SET 
        status = 'rejected',
        rejection_reason = ?,
        rejected_by = ?,
        rejected_at = NOW()
      WHERE id = ?
    `, [reason || 'ไม่ระบุเหตุผล', req.user.id, id]);
    
    res.json({
      success: true,
      message: 'ปฏิเสธคำขอเรียบร้อยแล้ว'
    });
    
  } catch (error) {
    console.error('❌ Error rejecting request:', error);
    res.json({
      success: false,
      message: error.message || 'เกิดข้อผิดพลาดในการปฏิเสธคำขอ'
    });
  }
});

module.exports = router;