// ============================================
// routes/superadmin.js
// ============================================
// ซุปเปอร์แอดมิน (Super Admin) - ผู้ดูแลระบบสูงสุด
// สามารถจัดการแอดมิน, ผู้ใช้, และการตั้งค่าทั้งระบบ

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');

// Middleware: ตรวจสอบสิทธิ์ Super Admin
function requireSuperAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  req.db.execute('SELECT * FROM users WHERE id = ? AND role = ?', [req.session.userId, 'super_admin'])
    .then(([rows]) => {
      const user = rows[0];
      if (!user) {
        return res.status(403).render('error', { 
          message: 'ไม่มีสิทธิ์เข้าถึง - ต้องเป็นซุปเปอร์แอดมินเท่านั้น',
          error: { status: 403 }
        });
      }
      req.user = user;
      res.locals.user = user;
      next();
    })
    .catch(err => {
      console.error('Error checking super admin role:', err);
      res.status(500).send('เกิดข้อผิดพลาด');
    });
}

// ============================================
// แดชบอร์ด Super Admin
// ============================================
router.get('/dashboard', requireSuperAdmin, async (req, res) => {
  try {
    // ดึงสถิติทั่วไป
    const [adminCount] = await req.db.execute(
      'SELECT COUNT(*) as count FROM users WHERE role = ?',
      ['admin']
    );
    const [superAdminCount] = await req.db.execute(
      'SELECT COUNT(*) as count FROM users WHERE role = ?',
      ['super_admin']
    );
    const [teacherCount] = await req.db.execute(
      'SELECT COUNT(*) as count FROM users WHERE role = ?',
      ['teacher']
    );
    const [staffCount] = await req.db.execute(
      'SELECT COUNT(*) as count FROM users WHERE role = ?',
      ['staff']
    );
    const [certCount] = await req.db.execute(
      'SELECT COUNT(*) as count FROM certificate_requests'
    );
    const [certApprovedCount] = await req.db.execute(
      "SELECT COUNT(*) as count FROM certificate_requests WHERE status = 'approved'"
    );
    const [certPendingCount] = await req.db.execute(
      "SELECT COUNT(*) as count FROM certificate_requests WHERE status = 'pending'"
    );
    const [certRejectedCount] = await req.db.execute(
      "SELECT COUNT(*) as count FROM certificate_requests WHERE status = 'rejected'"
    );

    // ดึงแอดมินล่าสุด
    const [adminUsers] = await req.db.execute(
      'SELECT id, full_name, email, role, created_at FROM users WHERE role IN (?, ?) ORDER BY created_at DESC LIMIT 10',
      ['admin', 'super_admin']
    );

    // ดึงคำขอเกียรติบัตรล่าสุด
    const [recentRequests] = await req.db.execute(`
      SELECT cr.id, cr.event_name, cr.certificate_count, cr.status, cr.created_at, 
             u.full_name as requester_name
      FROM certificate_requests cr
      LEFT JOIN users u ON cr.user_id = u.id
      ORDER BY cr.created_at DESC
      LIMIT 5
    `);

    res.render('admin/superadmin-dashboard', {
      title: 'แดชบอร์ด Super Admin',
      adminCount: adminCount[0]?.count || 0,
      superAdminCount: superAdminCount[0]?.count || 0,
      teacherCount: teacherCount[0]?.count || 0,
      staffCount: staffCount[0]?.count || 0,
      certCount: certCount[0]?.count || 0,
      certApprovedCount: certApprovedCount[0]?.count || 0,
      certPendingCount: certPendingCount[0]?.count || 0,
      certRejectedCount: certRejectedCount[0]?.count || 0,
      adminUsers: adminUsers || [],
      recentRequests: recentRequests || []
    });
  } catch (err) {
    console.error('Super Admin Dashboard Error:', err);
    res.status(500).render('error', { 
      message: 'เกิดข้อผิดพลาดในการโหลดแดชบอร์ด',
      error: err
    });
  }
});

// ============================================
// รายการแอดมิน
// ============================================
router.get('/admins', requireSuperAdmin, async (req, res) => {
  try {
    const [admins] = await req.db.execute(`
      SELECT id, full_name, email, phone, school_name, role, created_at, updated_at 
      FROM users 
      WHERE role IN ('admin', 'super_admin')
      ORDER BY role DESC, created_at DESC
    `);

    res.render('admin/superadmin-admins', {
      title: 'จัดการแอดมิน',
      admins: admins || [],
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Error fetching admins:', err);
    res.status(500).render('error', { 
      message: 'เกิดข้อผิดพลาดในการโหลดรายการแอดมิน',
      error: err
    });
  }
});

// ============================================
// เพิ่มแอดมินใหม่
// ============================================
router.post('/admins/create', requireSuperAdmin, async (req, res) => {
  try {
    const { full_name, email, phone, password, password_confirm, school_name, role } = req.body;

    // ตรวจสอบข้อมูล
    if (!full_name || !email || !password || !role) {
      return res.redirect('/superadmin/admins?error=กรุณากรอกข้อมูลให้ครบถ้วน');
    }

    if (password !== password_confirm) {
      return res.redirect('/superadmin/admins?error=รหัสผ่านไม่ตรงกัน');
    }

    // ตรวจสอบว่า email มีอยู่แล้ว
    const [existing] = await req.db.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.redirect('/superadmin/admins?error=อีเมลนี้มีการใช้งานแล้ว');
    }

    // เข้ารหัสรหัสผ่าน
    const hashedPassword = await bcrypt.hash(password, 10);

    // เพิ่มแอดมินใหม่
    await req.db.execute(
      `INSERT INTO users (full_name, email, phone, password, school_name, role, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [full_name, email, phone || '', hashedPassword, school_name || '', role]
    );

    res.redirect('/superadmin/admins?success=เพิ่มแอดมินสำเร็จแล้ว');
  } catch (err) {
    console.error('Error creating admin:', err);
    res.redirect('/superadmin/admins?error=เกิดข้อผิดพลาดในการเพิ่มแอดมิน');
  }
});

// ============================================
// แก้ไขแอดมิน
// ============================================
router.get('/admins/:id/edit', requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const [admin] = await req.db.execute(
      'SELECT id, full_name, email, phone, school_name, role FROM users WHERE id = ? AND role IN (?, ?)',
      [id, 'admin', 'super_admin']
    );

    if (admin.length === 0) {
      return res.redirect('/superadmin/admins?error=ไม่พบแอดมิน');
    }

    res.render('admin/superadmin-admin-edit', {
      title: 'แก้ไขแอดมิน',
      admin: admin[0]
    });
  } catch (err) {
    console.error('Error loading admin:', err);
    res.redirect('/superadmin/admins?error=เกิดข้อผิดพลาด');
  }
});

// ============================================
// บันทึกการแก้ไขแอดมิน
// ============================================
router.post('/admins/:id/update', requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, email, phone, school_name, role, password } = req.body;

    // ตรวจสอบข้อมูล
    if (!full_name || !email || !role) {
      return res.redirect(`/superadmin/admins/${id}/edit?error=กรุณากรอกข้อมูลให้ครบถ้วน`);
    }

    // ตรวจสอบว่า email ที่เปลี่ยนมานี้ถูกใช้อยู่ที่อื่น
    const [existing] = await req.db.execute(
      'SELECT id FROM users WHERE email = ? AND id != ?',
      [email, id]
    );
    if (existing.length > 0) {
      return res.redirect(`/superadmin/admins/${id}/edit?error=อีเมลนี้มีการใช้งานแล้ว`);
    }

    let updateQuery = 'UPDATE users SET full_name = ?, email = ?, phone = ?, school_name = ?, role = ?, updated_at = NOW() WHERE id = ?';
    let params = [full_name, email, phone || '', school_name || '', role, id];

    // ถ้ามีการเปลี่ยนรหัสผ่าน
    if (password && password.trim() !== '') {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateQuery = 'UPDATE users SET full_name = ?, email = ?, phone = ?, school_name = ?, role = ?, password = ?, updated_at = NOW() WHERE id = ?';
      params = [full_name, email, phone || '', school_name || '', role, hashedPassword, id];
    }

    await req.db.execute(updateQuery, params);

    res.redirect('/superadmin/admins?success=แก้ไขแอดมินสำเร็จแล้ว');
  } catch (err) {
    console.error('Error updating admin:', err);
    res.redirect('/superadmin/admins?error=เกิดข้อผิดพลาดในการแก้ไขแอดมิน');
  }
});

// ============================================
// ลบแอดมิน
// ============================================
router.post('/admins/:id/delete', requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // ป้องกันการลบตัวเอง
    if (parseInt(id) === req.user.id) {
      return res.redirect('/superadmin/admins?error=ไม่สามารถลบตัวเองได้');
    }

    // ตรวจสอบว่า user นี้เป็น admin หรือ super_admin
    const [user] = await req.db.execute(
      'SELECT role FROM users WHERE id = ?',
      [id]
    );

    if (user.length === 0 || !['admin', 'super_admin'].includes(user[0].role)) {
      return res.redirect('/superadmin/admins?error=ไม่สามารถลบผู้ใช้งานนี้ได้');
    }

    await req.db.execute('DELETE FROM users WHERE id = ?', [id]);

    res.redirect('/superadmin/admins?success=ลบแอดมินสำเร็จแล้ว');
  } catch (err) {
    console.error('Error deleting admin:', err);
    res.redirect('/superadmin/admins?error=เกิดข้อผิดพลาดในการลบแอดมิน');
  }
});

// ============================================
// การจัดการผู้ใช้ระบบ
// ============================================
router.get('/users', requireSuperAdmin, async (req, res) => {
  try {
    const { role = 'all', search = '' } = req.query;

    let query = 'SELECT id, full_name, email, role, school_name, created_at FROM users WHERE 1=1';
    let params = [];

    if (role !== 'all') {
      query += ' AND role = ?';
      params.push(role);
    }

    if (search) {
      query += ' AND (full_name LIKE ? OR email LIKE ? OR school_name LIKE ?)';
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }

    query += ' ORDER BY created_at DESC LIMIT 100';

    const [users] = await req.db.execute(query, params);

    res.render('admin/superadmin-users', {
      title: 'จัดการผู้ใช้ระบบ',
      users: users || [],
      currentRole: role,
      searchTerm: search,
      success: req.query.success,
      error: req.query.error
    });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).render('error', { 
      message: 'เกิดข้อผิดพลาดในการโหลดรายการผู้ใช้',
      error: err
    });
  }
});

// ============================================
// ลบผู้ใช้ระบบ
// ============================================
router.post('/users/:id/delete', requireSuperAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // ป้องกันการลบตัวเอง
    if (parseInt(id) === req.user.id) {
      return res.redirect('/superadmin/users?error=ไม่สามารถลบตัวเองได้');
    }

    await req.db.execute('DELETE FROM users WHERE id = ?', [id]);

    res.redirect('/superadmin/users?success=ลบผู้ใช้สำเร็จแล้ว');
  } catch (err) {
    console.error('Error deleting user:', err);
    res.redirect('/superadmin/users?error=เกิดข้อผิดพลาดในการลบผู้ใช้');
  }
});

// ============================================
// ระบบการอุทธรณ์/ตรวจสอบ
// ============================================
router.get('/audits', requireSuperAdmin, async (req, res) => {
  try {
    // ดึงประวัติการอนุมัติ/ปฏิเสธ (หากมีตาราง audit)
    const [recentApprovals] = await req.db.execute(`
      SELECT cr.id, cr.event_name, cr.status, cr.approved_by, cr.approved_at, 
             cr.rejected_by, cr.rejected_at, cr.rejection_reason,
             requester.full_name as requester_name,
             approved_user.full_name as approved_by_name,
             rejected_user.full_name as rejected_by_name
      FROM certificate_requests cr
      LEFT JOIN users requester ON cr.user_id = requester.id
      LEFT JOIN users approved_user ON cr.approved_by = approved_user.id
      LEFT JOIN users rejected_user ON cr.rejected_by = rejected_user.id
      WHERE cr.status IN ('approved', 'rejected')
      ORDER BY cr.approved_at DESC, cr.rejected_at DESC
      LIMIT 50
    `);

    res.render('admin/superadmin-audits', {
      title: 'บันทึกการตรวจสอบและการอนุมัติ',
      recentApprovals: recentApprovals || []
    });
  } catch (err) {
    console.error('Error fetching audits:', err);
    res.status(500).render('error', { 
      message: 'เกิดข้อผิดพลาดในการโหลดบันทึก',
      error: err
    });
  }
});

module.exports = router;
