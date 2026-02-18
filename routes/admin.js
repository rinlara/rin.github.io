import express from "express";
const router = express.Router();
import db from "../config/db.js"; // ไฟล์เชื่อมต่อฐานข้อมูล

// ✅ แดชบอร์ดแอดมิน
router.get("/dashboard", async (req, res) => {
  try {
    // ดึงจำนวนรวม
    const [certResult] = await db.query("SELECT COUNT(*) AS count FROM certificates");
    const [teacherResult] = await db.query("SELECT COUNT(*) AS count FROM users WHERE role = 'teacher'");
    const [schoolResult] = await db.query("SELECT COUNT(DISTINCT school_name) AS count FROM users WHERE role = 'teacher'");

    app.get('/admin/certificate-requests/history', async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // ดึงข้อมูลผู้ใช้
    const [userRows] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    const user = userRows[0];
    
    // ดึงสถิติ
    const [statsRows] = await db.execute(`
      SELECT 
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_count,
        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_count,
        COUNT(*) as total_requests
      FROM certificate_requests
    `);
    const stats = statsRows[0];
    
    // ดึงประวัติทั้งหมด
    const [requestsRows] = await db.execute(`
      SELECT * FROM certificate_requests 
      ORDER BY created_at DESC
    `);
    
    res.render('admin/certificate-requests-history', {
      user,
      stats,
      allRequests: requestsRows,
      title: 'ประวัติการขอทั้งหมด'
    });
  } catch (error) {
    console.error('Error loading history:', error);
    res.render('admin/certificate-requests-history', {
      error: 'เกิดข้อผิดพลาดในการโหลดข้อมูล',
      user: req.session.user,
      stats: { pending_count: 0, approved_count: 0, rejected_count: 0, total_requests: 0 },
      allRequests: []
    });
  }
});
    // ดึงเกียรติบัตรล่าสุด
    const [latestCerts] = await db.query(`
      SELECT c.id, c.title, c.issuing_agency, c.file_path, c.upload_date, u.full_name AS teacher_name
      FROM certificates c
      LEFT JOIN users u ON c.user_id = u.id
      ORDER BY c.upload_date DESC
      LIMIT 5
    `);

    res.render("layouts/admin/main", {
      title: "แดชบอร์ดแอดมิน",
      totalCertificates: certResult[0]?.count || 0,
      totalTeachers: teacherResult[0]?.count || 0,
      totalSchools: schoolResult[0]?.count || 0,
      certificates: latestCerts || [],
    });
  } catch (err) {
    console.error("❌ Dashboard Error:", err);
    res.status(500).send("เกิดข้อผิดพลาดในการโหลดแดชบอร์ด");
  }
});

export default router;
