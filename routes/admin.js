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
