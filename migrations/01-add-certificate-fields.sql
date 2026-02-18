-- Migration: เพิ่มฟิลด์สำคัญให้ table certificates
-- สำหรับ OCR, Validation และ Approval Workflow

-- 1. เพิ่ม column สำหรับข้อมูลเกียรติบัตร
ALTER TABLE certificates 
ADD COLUMN IF NOT EXISTS certificate_number VARCHAR(50),
ADD COLUMN IF NOT EXISTS issuing_agency VARCHAR(255),
ADD COLUMN IF NOT EXISTS issue_date DATE,
ADD COLUMN IF NOT EXISTS status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
ADD COLUMN IF NOT EXISTS approved_by INT COMMENT 'Admin user ID ที่อนุมัติ',
ADD COLUMN IF NOT EXISTS approval_date DATETIME,
ADD COLUMN IF NOT EXISTS rejection_reason TEXT COMMENT 'เหตุผลการปฏิเสธ (ถ้ามี)',
ADD COLUMN IF NOT EXISTS ocr_data JSON COMMENT 'ข้อมูลจาก OCR (certificate_number, issuing_agency, issue_date)',
ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE COMMENT 'ผ่านการตรวจสอบ AI/Manual';

-- 2. สร้าง index สำหรับการ query approved certificates
CREATE INDEX IF NOT EXISTS idx_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_user_status ON certificates(user_id, status);

-- 3. เพิ่ม column ให้ users table (สำหรับ Admin)
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS profile_image VARCHAR(255);

-- 4. Log table สำหรับ approval history
CREATE TABLE IF NOT EXISTS certificate_audit_log (
  id INT PRIMARY KEY AUTO_INCREMENT,
  certificate_id INT NOT NULL,
  user_id INT NOT NULL,
  action VARCHAR(50), -- 'uploaded', 'approved', 'rejected', 'ocr_extracted'
  details JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (certificate_id) REFERENCES certificates(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 5. สร้าง index
CREATE INDEX IF NOT EXISTS idx_cert_audit ON certificate_audit_log(certificate_id);
