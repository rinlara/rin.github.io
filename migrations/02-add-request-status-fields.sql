-- Migration: เพิ่มฟิลด์การอนุมัติ/ปฏิเสธให้ table certificate_requests

ALTER TABLE certificate_requests
ADD COLUMN IF NOT EXISTS approved_by INT NULL COMMENT 'Admin user ID ที่อนุมัติ',
ADD COLUMN IF NOT EXISTS approved_at DATETIME NULL,
ADD COLUMN IF NOT EXISTS rejected_by INT NULL COMMENT 'Admin user ID ที่ปฏิเสธ',
ADD COLUMN IF NOT EXISTS rejected_at DATETIME NULL,
ADD COLUMN IF NOT EXISTS rejection_reason TEXT NULL;

-- สร้าง index ช่วยค้นหาตามสถานะ/ผู้อนุมัติ
CREATE INDEX IF NOT EXISTS idx_cr_status ON certificate_requests(status);
CREATE INDEX IF NOT EXISTS idx_cr_approved_by ON certificate_requests(approved_by);
CREATE INDEX IF NOT EXISTS idx_cr_rejected_by ON certificate_requests(rejected_by);
