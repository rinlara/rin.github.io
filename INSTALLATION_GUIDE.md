# 🎓 Phase 1, 2, 3: Certificate OCR, Validation & Approval System

## 📋 สรุปการเปลี่ยนแปลง

### **Phase 1: OCR (Optical Character Recognition)**
✅ เพิ่ม Tesseract.js ให้ upload form
✅ อ่านข้อมูลจากเกียรติบัตร (หมายเลข, วันที่, หน่วยงาน)
✅ แสดงข้อมูลที่อ่านได้ในฟอร์ม

### **Phase 2: Server-Side Validation API**
✅ สร้าง `/api/certificates/validate` เพื่อตรวจสอบว่าเป็นเกียรติบัตรจริง
✅ ใช้ AI (keyword matching + OCR content analysis)
✅ คิด confidence score (0-100%) 

### **Phase 3: Approval Workflow (Admin)**
✅ สร้าง Admin Dashboard: `/admin/certificate-approval`
✅ Admin สามารถอนุมัติ/ปฏิเสธเกียรติบัตร
✅ บันทึก Audit Log

---

## 🔧 Installation Steps

### 1️⃣ Run Database Migration

```bash
# ใช้ MySQL client เพื่อ run migration
mysql -u root -p certificate_system < migrations/01-add-certificate-fields.sql
```

หรือใช้ Node.js script:

```bash
node scripts/run-migration.js
```

### 2️⃣ Install Tesseract.js (already added via CDN)

OCR library ถูก load จาก CDN แล้วในหน้า upload:
```html
<script src="https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js"></script>
```

### 3️⃣ Update .env (if needed)

```env
BASE_URL=http://localhost:3000
OCRL_CONFIDENCE_THRESHOLD=60  # % confidence สำหรับ auto-approve
```

---

## 📂 Files Modified/Created

### **Modified:**
1. ✅ `views/teacher/upload.ejs` — เพิ่ม OCR button + script
2. ✅ `routes/teacher.js` — เพิ่ม certificate_number, issuing_agency, issue_date, status
3. ✅ `app.js` — เพิ่ม routes สำหรับ admin dashboard

### **Created:**
1. ✅ `routes/certificate-validation-api.js` — API สำหรับ validation & approval
2. ✅ `views/admin/certificate-approval.ejs` — Admin dashboard
3. ✅ `migrations/01-add-certificate-fields.sql` — Database migration

---

## 🚀 How to Use

### **สำหรับผู้ใช้ (Teacher/Staff):**

1. **ไปที่หน้া Upload เกียรติบัตร**
   ```
   http://localhost:3000/teacher/upload
   ```

2. **เลือกไฟล์เกียรติบัตร (JPG/PNG - OCR จะได้มากขึ้น)**

3. **กดปุ่ม "ดึงข้อมูล OCR"** 
   - ระบบจะอ่านข้อมูลจากรูปและโชว์ให้ตรวจสอบ

4. **กรอก/แก้ไขข้อมูลที่เหลือและส่ง**
   - เกียรติบัตรจะมี status = 'pending'

### **สำหรับ Admin:**

1. **ไปที่ Dashboard ตรวจสอบ**
   ```
   http://localhost:3000/admin/certificate-approval
   ```

2. **ตรวจสอบแต่ละเกียรติบัตร**
   - ดูรูป
   - ตรวจสอบข้อมูล
   - กดอนุมัติ หรือ ปฏิเสธ

3. **ผลลัพธ์:**
   - ✅ Approved → status = 'approved'
   - ❌ Rejected → status = 'rejected' + บันทึก reason

---

## 💾 Database Schema

```sql
-- Certificate table ได้รับการเพิ่มเติม:
ALTER TABLE certificates ADD COLUMN certificate_number VARCHAR(50);
ALTER TABLE certificates ADD COLUMN issuing_agency VARCHAR(255);
ALTER TABLE certificates ADD COLUMN issue_date DATE;
ALTER TABLE certificates ADD COLUMN status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending';
ALTER TABLE certificates ADD COLUMN approved_by INT;
ALTER TABLE certificates ADD COLUMN approval_date DATETIME;
ALTER TABLE certificates ADD COLUMN rejection_reason TEXT;
ALTER TABLE certificates ADD COLUMN ocr_data JSON;
ALTER TABLE certificates ADD COLUMN is_verified BOOLEAN DEFAULT FALSE;

-- Audit log table
CREATE TABLE certificate_audit_log (
  id INT PRIMARY KEY AUTO_INCREMENT,
  certificate_id INT NOT NULL,
  user_id INT NOT NULL,
  action VARCHAR(50),
  details JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (certificate_id) REFERENCES certificates(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

---

## 🔍 API Endpoints

### **Validation API:**

```bash
# ตรวจสอบเกียรติบัตร (Frontend)
POST /api/certificates/validate
Content-Type: multipart/form-data
Body: { certificate: file }

Response:
{
  "success": true,
  "data": {
    "isCertificate": true,
    "confidenceScore": 85,
    "recommendation": "approved"
  }
}
```

### **Approval API:**

```bash
# อนุมัติ
POST /api/certificates/approve/:id

# ปฏิเสธ
POST /api/certificates/reject/:id
Body: { reason: "เหตุผล" }
```

---

## 🎯 Confidence Score Rules

| Score | Action | Meaning |
|-------|--------|---------|
| 60-100% | ✅ Approve | ชัวร์ว่าเป็นเกียรติบัตร |
| 35-59% | 🔍 Review Needed | ต้องดูแบบ manual |
| 0-34% | ❌ Reject | ไม่ใช่เกียรติบัตร |

**Score based on:**
- ✅ +40% — หากมีคำ "เกียรติบัตร" / "certificate"
- ✅ +20% — หากมี signature
- ✅ +15% — หากมีวันที่
- ✅ +25% — หากมีหมายเลขเกียรติบัตร

---

## ⚠️ Known Limitations

1. **OCR accuracy depends on image quality**
   - ต้องใช้ JPG/PNG ที่ชัด
   - PDF ต้องดึงข้อมูลเอง

2. **Thai text recognition**
   - Tesseract.js + Thai model อาจไม่perfect
   - Recommend: Manual correction by user

3. **No AI fraud detection (yet)**
   - ตรวจสอบแค่ keyword matching
   - Recommend: Add image forensics (future)

---

## 🔐 Security Features

✅ File upload validation (size, type)
✅ User auth required
✅ Admin approval required
✅ Audit logging
✅ Status tracking
✅ Rejection reason tracking

---

## 📝 Example Flow

```
User (Teacher)
  ↓
Upload Certificate + Auto-OCR
  ↓
Data → Database (status: pending)
  ↓
Admin Dashboard
  ↓
Review + Decision
  ↓
Approve → status: approved ✅
Reject  → status: rejected ❌
  ↓
User See Status in Profile
```

---

## 🐛 Troubleshooting

### OCR not working?
- Check if Tesseract.js CDN is accessible
- Check browser console for errors
- Try with a clearer image

### Admin page not showing?
- Check if you're logged in as admin
- Check `/admin/certificate-approval` route

### Database errors?
- Run migration SQL manually if script fails
- Check MySQL user permissions

---

## 📞 Support

For issues, check:
1. Browser console (F12)
2. Server logs (`console.error`)
3. Database (check schema)

---

**Created:** Feb 16, 2025
**Status:** ✅ Production Ready
