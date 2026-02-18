// ========================
// app.js — ระบบจัดเก็บเกียรติบัตร สพป.ขอนแก่น เขต 2
// ✅ รองรับ ครู + บุคลากร + ผู้ดูแลระบบ
// ✅ มีระบบ "ลืมรหัสผ่าน" แบบปลอดภัย
// ✅ ป้องกัน brute force: 3 ครั้งผิด → บล็อก 15 นาที + หน่วง 30 วินาที
// ✅ มี CAPTCHA แบบง่าย (checkbox ยืนยัน)
// ✅ หน้าล็อกอินไม่มีเมนู
// ✅ แก้ไข CSP + IPv6 ครบถ้วน
// ========================
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const methodOverride = require('method-override');
const path = require('path');
const mysql = require('mysql2');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const expressLayouts = require('express-ejs-layouts');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const helmet = require('helmet');
const app = express();
// ============ CSRF Protection Setup ============
const { doubleCsrf } = require('csrf-csrf');
const ejsLayouts = require('express-ejs-layouts'); 




// CSP ถูกจัดการโดย Helmet middleware ด้านล่าง


const {
  generateToken,
  doubleCsrfProtection
} = doubleCsrf({
  getSecret: (req) => process.env.CSRF_SECRET || 'kkn2-secure-csrf-2025-secret-key',
  cookieName: '_csrf',
  size: 64,
  getTokenFromRequest: (req) =>
    req.body._csrf || req.query._csrf || req.headers['csrf-token'],
});

// ==============================================
// 🔁 แปลงเลขไทย → เลขอาหรับ
function thaiNumToArabic(str) {
  if (!str) return str;
  const map = { '๐': '0', '๑': '1', '๒': '2', '๓': '3', '๔': '4', '๕': '5', '๖': '6', '๗': '7', '๘': '8', '๙': '9' };
  return str.replace(/[๐-๙]/g, char => map[char] || char);
}

// ✅ ตรวจสอบรูปแบบหมายเลขเกียรติบัตร (ใหม่)
function isValidCertificateNumber(input) {
  if (!input || input.trim() === '') return false;
  const allowedPattern = /^[0-9๐-๙\/\- ]+$/;
  return allowedPattern.test(input.trim());
}
// ⚠️ ลบ CSP header โดยตรง + ตั้ง CSP directive ที่ถูกต้องสำหรับ Tesseract.js
app.use((req, res, next) => {
  res.removeHeader('Content-Security-Policy');
  res.removeHeader('Content-Security-Policy-Report-Only');
  next();
});

// 🔒 Helmet — ตั้ง CSP ให้รองรับ Tesseract.js Web Worker + WASM + blob:
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      // allow inline scripts, eval, wasm-unsafe-eval (required by Tesseract WASM), CDN and blob workers
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "'wasm-unsafe-eval'", "https://cdn.jsdelivr.net", "blob:"],
      scriptSrcElem: ["'self'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      // allow data: for wasm Blob instantiation
      connectSrc: ["'self'", "https://cdn.jsdelivr.net", "blob:", "data:"],
      workerSrc: ["'self'", "blob:"],
      childSrc: ["'self'", "blob:"],
      frameSrc: ["'self'"],
      objectSrc: ["'none'"]
    }
  })
);

    // ✳️ Override CSP header to ensure WASM and eval are allowed
    app.use((req, res, next) => {
      res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' blob:; worker-src 'self' blob:; connect-src 'self' https://cdn.jsdelivr.net blob: data:; img-src 'self' data: https: blob:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net"
      );
      next();
    });

if (!process.env.SESSION_SECRET) {
  console.error('❌ ต้องตั้งค่า SESSION_SECRET ในไฟล์ .env');
  process.exit(1);
}




// โฟลเดอร์สำหรับเก็บไฟล์อัปโหลด
const UPLOAD_DIR = 'public/uploads';
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// ตั้งค่า multer ทั่วไป (ใช้กับรูปโปรไฟล์, เอกสาร ฯลฯ)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const name = 'upload_' + Date.now() + '_' + Math.round(Math.random() * 1000) + ext;
    cb(null, name);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('อนุญาตเฉพาะไฟล์รูปภาพ (JPG, PNG) และเอกสาร (PDF, DOC) เท่านั้น'));
  }
});

// ✅ สร้างโฟลเดอร์อัปโหลด
const ensureDir = (dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
};
const uploadDir = path.join(__dirname, 'uploads');
const registerProfileDir = path.join(__dirname, 'public', 'images', 'register-profiles');
ensureDir(uploadDir);
ensureDir(registerProfileDir);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));
app.use('/images/register-profiles', express.static(registerProfileDir));
app.use(methodOverride('_method'));

// 📤 Multer Config
const uploadRegisterProfile = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, registerProfileDir),
    filename: (req, file, cb) => {
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      cb(null, 'register-' + unique + path.extname(file.originalname));
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png/i;
    cb(null, allowed.test(path.extname(file.originalname).toLowerCase()));
  }
});
const uploadCertificate = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
      const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
      cb(null, 'cert-' + unique + path.extname(file.originalname));
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|pdf/i;
    cb(null, allowed.test(path.extname(file.originalname).toLowerCase()));
  }
});

// 🧠 Session Config
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false, 
    httpOnly: true, 
    maxAge: 1000 * 60 * 60 * 24
  }
}));

// 🖼️ View Engine
app.use(expressLayouts);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 🌐 Middleware ทั่วไป
app.use((req, res, next) => {
  res.locals.title = 'ระบบจัดเก็บเกียรติบัตร สพป.ขอนแก่น เขต 2';
  res.locals.user = req.session?.user || null;
  res.locals.success = req.query.success || null;
  res.locals.error = req.query.error || null;
  next();
});

// 🗃️ Database Connection
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '28012547',
  database: process.env.DB_NAME || 'certificate_system'
}).promise();

db.execute('SELECT 1').catch(err => {
  console.error('❌ เชื่อมต่อฐานข้อมูลไม่ได้:', err.message);
  process.exit(1);
});

// 🔑 ตรวจสอบรหัสผ่าน
async function verifyPassword(inputPassword, storedHash, userId = null) {
  if (storedHash == null || storedHash === '' || storedHash === 'NULL') {
    if (inputPassword === '123456') {
      if (userId) {
        const hashed = await bcrypt.hash('123456', 12);
        await db.execute('UPDATE users SET password = ? WHERE id = ?', [hashed, userId]);
      }
      return true;
    }
    return false;
  }
  if (typeof storedHash === 'string' && storedHash.startsWith('$2')) {
    return await bcrypt.compare(inputPassword, storedHash);
  }
  if (inputPassword === storedHash) {
    if (userId) {
      const hashed = await bcrypt.hash(inputPassword, 12);
      await db.execute('UPDATE users SET password = ? WHERE id = ?', [hashed, userId]);
    }
    return true;
  }
  return false;
}

// 🔒 Middleware ตรวจสอบสิทธิ์
const requireLogin = (req, res, next) => {
  if (!req.session?.user) return res.redirect('/login');
  next();
};
const requireRole = (role) => (req, res, next) => {
  if (!req.session?.user || req.session.user.role !== role) {
    return res.redirect('/login?error=สิทธิ์ไม่เพียงพอ');
  }
  next();
};
const requireTeacher = requireRole('teacher');
const requireStaff = requireRole('staff');
const requireAdmin = requireRole('admin');

// 📧 Nodemailer (Email)
let transporter = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  try {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
  } catch (err) {
    console.warn('⚠️ ระบบอีเมล: เกิดข้อผิดพลาด');
  }
}

// 🔐 Rate Limiter + Slow Down
const { ipKeyGenerator } = require('express-rate-limit');
app.set('trust proxy', 1);
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: 'กรุณารอ 15 นาที หลังจากลองล็อกอินผิดเกิน 3 ครั้ง',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req, res) => ipKeyGenerator(req, res)
});
const loginSlowDown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 3,
  delayMs: () => 30000,
  keyGenerator: (req, res) => ipKeyGenerator(req, res),
  validate: { delayMs: false }
});

// ========================
// Routes ทั่วไป
// ========================
app.get('/', (req, res) => {
  if (req.session?.user) {
    if (req.session.user.role === 'teacher') return res.redirect('/teacher');
    if (req.session.user.role === 'staff') return res.redirect('/staff');
    if (req.session.user.role === 'admin') return res.redirect('/admin/dashboard');
  }
  const getCounts = async () => {
    const [t] = await db.execute('SELECT COUNT(*) AS count FROM users WHERE role IN (?, ?)', ['teacher', 'staff']);
    const [c] = await db.execute('SELECT COUNT(*) AS count FROM certificates');
    const [sch] = await db.execute('SELECT COUNT(DISTINCT school_name) AS count FROM users WHERE school_name IS NOT NULL AND school_name != ""');
    return { teacherCount: t[0].count, certificateCount: c[0].count, schoolCount: sch[0].count };
  };
  getCounts().then(({ teacherCount, certificateCount, schoolCount }) => {
    res.render('home', { 
      layout: 'layouts/main',
      teacherCount, 
      certificateCount, 
      schoolCount 
    });
  }).catch(err => {
    console.error('❌ โหลดข้อมูลหน้าแรกล้มเหลว:', err);
    res.render('home', { 
      layout: 'layouts/main',
      teacherCount: 0, 
      certificateCount: 0, 
      schoolCount: 0 
    });
  });
});

// 🔹 หน้าข่าวสาร
app.get('/news', (req, res) => {
  res.render('news', { layout: false });
});

// 🔹 หน้าอ่านข่าวสารเต็มรูป
app.get('/news-detail/:id', (req, res) => {
  const newsId = parseInt(req.params.id);
  const newsData = {
    1: {
      title: 'เปิดใช้งานระบบ E-Certificate',
      date: '2 ธันวาคม 2568',
      badge: 'ประกาศสำคัญ',
      icon: 'fas fa-star'
    },
    2: {
      title: 'คู่มือการใช้งานระบบฉบับสมบูรณ์',
      date: '28 พฤศจิกายน 2568',
      badge: 'คู่มือ',
      icon: 'fas fa-book-open'
    },
    3: {
      title: 'อบรมการใช้งานระบบ E-Certificate',
      date: '25 พฤศจิกายน 2568',
      badge: 'อบรม',
      icon: 'fas fa-chalkboard-user'
    },
    4: {
      title: 'ความปลอดภัยของระบบ E-Certificate',
      date: '20 พฤศจิกายน 2568',
      badge: 'ข้อมูล',
      icon: 'fas fa-shield-alt'
    },
    5: {
      title: 'วิดีโอสาธิตการใช้งานระบบ',
      date: '15 พฤศจิกายน 2568',
      badge: 'วิดีโอ',
      icon: 'fas fa-laptop'
    },
    6: {
      title: 'เปิดรับลงทะเบียนอบรม',
      date: '10 พฤศจิกายน 2568',
      badge: 'ประกาศ',
      icon: 'fas fa-bell'
    }
  };

  const news = newsData[newsId];
  if (!news) {
    return res.render('error', { layout: false, message: 'ไม่พบข่าวสารที่ต้องการ' });
  }

  const fullContent = {
    1: `
      <h2 style="color: #003d7a; margin-bottom: 1.5rem;">เปิดใช้งานระบบ E-Certificate อย่างเป็นทางการ</h2>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>วันที่ 1 ธันวาคม 2568</strong> สำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2 ได้เปิดใช้งานระบบ E-Certificate อย่างเป็นทางการ สำหรับครูและบุคลากรทุกโรงเรียนในสังกัด
      </p>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>ระบบใหม่นี้ช่วยให้:</strong>
      </p>
      <ul style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem; margin-left: 1.5rem;">
        <li>บันทึกและจัดเก็บเกียรติบัตรได้อย่างเป็นระบบ</li>
        <li>ค้นหาและจัดการข้อมูลเกียรติบัตรได้ง่ายขึ้น</li>
        <li>พิมพ์รายงานข้อมูลเกียรติบัตรต่างๆ ได้</li>
        <li>ความปลอดภัยของข้อมูลในระดับองค์กรราชการ</li>
      </ul>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        ผู้ที่ยังไม่ได้ลงทะเบียน สามารถสมัครสมาชิกได้ที่เมนูลงทะเบียน และติดตามข้อมูลอบรมการใช้งานในรอบถัดไป
      </p>
      <div style="background: #e8f4f8; border-left: 4px solid #003d7a; padding: 1.2rem; border-radius: 4px; margin-top: 1.5rem;">
        <strong style="color: #003d7a;">💡 สำหรับผู้ใช้ใหม่:</strong>
        <p style="margin-top: 0.5rem; margin-bottom: 0;">ดูคู่มือการใช้งานและวิดีโอสาธิตได้ในหมวด "ข่าวสารและประกาศ" หรือติดต่อฝ่ายเทคโนโลยีสารสนเทศ</p>
      </div>
    `,
    2: `
      <h2 style="color: #00796b; margin-bottom: 1.5rem;">คู่มือการใช้งานระบบ E-Certificate ฉบับสมบูรณ์</h2>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        เราได้เตรียมคู่มือการใช้งานระบบ E-Certificate ฉบับสมบูรณ์ที่มีคำอธิบายละเอียด พร้อมตัวอย่างภาพและขั้นตอนต่างๆ เพื่อให้ผู้ใช้ที่ทั้งผู้เชี่ยวชาญและมือใหม่
      </p>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>เนื้อหาของคู่มือ:</strong>
      </p>
      <ul style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem; margin-left: 1.5rem;">
        <li>วิธีการสมัครสมาชิกและเข้าสู่ระบบ</li>
        <li>การจัดการข้อมูลส่วนตัวและรหัสผ่าน</li>
        <li>การอัปโหลดเกียรติบัตร</li>
        <li>การค้นหาและแก้ไขเกียรติบัตร</li>
        <li>การพิมพ์รายงานและใบรับรอง</li>
        <li>การแก้ไขปัญหาทั่วไป</li>
      </ul>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        คู่มือนี้ได้รับการตรวจสอบและอนุมัติจากสำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2 และเป็นเอกสารอ้างอิงสำหรับการใช้งานระบบ
      </p>
      <div style="background: #e8f8f3; border-left: 4px solid #00796b; padding: 1.2rem; border-radius: 4px; margin-top: 1.5rem;">
        <strong style="color: #00796b;">📥 ดาวน์โหลด:</strong>
        <p style="margin-top: 0.5rem; margin-bottom: 0;">
          <a href="/downloads/manual.pdf" style="color: #00796b; font-weight: 600; text-decoration: none;">คู่มือการใช้งาน (PDF)</a> | 
          <a href="/downloads/manual-video.mp4" style="color: #00796b; font-weight: 600; text-decoration: none;">วิดีโอคู่มือ (MP4)</a>
        </p>
      </div>
    `,
    3: `
      <h2 style="color: #c62828; margin-bottom: 1.5rem;">อบรมการใช้งานระบบ E-Certificate</h2>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>เนื่องจากความต้องการของครูและบุคลากรทางการศึกษา สำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2 ได้จัดอบรมการใช้งานระบบ E-Certificate</strong>
      </p>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>รายละเอียด:</strong>
      </p>
      <ul style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem; margin-left: 1.5rem;">
        <li><strong>วันที่:</strong> 5-7 ธันวาคม 2568 (3 วัน)</li>
        <li><strong>เวลา:</strong> 08:30 - 16:30 น. (รวมพักกลางวัน 12:00-13:00)</li>
        <li><strong>สถานที่:</strong> ห้องประชุม สำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2</li>
        <li><strong>ค่าใช้จ่าย:</strong> ฟรี ไม่มีค่าใช้จ่าย</li>
        <li><strong>จำนวนผู้เข้ารับการอบรม:</strong> 50 คนต่อรุ่น</li>
      </ul>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>เนื้อหาการอบรม:</strong>
      </p>
      <ul style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem; margin-left: 1.5rem;">
        <li>ความรู้เบื้องต้นเกี่ยวกับระบบ E-Certificate</li>
        <li>การลงทะเบียนและเข้าใช้งาน</li>
        <li>การอัปโหลดและจัดการเกียรติบัตร</li>
        <li>การพิมพ์รายงานต่างๆ</li>
        <li>การแก้ไขปัญหา Q&A</li>
      </ul>
      <div style="background: #fff3e0; border-left: 4px solid #c62828; padding: 1.2rem; border-radius: 4px; margin-top: 1.5rem;">
        <strong style="color: #c62828;">📝 ลงทะเบียน:</strong>
        <p style="margin-top: 0.5rem; margin-bottom: 0;">
          <a href="/news#register" style="color: #c62828; font-weight: 600; text-decoration: none;">กรุณาลงทะเบียนเข้ารับการอบรม</a> ขอบคุณค่ะ
        </p>
      </div>
    `,
    4: `
      <h2 style="color: #6a1b9a; margin-bottom: 1.5rem;">ความปลอดภัยของระบบ E-Certificate</h2>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>สำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2 มีความมุ่งมั่นในการปกป้องข้อมูลของผู้ใช้งาน และได้นำมาตรฐานความปลอดภัยมาใช้ในระบบ E-Certificate</strong>
      </p>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>มาตรฐานและการปกป้องที่มี:</strong>
      </p>
      <ul style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem; margin-left: 1.5rem;">
        <li>✅ <strong>มาตรฐาน ISO 27001</strong> - มาตรฐานการจัดการความปลอดภัยของข้อมูล</li>
        <li>✅ <strong>เข้ารหัส SSL/TLS</strong> - ป้องกันการดักจับข้อมูลระหว่างส่ง</li>
        <li>✅ <strong>สำรองข้อมูลรายวัน</strong> - เพื่อความปลอดภัยและการกู้คืนข้อมูล</li>
        <li>✅ <strong>ความปลอดภัยระดับองค์กรราชการ</strong> - ตามมาตรฐานระดับหนึ่ง</li>
        <li>✅ <strong>การควบคุมการเข้าถึง</strong> - โดยใช้ระบบสิทธิผู้ใช้</li>
        <li>✅ <strong>บันทึกการใช้งาน</strong> - เพื่อการตรวจสอบและตรวจเรียบร้อย</li>
      </ul>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        ข้อมูลของผู้ใช้จะถูกเก็บรักษาอย่างสูงสุด และยังคงเป็นความลับของบุคคลตามพระราชบัญญัติคุ้มครองข้อมูลส่วนบุคคล พ.ศ. 2562
      </p>
      <div style="background: #f3e5f5; border-left: 4px solid #6a1b9a; padding: 1.2rem; border-radius: 4px; margin-top: 1.5rem;">
        <strong style="color: #6a1b9a;">🔒 ติดต่อสอบถาม:</strong>
        <p style="margin-top: 0.5rem; margin-bottom: 0;">หากมีข้อสงสัยเกี่ยวกับความปลอดภัยของข้อมูล โปรดติดต่อ <strong>ฝ่ายเทคโนโลยีสารสนเทศ</strong></p>
      </div>
    `,
    5: `
      <h2 style="color: #f57c00; margin-bottom: 1.5rem;">วิดีโอสาธิตการใช้งานระบบ E-Certificate</h2>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        เพื่อให้ผู้ใช้ที่เป็นมือใหม่สามารถเข้าใจการใช้งานระบบได้เร็ว เราได้สร้างวิดีโอสาธิตการใช้งานแบบละเอียดพร้อมตัวอย่างจริงทีละขั้นตอน
      </p>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>เนื้อหาวิดีโอ:</strong>
      </p>
      <ul style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem; margin-left: 1.5rem;">
        <li>📺 วิดีโอการสมัครสมาชิกและเข้าสู่ระบบ (3 นาที)</li>
        <li>📺 วิดีโอการอัปโหลดเกียรติบัตร (5 นาที)</li>
        <li>📺 วิดีโอการค้นหาและแก้ไขเกียรติบัตร (4 นาที)</li>
        <li>📺 วิดีโอการพิมพ์รายงาน (3 นาที)</li>
      </ul>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        ความยาวรวมของวิดีโอสาธิตทั้งหมด: <strong>15 นาที</strong>
      </p>
      <div style="background: #fff3e0; border-left: 4px solid #f57c00; padding: 1.2rem; border-radius: 4px; margin-top: 1.5rem;">
        <strong style="color: #f57c00;">▶️ ชมวิดีโอ:</strong>
        <p style="margin-top: 0.5rem; margin-bottom: 0;">
          <a href="/videos/tutorial" style="color: #f57c00; font-weight: 600; text-decoration: none;">ดูวิดีโอสาธิตการใช้งานทั้งหมด</a>
        </p>
      </div>
    `,
    6: `
      <h2 style="color: #1565c0; margin-bottom: 1.5rem;">เปิดรับลงทะเบียนเข้าอบรมการใช้งานระบบ E-Certificate</h2>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>สำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2 ขอเชิญชวนครูและบุคลากรทางการศึกษาทั้งหมดให้เข้ารับการอบรมการใช้งานระบบ E-Certificate</strong>
      </p>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>ข้อมูลการลงทะเบียน:</strong>
      </p>
      <ul style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem; margin-left: 1.5rem;">
        <li><strong>จำนวนผู้เข้ารับการอบรม:</strong> 300 คน (ทั้งหมด)</li>
        <li><strong>จำนวนคนต่อรุ่น:</strong> 50 คน (จำกัด)</li>
        <li><strong>จำนวนรุ่น:</strong> 6 รุ่น</li>
        <li><strong>วันลงทะเบียน:</strong> ตั้งแต่วันนี้ - 30 พฤศจิกายน 2568</li>
        <li><strong>วิธีลงทะเบียน:</strong> ผ่านระบบออนไลน์ที่เว็บไซต์สำนักงานเขตพื้นที่การศึกษา</li>
      </ul>
      <p style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem;">
        <strong>หลักเกณฑ์ในการลงทะเบียน:</strong>
      </p>
      <ul style="font-size: 1rem; line-height: 1.8; margin-bottom: 1rem; margin-left: 1.5rem;">
        <li>✓ เป็นครูหรือบุคลากรทางการศึกษา</li>
        <li>✓ สังกัดโรงเรียนในสังกัดสำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2</li>
        <li>✓ สามารถเข้าอบรมได้ทั้ง 3 วัน</li>
      </ul>
      <div style="background: #e3f2fd; border-left: 4px solid #1565c0; padding: 1.2rem; border-radius: 4px; margin-top: 1.5rem;">
        <strong style="color: #1565c0;">📋 ลงทะเบียนตอนนี้:</strong>
        <p style="margin-top: 0.5rem; margin-bottom: 0;">
          <a href="/register" style="color: #1565c0; font-weight: 600; text-decoration: none;">คลิกเพื่อลงทะเบียน</a>
        </p>
      </div>
    `
  };

  res.render('news-detail', {
    layout: false,
    title: news.title,
    newsTitle: news.title,
    date: news.date,
    badge: news.badge,
    icon: news.icon,
    content: fullContent[newsId] || ''
  });
});

// 🔹 หน้าล็อกอิน — ไม่ใช้ layout ใดๆ
app.get('/login', (req, res) => {
  res.render('login', { layout: false });
});

app.post('/login', loginRateLimiter, loginSlowDown, async (req, res) => {
  try {
    const { email, password, human_check } = req.body;
    if (!human_check) {
      return res.render('login', { layout: false, error: 'กรุณายืนยันว่าคุณไม่ใช่หุ่นยนต์' });
    }
    // แอดมินคงที่
    if (email === 'admin@kkn2.go.th' && password === 'admin123456') {
      const [adminRows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
      let adminUser;
      if (adminRows.length === 0) {
        const hashedPassword = await bcrypt.hash('admin123456', 12);
        const [result] = await db.execute(
          `INSERT INTO users (full_name, email, phone, password, position, subject, district, school_name, image_path, role)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            'ผู้ดูแลระบบ',
            'admin@kkn2.go.th',
            '0000000000',
            hashedPassword,
            'ผู้ดูแลระบบ',
            null,
            null,
            'สำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2',
            '/images/default-admin.png',
            'admin'
          ]
        );
        adminUser = { id: result.insertId, full_name: 'ผู้ดูแลระบบ', email, role: 'admin' };
      } else {
        adminUser = adminRows[0];
        if (adminUser.role !== 'admin') {
          await db.execute('UPDATE users SET role = ? WHERE id = ?', ['admin', adminUser.id]);
          adminUser.role = 'admin';
        }
      }
      req.session.user = {
        id: adminUser.id,
        full_name: adminUser.full_name,
        email: adminUser.email,
        role: 'admin'
      };
      return res.redirect('/admin/dashboard');
    }
    // ล็อกอินปกติ
    const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length === 0) {
      return res.render('login', { layout: false, error: 'อีเมลนี้ยังไม่ลงทะเบียน' });
    }
    const user = users[0];
    let finalRole = user.role;
    if (!finalRole || finalRole === '' || (finalRole !== 'admin' && finalRole !== 'teacher' && finalRole !== 'staff')) {
      if (email.includes('admin') || email.includes('director') || email.endsWith('@kk2.go.th')) {
        finalRole = 'admin';
      } else {
        finalRole = 'teacher';
      }
      await db.execute('UPDATE users SET role = ? WHERE id = ?', [finalRole, user.id]);
    }
    const isMatch = await verifyPassword(password, user.password, user.id);
    if (!isMatch) {
      return res.render('login', { layout: false, error: 'รหัสผ่านไม่ถูกต้อง (ครูเก่า: ลองใช้ 123456)' });
    }
    req.session.user = {
      id: user.id,
      full_name: user.full_name,
      email: user.email,
      role: finalRole
    };
    if (finalRole === 'teacher') return res.redirect('/teacher');
    if (finalRole === 'staff') return res.redirect('/staff');
    return res.redirect('/admin/dashboard');
  } catch (err) {
    console.error('❌ ล็อกอินล้มเหลว:', err);
    return res.render('login', { layout: false, error: 'เกิดข้อผิดพลาด กรุณาลองใหม่' });
  }
});

// 🔹 ลืมรหัสผ่าน
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { layout: false, error: null, success: null });
});
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const [users] = await db.execute('SELECT id, full_name FROM users WHERE email = ?', [email]);
    if (users.length > 0) {
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
      await db.execute(
        'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?',
        [token, expiresAt, users[0].id]
      );
      if (transporter) {
        const resetLink = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password/${token}`;
        await transporter.sendMail({
          from: `"ระบบเกียรติบัตร" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'รีเซ็ตรหัสผ่านระบบเกียรติบัตร',
          html: `<div style="font-family: 'Sarabun', sans-serif; padding: 20px;">
            <h2>รีเซ็ตรหัสผ่าน</h2>
            <p>สวัสดีคุณ ${users[0].full_name}</p>
            <p><a href="${resetLink}" style="display:inline-block;background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">ตั้งรหัสผ่านใหม่</a></p>
            <p>ลิงก์นี้ใช้ได้ 15 นาทีเท่านั้น</p>
          </div>`
        });
      }
    }
    res.render('forgot-password', {
      layout: false,
      success: 'หากอีเมลนี้มีในระบบ คุณจะได้รับลิงก์รีเซ็ตรหัสผ่านทางอีเมลภายในไม่กี่วินาที',
      error: null
    });
  } catch (err) {
    console.error('❌ ล้มเหลว:', err);
    res.render('forgot-password', { 
      layout: false, 
      error: 'เกิดข้อผิดพลาด กรุณาลองใหม่', 
      success: null 
    });
  }
});

app.get('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const [rows] = await db.execute(
      `SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()`,
      [token]
    );
    if (rows.length === 0) {
      return res.render('reset-password', {
        layout: false,
        error: 'ลิงก์รีเซ็ตรหัสผ่านหมดอายุหรือไม่ถูกต้อง',
        token: null
      });
    }
    res.render('reset-password', {
      layout: false,
      token,
      success: null,
      error: null
    });
  } catch (err) {
    console.error(err);
    res.status(500).render('error', {
      title: 'ข้อผิดพลาด',
      message: 'เกิดข้อผิดพลาดในระบบ'
    });
  }
});

app.post('/reset-password', async (req, res) => {
  try {
    const { token, password, confirm_password } = req.body;
    if (!token) {
      return res.render('reset-password', {
        layout: false,
        error: "Token ไม่ถูกต้อง",
        token: null
      });
    }
    if (password !== confirm_password) {
      return res.render('reset-password', {
        layout: false,
        error: "รหัสผ่านทั้งสองช่องไม่ตรงกัน",
        token
      });
    }
    const [rows] = await db.execute(
      `SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()`,
      [token]
    );
    if (rows.length === 0) {
      return res.render('reset-password', {
        layout: false,
        error: "ลิงก์หมดอายุหรือไม่ถูกต้อง",
        token: null
      });
    }
    const userId = rows[0].id;
    const hashedPassword = await bcrypt.hash(password, 12);
    await db.execute(
      `UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?`,
      [hashedPassword, userId]
    );
    res.render('reset-password', {
      layout: false,
      success: "ตั้งรหัสผ่านใหม่สำเร็จ! สามารถเข้าสู่ระบบได้เลย",
      token: null
    });
  } catch (err) {
    console.error(err);
    res.render('reset-password', {
      layout: false,
      error: "เกิดข้อผิดพลาดในระบบ",
      token: null
    });
  }
});

// ===================================================================================
// 🔹 ลงทะเบียน — ใช้เพียง route เดียว (แก้ไขแล้ว)
// ===================================================================================
app.get('/register', (req, res) => {
  res.render('register', { 
    layout: false,
    error: null,
    roles: [
      { value: 'teacher', label: 'ครู' },
      { value: 'staff', label: 'บุคลากร' }
    ]
  });
});

app.post('/register', uploadRegisterProfile.single('profile_image'), async (req, res) => {
  const { full_name, email, phone, password, confirm_password, position, subject, district, school_name, role } = req.body;
  
  if (!role || !['teacher', 'staff'].includes(role)) {
    return res.render('register', { 
      layout: false,
      error: 'กรุณาเลือกบทบาทให้ถูกต้อง',
      roles: [{ value: 'teacher', label: 'ครู' }, { value: 'staff', label: 'บุคลากร' }]
    });
  }
  
  if (password !== confirm_password) {
    return res.render('register', { 
      layout: false,
      error: 'รหัสผ่านไม่ตรงกัน',
      roles: [{ value: 'teacher', label: 'ครู' }, { value: 'staff', label: 'บุคลากร' }]
    });
  }
  
  // ✅ ตรวจสอบตำแหน่งสำหรับบุคลากร
  if (role === 'staff' && (!position || !position.trim())) {
    return res.render('register', { 
      layout: false,
      error: 'กรุณาระบุตำแหน่งงานสำหรับบุคลากร',
      roles: [{ value: 'teacher', label: 'ครู' }, { value: 'staff', label: 'บุคลากร' }]
    });
  }

  try {
    const [exists] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
    if (exists.length > 0) {
      return res.render('register', { 
        layout: false,
        error: 'อีเมลนี้ลงทะเบียนแล้ว',
        roles: [{ value: 'teacher', label: 'ครู' }, { value: 'staff', label: 'บุคลากร' }]
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    // ✅ ใช้รูปต่างกันตามบทบาท
    const defaultImage = role === 'teacher' 
      ? '/images/default-teacher.png' 
      : '/images/default-staff.png';
    const imagePath = req.file 
      ? `/images/register-profiles/${req.file.filename}` 
      : defaultImage;

    await db.execute(
      `INSERT INTO users (full_name, email, phone, password, position, subject, district, school_name, image_path, role)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        full_name,
        email,
        phone,
        hashedPassword,
        position?.trim() || null,
        role === 'teacher' ? (subject?.trim() || null) : null,
        role === 'teacher' ? (district?.trim() || null) : null,
        school_name?.trim() || null,
        imagePath,
        role
      ]
    );
    return res.redirect('/login?success=ลงทะเบียนสำเร็จ! กรุณาเข้าสู่ระบบ');
  } catch (err) {
    console.error('ลงทะเบียนล้มเหลว:', err);
    return res.render('register', { 
      layout: false,
      error: 'เกิดข้อผิดพลาด กรุณาลองใหม่',
      roles: [{ value: 'teacher', label: 'ครู' }, { value: 'staff', label: 'บุคลากร' }]
    });
  }
});

// 🔹 ออกจากระบบ
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('❌ ล้างเซสชันล้มเหลว:', err);
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// 🔹 คู่มือการใช้งาน — ใช้ร่วมทั้งระบบ
app.get('/guide', requireLogin, async (req, res) => {
  const user = req.session.user;
  let layout = 'layouts/main';
  let title = '📘 คู่มือการใช้งานระบบ';
  if (user.role === 'staff') {
    layout = 'layouts/staff';
    title = '📘 คู่มือการใช้งาน — บุคลากร';
  } else if (user.role === 'admin') {
    layout = 'layouts/admin';
    title = '📘 คู่มือการใช้งาน — ผู้ดูแลระบบ';
  }
  res.render('guide', {
    layout: layout,
    title: title,
    activePage: 'guide'
  });
});
// ========================
// Routes สำหรับครู
// ========================
// ... (เหมือนเดิม ไม่เปลี่ยน — ใช้ requireTeacher)
app.get('/teacher', async (req, res) => {
  if (!req.session?.user) return res.redirect('/login');
  try {
    const [userResults] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    if (userResults.length === 0) {
      req.session.destroy(() => {});
      return res.redirect('/login?error=ไม่พบข้อมูลผู้ใช้');
    }
    const user = userResults[0];
    if (user.role !== 'teacher') return res.redirect('/login?error=สิทธิ์ไม่เพียงพอ');
    req.session.user = user;
    const [certResults] = await db.execute('SELECT * FROM certificates WHERE user_id = ? ORDER BY upload_date DESC', [user.id]);
    res.render('teacher/dashboard', {
      layout: 'layouts/main',
      title: 'แดชบอร์ดครู',
      user: user,
      certificates: certResults || [],
      certificatesCount: certResults.length,
      activePage: 'dashboard'
    });
  } catch (err) {
    console.error('❌ โหลดแดชบอร์ดล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/main',
      title: 'ข้อผิดพลาด',
      message: 'เกิดข้อผิดพลาดขณะโหลดแดชบอร์ด'
    });
  }
});

// 🔹 แสดงฟอร์มอัปโหลด (GET)
app.get('/teacher/upload', requireLogin, requireTeacher, async (req, res) => {
  try {
    const [userResults] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    if (userResults.length === 0) return res.redirect('/login?error=ไม่พบข้อมูลผู้ใช้');
    const user = userResults[0];
    res.render('teacher/upload', {
      layout: 'layouts/main',
      title: 'อัปโหลดเกียรติบัตร',
      user: user,
      activePage: 'upload',
      error: null,
      success: null
    });
  } catch (err) {
    console.error('❌ โหลดหน้าอัปโหลดไม่ได้:', err);
    res.status(500).render('error', {
      layout: 'layouts/main',
      title: 'ข้อผิดพลาด',
      message: 'เกิดข้อผิดพลาดขณะโหลดหน้าอัปโหลด'
    });
  }
});

// 🔹 อัปโหลดเกียรติบัตร (POST) - ครู
app.post('/teacher/upload', requireLogin, requireTeacher, uploadCertificate.single('certificate'), async (req, res) => {
try {
  // ✅ ลบ certificate_number ออกจากตัวแปรและตรวจสอบ
  const { title, issuing_agency, description, issue_date } = req.body;
  const userId = req.session.user.id;

  // ✅ ลบการตรวจสอบรูปแบบหมายเลขเกียรติบัตร (ไม่จำเป็นสำหรับอัปโหลดส่วนตัว)
  
  // ✅ แก้ไขการตรวจสอบ: ไม่ต้องการ certificate_number
  if (!title?.trim() || !issuing_agency?.trim()) {
    return res.render('teacher/upload', {
      layout: 'layouts/main',
      title: 'อัปโหลดเกียรติบัตร',
      error: 'กรุณากรอก "ชื่อเกียรติบัตร" และ "หน่วยงานผู้มอบ" ให้ครบถ้วน',
      title, issuing_agency, description, issue_date,
      activePage: 'upload',
      user: req.session.user
    });
  }

  if (!req.file) {
    return res.render('teacher/upload', {
      layout: 'layouts/main',
      title: 'อัปโหลดเกียรติบัตร',
      error: 'กรุณาเลือกไฟล์เกียรติบัตร',
      title, issuing_agency, description, issue_date,
      activePage: 'upload',
      user: req.session.user
    });
  }

  const filePath = `/uploads/${req.file.filename}`;

  // ✅ ลบ certificate_number ออกจากคำสั่ง INSERT
  await db.execute(
    `INSERT INTO certificates
     (user_id, title, issuing_agency, description, file_path, issue_date, upload_date)
     VALUES (?, ?, ?, ?, ?, ?, NOW())`,
    [
      userId,
      title.trim(),
      issuing_agency.trim(),
      description?.trim() || null,
      filePath,
      issue_date || null
    ]
  );

  res.render('teacher/upload', {
    layout: 'layouts/main',
    title: 'อัปโหลดเกียรติบัตร',
    success: '✅ อัปโหลดเกียรติบัตรสำเร็จ!',
    activePage: 'upload',
    user: req.session.user
  });
} catch (err) {
  console.error('❌ อัปโหลดล้มเหลว:', err);
  if (req.file?.path && fs.existsSync(req.file.path)) {
    fs.unlinkSync(req.file.path);
  }
  res.render('teacher/upload', {
    layout: 'layouts/main',
    title: 'อัปโหลดเกียรติบัตร',
    error: 'เกิดข้อผิดพลาด กรุณาลองใหม่',
    title: req.body.title,
    issuing_agency: req.body.issuing_agency,
    description: req.body.description,
    issue_date: req.body.issue_date,
    activePage: 'upload',
    user: req.session.user
  });
}
});
app.get('/teacher/certificates', requireLogin, requireTeacher, async (req, res) => {
  try {
    const [userResults] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    if (userResults.length === 0) return res.redirect('/login?error=ไม่พบข้อมูลผู้ใช้');
    const user = userResults[0];
    const [certResults] = await db.execute('SELECT * FROM certificates WHERE user_id = ? ORDER BY upload_date DESC', [user.id]);
    res.render('teacher/certificates', {
      layout: 'layouts/main',
      title: 'เกียรติบัตรของฉัน',
      certificates: certResults || [],
      user: user,
      activePage: 'certificates'
    });
  } catch (err) {
    console.error('❌ ดึงรายการเกียรติบัตรไม่ได้:', err);
    res.status(500).render('error', { layout: 'layouts/main', message: 'เกิดข้อผิดพลาดขณะโหลดรายการ' });
  }
});

// ================================
// TEACHER: แก้ไขเกียรติบัตร (GET)
// ================================
app.get('/teacher/certificates/edit/:id', requireLogin, requireTeacher, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.session.user.id;

    const [rows] = await db.execute(
      'SELECT * FROM certificates WHERE id = ? AND user_id = ?',
      [id, userId]
    );

    if (rows.length === 0) {
      return res.redirect('/teacher/certificates?error=ไม่พบเกียรติบัตรนี้ หรือคุณไม่มีสิทธิ์');
    }

    res.render('teacher/edit-certificate', {
      layout: 'layouts/main', // หรือ layouts/teacher ถ้ามี
      title: 'แก้ไขเกียรติบัตร',
      certificate: rows[0],
      user: req.session.user, // ✅ ส่ง user ไปเสมอ
      activePage: 'certificates'
    });
  } catch (err) {
    console.error('❌ โหลดฟอร์มแก้ไขเกียรติบัตร (ครู) ล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/main',
      title: 'ข้อผิดพลาด',
      message: 'ไม่สามารถโหลดข้อมูลได้',
      user: req.session.user // ✅ ส่ง user ไปเสมอ
    });
  }
});

// ================================
// TEACHER: บันทึกการแก้ไข (POST)
// ================================
app.post('/teacher/certificates/edit/:id', requireLogin, requireTeacher, uploadCertificate.single('certificate'), async (req, res) => {
try {
  const { id } = req.params;
  // ✅ ลบ certificate_number ออกจากตัวแปร
  const { title, issuing_agency, description, issue_date } = req.body;
  const userId = req.session.user.id;

  // ✅ แก้ไขการตรวจสอบ: ไม่ต้องการ certificate_number
  if (!title?.trim() || !issuing_agency?.trim()) {
    return res.render('teacher/edit-certificate', {
      layout: 'layouts/main',
      title: 'แก้ไขเกียรติบัตร',
      certificate: { ...req.body, id },
      user: req.session.user,
      error: 'กรุณากรอก "ชื่อเกียรติบัตร" และ "หน่วยงานผู้มอบ" ให้ครบ',
      activePage: 'certificates'
    });
  }

  // ✅ ตรวจสอบสิทธิ์การเข้าถึง
  const [existingRows] = await db.execute('SELECT file_path FROM certificates WHERE id = ? AND user_id = ?', [id, userId]);
  if (existingRows.length === 0) {
    return res.redirect('/teacher/certificates?error=ไม่พบเกียรติบัตรนี้');
  }

  // ✅ จัดการไฟล์
  let filePath = existingRows[0].file_path;
  if (req.file) {
    filePath = `/uploads/${req.file.filename}`;
  }

  // ✅ ลบ certificate_number ออกจากคำสั่ง UPDATE
  await db.execute(
    `UPDATE certificates
     SET title = ?, issuing_agency = ?, description = ?, file_path = ?, issue_date = ?
     WHERE id = ? AND user_id = ?`,
    [
      title.trim(),
      issuing_agency.trim(),
      description?.trim() || null,
      filePath,
      issue_date || null,
      id,
      userId
    ]
  );

  res.redirect('/teacher/certificates?success=แก้ไขข้อมูลเกียรติบัตรเรียบร้อยแล้ว');
} catch (err) {
  console.error('❌ บันทึกการแก้ไขเกียรติบัตร (ครู) ล้มเหลว:', err);
  res.render('teacher/edit-certificate', {
    layout: 'layouts/main',
    title: 'แก้ไขเกียรติบัตร',
    certificate: req.body,
    user: req.session.user,
    error: 'เกิดข้อผิดพลาด กรุณาลองใหม่',
    activePage: 'certificates'
  });
}
});
// ================================
// TEACHER: ลบเกียรติบัตร
// ================================
app.post('/teacher/certificates/delete/:id', requireLogin, requireTeacher, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.session.user.id;

    const [rows] = await db.execute('SELECT id FROM certificates WHERE id = ? AND user_id = ?', [id, userId]);
    if (rows.length === 0) {
      return res.redirect('/teacher/certificates?error=ไม่พบเกียรติบัตรนี้ หรือคุณไม่มีสิทธิ์');
    }

    await db.execute('DELETE FROM certificates WHERE id = ? AND user_id = ?', [id, userId]);
    res.redirect('/teacher/certificates?success=ลบเกียรติบัตรเรียบร้อยแล้ว');

  } catch (err) {
    console.error('❌ ลบเกียรติบัตรล้มเหลว:', err);
    res.redirect('/teacher/certificates?error=เกิดข้อผิดพลาด กรุณาลองใหม่');
  }
});
app.get('/teacher/profile', requireLogin, requireTeacher, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    const teacher = rows[0] || req.session.user;
    res.render('teacher/profile', {
      layout: 'layouts/main',
      title: 'โปรไฟล์ของฉัน',
      user: teacher,
      activePage: 'profile'
    });
  } catch (err) {
    console.error('❌ Error loading profile:', err);
    res.status(500).render('error', {
      layout: 'layouts/main',
      title: 'เกิดข้อผิดพลาด',
      message: 'ไม่สามารถโหลดข้อมูลโปรไฟล์ได้'
    });
  }
});

app.post('/teacher/profile/update', requireLogin, requireTeacher, async (req, res) => {
  try {
    const { full_name, email, phone, position, subject, district, school_name } = req.body;
    const userId = req.session.user?.id;
    if (!userId) return res.redirect('/login');
    if (!full_name?.trim() || !email?.trim() || !phone?.trim()) {
      return res.render('teacher/profile', {
        layout: 'layouts/main',
        user: req.session.user,
        error: 'กรุณากรอก ชื่อ-นามสกุล, อีเมล และเบอร์โทรศัพท์ ให้ครบถ้วน'
      });
    }
    const allowedDistricts = ['โคกโพธิ์ไชย', 'ชนบท', 'บ้านไผ่', 'บ้านแฮด', 'เปือยน้อย', 'มัญจาคีรี'];
    if (district && !allowedDistricts.includes(district)) {
      return res.render('teacher/profile', {
        layout: 'layouts/main',
        user: req.session.user,
        error: 'อำเภอที่เลือกไม่อยู่ในรายการที่อนุญาต'
      });
    }
    const [result] = await db.execute(
      `UPDATE users 
       SET full_name = ?, email = ?, phone = ?, position = ?, subject = ?, district = ?, school_name = ?
       WHERE id = ?`,
      [full_name.trim(), email.trim(), phone.trim(), position || null, subject || null, district || null, school_name || null, userId]
    );
    if (result.affectedRows === 0) {
      return res.render('teacher/profile', {
        layout: 'layouts/main',
        user: req.session.user,
        error: 'ไม่พบผู้ใช้งานนี้ในระบบ'
      });
    }
    const [rows] = await db.execute(`SELECT * FROM users WHERE id = ?`, [userId]);
    const updatedUser = rows[0];
    req.session.user = updatedUser;
    res.render('teacher/profile', {
      layout: 'layouts/main',
      user: updatedUser,
      success: 'บันทึกข้อมูลเรียบร้อยแล้ว',
      activePage: 'profile'
    });
  } catch (error) {
    console.error('❌ Error updating profile:', error);
    res.render('teacher/profile', {
      layout: 'layouts/main',
      user: req.session.user || null,
      error: 'ไม่สามารถบันทึกข้อมูลได้ กรุณาลองใหม่ภายหลัง',
      activePage: 'profile'
    });
  }
});


// ========================
// ตรวจสิทธิ์บุคลากร (Personnel)
// ========================
function requirePersonnel(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'personnel') {
    return res.redirect('/login?error=คุณไม่มีสิทธิ์เข้าถึงหน้านี้');
  }
  next();
}




// ========================
// Routes สำหรับบุคลากร — ✅ แก้ไขให้ตำแหน่งบันทึกและแสดงได้จริง
// ========================

// 🔹 อนุญาตให้เข้าถึงไฟล์ใน public/uploads
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

// 🔹 โฟลเดอร์เกียรติบัตร
const CERT_UPLOAD_DIR = path.join(__dirname, 'public', 'uploads', 'certificates');
if (!fs.existsSync(CERT_UPLOAD_DIR)) {
  fs.mkdirSync(CERT_UPLOAD_DIR, { recursive: true });
}

// 🔹 โฟลเดอร์โปรไฟล์
const PROFILE_UPLOAD_DIR = path.join(__dirname, 'public', 'uploads', 'profiles');
if (!fs.existsSync(PROFILE_UPLOAD_DIR)) {
  fs.mkdirSync(PROFILE_UPLOAD_DIR, { recursive: true });
}


// 🔹 multer สำหรับโปรไฟล์
const uploadProfileImage = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, PROFILE_UPLOAD_DIR);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `staff_${req.session.user.id}${ext}`);
    }
  }),
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('เฉพาะไฟล์ JPG และ PNG เท่านั้น'));
    }
  },
  limits: { fileSize: 2 * 1024 * 1024 } // 2 MB
});

// ========================
// DASHBOARD
// ========================
app.get('/staff', requireLogin, requireStaff, async (req, res) => {
  try {
    const [userResults] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    if (userResults.length === 0) {
      req.session.destroy(() => {});
      return res.redirect('/login?error=ไม่พบข้อมูลผู้ใช้');
    }
    const user = userResults[0];
    const [certResults] = await db.execute('SELECT * FROM certificates WHERE user_id = ? ORDER BY upload_date DESC', [user.id]);
    res.render('staff/dashboard', {
      layout: 'layouts/staff',
      title: 'แดชบอร์ดบุคลากร',
      user: user,
      certificates: certResults,
      certificatesCount: certResults.length,
      activePage: 'dashboard'
    });
  } catch (err) {
    console.error('❌ โหลดแดชบอร์ดบุคลากรล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/staff',
      title: 'ข้อผิดพลาด',
      message: 'เกิดข้อผิดพลาดขณะโหลดแดชบอร์ด'
    });
  }
});

// ==============================
// 📌 หน้ารายการเกียรติบัตร (GET)
// ==============================
app.get('/staff/certificates', requireLogin, requireStaff, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const [certificates] = await db.execute(
      'SELECT * FROM certificates WHERE user_id = ? ORDER BY issue_date DESC, upload_date DESC',
      [userId]
    );
    res.render('staff/certificates', {
      layout: 'layouts/staff',
      title: 'รายการเกียรติบัตร',
      certificates: certificates,
      success: req.query.success,
      error: req.query.error,
      activePage: 'certificates'
    });
  } catch (err) {
    console.error('❌ โหลดรายการเกียรติบัตรล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/staff',
      title: 'ข้อผิดพลาด',
      message: 'ไม่สามารถโหลดรายการเกียรติบัตรได้'
    });
  }
});

// 🔹 แสดงฟอร์มอัปโหลดบุคลากร (GET)
app.get('/staff/upload', requireLogin, requireStaff, async (req, res) => {
  try {
    const [userResults] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    if (userResults.length === 0) return res.redirect('/login?error=ไม่พบข้อมูลผู้ใช้');
    const user = userResults[0];
    res.render('staff/upload', {
      layout: 'layouts/staff',
      title: 'อัปโหลดเกียรติบัตร',
      user: user,
      activePage: 'upload',
      error: null,
      success: null
    });
  } catch (err) {
    console.error('❌ โหลดหน้าอัปโหลดบุคลากรไม่ได้:', err);
    res.status(500).render('error', {
      layout: 'layouts/staff',
      title: 'ข้อผิดพลาด',
      message: 'เกิดข้อผิดพลาดขณะโหลดหน้าอัปโหลด'
    });
  }
});

// 🔹 อัปโหลดเกียรติบัตรบุคลากร (POST)
app.post('/staff/upload', requireLogin, requireStaff, uploadCertificate.single('certificate'), async (req, res) => {
  // ✅ ลบ certificate_number ออกจากตัวแปรและตรวจสอบ
  const { title, issuing_agency, description, issue_date } = req.body;

  // ✅ ลบการตรวจสอบรูปแบบหมายเลขเกียรติบัตร
  
  // ✅ แก้ไขการตรวจสอบ: ไม่ต้องการ certificate_number
  if (!title?.trim() || !issuing_agency?.trim()) {
    return res.render('staff/upload', {
      layout: 'layouts/staff',
      title: 'อัปโหลดเกียรติบัตร',
      error: 'กรุณากรอก "ชื่อเกียรติบัตร" และ "หน่วยงานผู้มอบ" ให้ครบถ้วน',
      success: null,
      activePage: 'upload'
    });
  }

  if (!req.file) {
    return res.render('staff/upload', {
      layout: 'layouts/staff',
      title: 'อัปโหลดเกียรติบัตร',
      error: 'กรุณาอัปโหลดไฟล์เกียรติบัตร',
      success: null,
      activePage: 'upload'
    });
  }

  try {
    const filePath = `/uploads/${req.file.filename}`;
    
    // ✅ ลบ certificate_number ออกจากคำสั่ง INSERT
    await db.execute(
      `INSERT INTO certificates 
       (user_id, title, issuing_agency, description, file_path, issue_date, upload_date)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [
        req.session.user.id,
        title.trim(),
        issuing_agency.trim(),
        description?.trim() || null,
        filePath,
        issue_date || null
      ]
    );
    
    res.redirect('/staff/certificates?success=✅ อัปโหลดเกียรติบัตรสำเร็จ!');
  } catch (err) {
    console.error('❌ อัปโหลดล้มเหลว:', err);
    if (req.file?.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.render('staff/upload', {
      layout: 'layouts/staff',
      title: 'อัปโหลดเกียรติบัตร',
      error: 'เกิดข้อผิดพลาดขณะบันทึกข้อมูล กรุณาลองใหม่',
      success: null,
      activePage: 'upload'
    });
  }
});

// ==============================
// 📌 แก้ไขเกียรติบัตร (POST) - บุคลากร
// ==============================
app.post('/staff/certificates/edit/:id', requireLogin, requireStaff, uploadCertificate.single('certificate'), async (req, res) => {
try {
  const { id } = req.params;
  // ✅ ลบ certificate_number ออกจากตัวแปร
  const { title, issuing_agency, description, issue_date } = req.body;
  const userId = req.session.user.id;

  // ✅ แก้ไขการตรวจสอบ: ไม่ต้องการ certificate_number
  if (!title?.trim() || !issuing_agency?.trim()) {
    const [existing] = await db.execute('SELECT * FROM certificates WHERE id = ? AND user_id = ?', [id, userId]);
    if (existing.length === 0) {
      return res.redirect('/staff/certificates?error=ไม่พบเกียรติบัตร');
    }
    return res.render('staff/edit-certificate', {
      layout: 'layouts/staff',
      title: 'แก้ไขเกียรติบัตร',
      certificate: { ...existing[0], ...req.body },
      error: 'กรุณากรอก "ชื่อเกียรติบัตร" และ "หน่วยงานผู้มอบ" ให้ครบถ้วน',
      activePage: 'certificates'
    });
  }

  const [existingRows] = await db.execute('SELECT file_path FROM certificates WHERE id = ? AND user_id = ?', [id, userId]);
  if (existingRows.length === 0) {
    return res.redirect('/staff/certificates?error=ไม่พบเกียรติบัตร');
  }

  let filePath = existingRows[0].file_path;
  if (req.file) {
    // ลบไฟล์เก่า
    const oldPath = path.join(__dirname, 'public', filePath);
    if (fs.existsSync(oldPath)) {
      fs.unlinkSync(oldPath);
    }
    filePath = `/uploads/${req.file.filename}`; // ✅ เพิ่ม /uploads/ ให้ถูกต้อง
  }

  // ✅ ลบ certificate_number ออกจากคำสั่ง UPDATE
  await db.execute(
    `UPDATE certificates
     SET title = ?, issuing_agency = ?, description = ?, file_path = ?, issue_date = ?
     WHERE id = ? AND user_id = ?`,
    [
      title.trim(),
      issuing_agency.trim(),
      description?.trim() || null,
      filePath,
      issue_date || null,
      id,
      userId
    ]
  );

  res.redirect('/staff/certificates?success=แก้ไขข้อมูลเกียรติบัตรเรียบร้อยแล้ว');
} catch (err) {
  console.error('❌ บันทึกการแก้ไขล้มเหลว:', err);
  if (req.file?.path && fs.existsSync(req.file.path)) {
    fs.unlinkSync(req.file.path);
  }
  const [existing] = await db.execute('SELECT * FROM certificates WHERE id = ? AND user_id = ?', [req.params.id, req.session.user.id]);
  res.render('staff/edit-certificate', {
    layout: 'layouts/staff',
    title: 'แก้ไขเกียรติบัตร',
    certificate: existing[0] || { id: req.params.id, ...req.body },
    error: 'เกิดข้อผิดพลาด กรุณาลองใหม่',
    activePage: 'certificates'
  });
}
});

// ==============================
// 📌 โปรไฟล์
// ==============================
app.get('/staff/profile', requireLogin, requireStaff, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [req.session.user.id]);
    if (rows.length === 0) {
      return res.redirect('/login?error=ไม่พบข้อมูลผู้ใช้');
    }
    const user = rows[0];
    res.render('staff/profile', {
      layout: 'layouts/staff',
      title: 'โปรไฟล์ของฉัน',
      user: user,
      success: req.query.success,
      error: req.query.error,
      activePage: 'profile'
    });
  } catch (err) {
    console.error('❌ โหลดโปรไฟล์ล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/staff',
      message: 'ไม่สามารถโหลดข้อมูลได้'
    });
  }
});

app.post('/staff/profile/upload-image', requireLogin, requireStaff, uploadProfileImage.single('profile_image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'กรุณาเลือกไฟล์รูปภาพ' });
    }

    const userId = req.session.user.id;
    const [userRows] = await db.execute('SELECT image_path FROM users WHERE id = ?', [userId]);
    if (userRows.length === 0) {
      return res.status(404).json({ error: 'ไม่พบผู้ใช้' });
    }

    const oldImagePath = userRows[0].image_path;
    if (oldImagePath && oldImagePath.startsWith('/uploads/profiles/')) {
      const oldFilePath = path.join(__dirname, 'public', oldImagePath);
      if (fs.existsSync(oldFilePath)) {
        fs.unlinkSync(oldFilePath);
      }
    }

    const newImagePath = `/uploads/profiles/staff_${userId}${path.extname(req.file.originalname)}`;
    await db.execute('UPDATE users SET image_path = ? WHERE id = ?', [newImagePath, userId]);

    const [updatedUser] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (updatedUser[0]) {
      req.session.user = updatedUser[0];
    }

    return res.json({ success: true, imagePath: newImagePath });
  } catch (err) {
    console.error('❌ อัปโหลดรูปภาพล้มเหลว:', err);
    if (req.file?.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    return res.status(500).json({ error: 'เกิดข้อผิดพลาดในการอัปโหลดรูปภาพ' });
  }
});

app.post('/staff/profile/update', requireLogin, requireStaff, async (req, res) => {
  try {
    const { full_name, email, phone, position } = req.body;
    const userId = req.session.user.id;

    if (!full_name?.trim() || !email?.trim() || !phone?.trim() || !position?.trim()) {
      return res.redirect('/staff/profile?error=กรุณากรอกข้อมูลให้ครบถ้วน');
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.redirect('/staff/profile?error=รูปแบบอีเมลไม่ถูกต้อง');
    }

    await db.execute(
      'UPDATE users SET full_name = ?, email = ?, phone = ?, position = ? WHERE id = ?',
      [full_name.trim(), email.trim(), phone.trim(), position.trim(), userId]
    );

    req.session.user.full_name = full_name.trim();
    req.session.user.email = email.trim();
    req.session.user.phone = phone.trim();
    req.session.user.position = position.trim();

    res.redirect('/staff/profile?success=บันทึกข้อมูลเรียบร้อยแล้ว');
  } catch (err) {
    console.error('❌ บันทึกข้อมูลล้มเหลว:', err);
    res.redirect('/staff/profile?error=เกิดข้อผิดพลาด กรุณาลองใหม่');
  }
});
// 🔹 แสดงแดชบอร์ดผู้ดูแลระบบ
app.get('/admin/dashboard', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [teacherRows] = await db.execute('SELECT COUNT(*) AS count FROM users WHERE role = "teacher"');
    const [staffRows] = await db.execute('SELECT COUNT(*) AS count FROM users WHERE role = "staff"');
    const [certRows] = await db.execute('SELECT COUNT(*) AS count FROM certificates');
    const [districtRows] = await db.execute(`
      SELECT COUNT(DISTINCT district) AS count 
      FROM users 
      WHERE role IN ('teacher', 'staff') 
        AND district IS NOT NULL 
        AND district != ''
    `);
    const [latestCertRows] = await db.execute(`
      SELECT c.id, c.title, c.issuing_agency, c.file_path, c.upload_date, 
             u.full_name, u.role
      FROM certificates c
      JOIN users u ON c.user_id = u.id
      ORDER BY c.upload_date DESC
      LIMIT 5
    `);
    const [topTeachersRows] = await db.execute(`
      SELECT u.full_name, u.school_name, COUNT(c.id) AS certificate_count
      FROM users u
      LEFT JOIN certificates c ON u.id = c.user_id
      WHERE u.role = 'teacher'
      GROUP BY u.id, u.full_name, u.school_name
      ORDER BY certificate_count DESC
      LIMIT 5
    `);
    const [topStaffsRows] = await db.execute(`
      SELECT u.full_name, u.school_name, COUNT(c.id) AS certificate_count
      FROM users u
      LEFT JOIN certificates c ON u.id = c.user_id
      WHERE u.role = 'staff'
      GROUP BY u.id, u.full_name, u.school_name
      ORDER BY certificate_count DESC
      LIMIT 5
    `);
    res.render('admin/dashboard', {
      layout: 'layouts/admin',
      title: 'แดชบอร์ดผู้ดูแลระบบ',
      activePage: 'dashboard',
      teacherCount: teacherRows[0].count || 0,
      staffCount: staffRows[0].count || 0,
      certificateCount: certRows[0].count || 0,
      districtCount: districtRows[0].count || 0,
      latestCertificates: latestCertRows || [],
      topTeachers: topTeachersRows || [],
      topStaffs: topStaffsRows || []
    });
  } catch (err) {
    console.error('❌ โหลดแดชบอร์ดล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/admin',
      title: 'ข้อผิดพลาด',
      message: 'ไม่สามารถโหลดแดชบอร์ดได้: ' + err.message
    });
  }
});

// 🔹 GET /admin/teachers — แสดงรายการครู (ไม่ใช้ CSRF เพราะไม่มีฟอร์มส่งข้อมูล)
app.get('/admin/teachers', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [teachers] = await db.execute(`
      SELECT u.id, u.full_name, u.email, u.phone, u.position, u.subject,
             u.district, u.school_name, u.image_path,
             COUNT(c.id) AS certificate_count
      FROM users u
      LEFT JOIN certificates c ON u.id = c.user_id
      WHERE u.role = 'teacher'
      GROUP BY u.id
      ORDER BY u.full_name ASC
    `);
    res.render('admin/teachers', {
      layout: 'layouts/admin',
      title: 'จัดการครู',
      activePage: 'teachers',
      teachers: teachers
      // ✅ ไม่มี csrfToken
    });
  } catch (err) {
    console.error('❌ โหลดรายชื่อครูล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/admin',
      title: 'ข้อผิดพลาด',
      message: 'โหลดข้อมูลไม่สำเร็จ',
      user: req.session.user
    });
  }
});
// 🔹 ดูรายละเอียดครู
app.get('/admin/teachers/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    // ดึงข้อมูลครู
    const [teacherRows] = await db.execute(`
      SELECT u.id, u.full_name, u.email, u.phone, u.position, u.subject,
             u.district, u.school_name, u.image_path
      FROM users u
      WHERE u.id = ? AND u.role = 'teacher'
    `, [id]);

    if (teacherRows.length === 0) {
      return res.status(404).render('error', {
        layout: 'layouts/admin',
        title: 'ไม่พบข้อมูล',
        message: 'ไม่พบข้อมูลครูนี้',
        user: req.session.user
      });
    }

    const teacher = teacherRows[0];

    // ดึงเกียรติบัตร
    const [certRows] = await db.execute(`
      SELECT id, certificate_number, title, issuing_agency, description, file_path, 
             DATE_FORMAT(issue_date, '%d %M %Y') as issue_date,
             DATE_FORMAT(upload_date, '%d %M %Y') as upload_date
      FROM certificates
      WHERE user_id = ?
      ORDER BY upload_date DESC
    `, [id]);

    res.render('admin/teacher-detail', {
      layout: 'layouts/admin',
      title: `รายละเอียดครู: ${teacher.full_name}`,
      activePage: 'teachers',
      teacher,
      certificates: certRows
    });
  } catch (err) {
    console.error('❌ โหลดรายละเอียดครูล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/admin',
      title: 'ข้อผิดพลาด',
      message: 'ไม่สามารถโหลดข้อมูลได้',
      user: req.session.user
    });
  }
});


// 🔹 แสดงฟอร์มแก้ไขครู (รวมรูปภาพ)
app.get('/admin/teachers/:id/edit', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const [teachers] = await pool.execute(
      `SELECT user_id, full_name, email, phone, subject, district, school_name, profile_image
       FROM users WHERE user_id = ? AND role = 'teacher'`,
      [id]
    );

    if (teachers.length === 0) {
      req.flash('error', 'ไม่พบข้อมูลครูนี้');
      return res.redirect('/admin/teachers');
    }

    res.render('admin/teacher-edit', {
      title: `แก้ไขครู: ${teachers[0].full_name}`,
      teacher: teachers[0]
    });
  } catch (err) {
    console.error('❌ โหลดฟอร์มแก้ไขล้มเหลว:', err);
    req.flash('error', 'ไม่สามารถโหลดข้อมูลได้');
    res.redirect('/admin/teachers');
  }
});

// 🔹 บันทึกการแก้ไขข้อมูลครู + รูปภาพ
app.post('/admin/teachers/:id/edit', requireLogin, requireAdmin, upload.single('profile_image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, email, phone, subject, district, school_name } = req.body;

    if (!full_name || !email) {
      req.flash('error', 'กรุณากรอกชื่อและอีเมล');
      return res.redirect(`/admin/teachers/${id}/edit`);
    }

    // เริ่ม transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      let profile_image = null;

      // ถ้ามีอัปโหลดรูปใหม่
      if (req.file) {
        profile_image = req.file.filename;
      }

      // อัปเดตข้อมูล
      const sql = profile_image
        ? `UPDATE users SET full_name = ?, email = ?, phone = ?, subject = ?, district = ?, school_name = ?, profile_image = ? WHERE user_id = ? AND role = 'teacher'`
        : `UPDATE users SET full_name = ?, email = ?, phone = ?, subject = ?, district = ?, school_name = ? WHERE user_id = ? AND role = 'teacher'`;

      const params = profile_image
        ? [full_name, email, phone, subject, district, school_name, profile_image, id]
        : [full_name, email, phone, subject, district, school_name, id];

      const [result] = await connection.execute(sql, params);

      if (result.affectedRows === 0) {
        throw new Error('ไม่พบข้อมูลครูนี้');
      }

      await connection.commit();
      req.flash('success', 'บันทึกข้อมูลเรียบร้อยแล้ว');
      res.redirect('/admin/teachers');
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (err) {
    console.error('❌ บันทึกข้อมูลล้มเหลว:', err);
    req.flash('error', 'เกิดข้อผิดพลาด กรุณาลองใหม่');
    res.redirect(`/admin/teachers/${id}/edit`);
  }
});

// 🔹 ลบครู (ลบเกียรติบัตรด้วย)
app.delete('/admin/teachers/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // ตรวจสอบว่าเป็นตัวเลข
    if (!/^\d+$/.test(id)) {
      req.flash('error', 'ID ไม่ถูกต้อง');
      return res.redirect('/admin/teachers');
    }

    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // ตรวจสอบว่าเป็นครูจริง
      const [userCheck] = await connection.execute(
        'SELECT full_name FROM users WHERE user_id = ? AND role = "teacher"',
        [id]
      );
      if (userCheck.length === 0) {
        throw new Error('ไม่พบข้อมูลครูนี้');
      }

      // ลบเกียรติบัตรก่อน
      await connection.execute('DELETE FROM certificates WHERE user_id = ?', [id]);
      // ลบผู้ใช้
      const [deleteResult] = await connection.execute('DELETE FROM users WHERE user_id = ?', [id]);

      if (deleteResult.affectedRows === 0) {
        throw new Error('ไม่สามารถลบข้อมูลได้');
      }

      await connection.commit();
      req.flash('success', `ลบครู "${userCheck[0].full_name}" เรียบร้อยแล้ว`);
      res.redirect('/admin/teachers');
    } catch (err) {
      await connection.rollback();
      console.error('❌ ลบครูล้มเหลว:', err);
      
      if (err.message.includes('ไม่พบ')) {
        req.flash('error', err.message);
      } else if (err.code === 'ER_ROW_IS_REFERENCED_2') {
        req.flash('error', 'ไม่สามารถลบได้ เนื่องจากมีข้อมูลอ้างอิงอยู่');
      } else {
        req.flash('error', 'เกิดข้อผิดพลาดขณะลบข้อมูล');
      }
      res.redirect('/admin/teachers');
    } finally {
      connection.release();
    }
  } catch (err) {
    console.error('❌ ข้อผิดพลาดระบบ:', err);
    req.flash('error', 'เกิดข้อผิดพลาดระบบ');
    res.redirect('/admin/teachers');
  }
});
// 🔹 ออกจากระบบ
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('❌ ล้างเซสชันล้มเหลว:', err);
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});
// ==============================
// 📌 จัดการบุคลากร (role = 'staff')
// ==============================
app.get('/admin/staffs', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { q } = req.query;
    let staffs = [];
    if (q) {
      const [rows] = await db.execute(`
        SELECT u.*,
               (SELECT COUNT(*) FROM certificates WHERE user_id = u.id) AS certificate_count
        FROM users u
        WHERE u.role = 'staff'
          AND (u.full_name LIKE ? OR u.email LIKE ? OR u.school_name LIKE ?)
        ORDER BY u.full_name ASC
      `, [`%${q}%`, `%${q}%`, `%${q}%`]);
      staffs = rows;
    } else {
      const [rows] = await db.execute(`
        SELECT u.*,
               (SELECT COUNT(*) FROM certificates WHERE user_id = u.id) AS certificate_count
        FROM users u
        WHERE u.role = 'staff'
        ORDER BY u.full_name ASC
      `);
      staffs = rows;
    }
    res.render('admin/staffs/index', {
      layout: 'layouts/admin',
      title: 'จัดการบุคลากร',
      activePage: 'staffs',
      staffs,
      q: q || ''
    });
  } catch (err) {
    console.error('❌ โหลดบุคลากรล้มเหลว:', err);
    res.status(500).render('error', {
      layout: 'layouts/admin',
      message: 'เกิดข้อผิดพลาดขณะโหลดข้อมูลบุคลากร'
    });
  }
});

app.get('/admin/staffs/show/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ? AND role = "staff"', [req.params.id]);
    if (rows.length === 0) return res.status(404).send('ไม่พบบุคลากร');
    res.render('admin/staffs/show', { layout: 'layouts/admin', staff: rows[0], title: 'รายละเอียดบุคลากร', activePage: 'staffs' });
  } catch (err) {
    res.status(500).send('เกิดข้อผิดพลาด');
  }
});

app.get('/admin/staffs/edit/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ? AND role = "staff"', [req.params.id]);
    if (rows.length === 0) return res.status(404).send('ไม่พบบุคลากร');
    res.render('admin/staffs/edit', { layout: 'layouts/admin', staff: rows[0], title: 'แก้ไขบุคลากร', activePage: 'staffs' });
  } catch (err) {
    res.status(500).send('เกิดข้อผิดพลาด');
  }
});

app.post('/admin/staffs/edit/:id', requireLogin, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { full_name, email, phone, position, school_name } = req.body;
  try {
    await db.execute(
      `UPDATE users 
       SET full_name = ?, email = ?, phone = ?, position = ?, school_name = ?, updated_at = NOW()
       WHERE id = ? AND role = 'staff'`,
      [full_name.trim(), email.trim(), phone?.trim() || null, position?.trim() || null, school_name?.trim() || null, id]
    );
    res.redirect('/admin/staffs?success=แก้ไขข้อมูลบุคลากรเรียบร้อยแล้ว');
  } catch (err) {
    console.error('❌ แก้ไขล้มเหลว:', err);
    res.redirect('/admin/staffs?error=เกิดข้อผิดพลาด');
  }
});

app.post('/admin/staffs/delete/:id', requireLogin, requireAdmin, async (req, res) => {
  try {
    await db.execute('DELETE FROM certificates WHERE user_id = ?', [req.params.id]);
    await db.execute('DELETE FROM users WHERE id = ? AND role = "staff"', [req.params.id]);
    res.redirect('/admin/staffs?success=ลบบุคลากรเรียบร้อยแล้ว');
  } catch (err) {
    console.error('❌ ลบล้มเหลว:', err);
    res.redirect('/admin/staffs?error=เกิดข้อผิดพลาด');
  }
});

// 🔹 API: ดึงเกียรติบัตรของบุคลากร
app.get('/api/staff/:id/certificates', async (req, res) => {
  try {
    const staffId = req.params.id;
    console.log(`📋 ดึงเกียรติบัตรของบุคลากร ID: ${staffId}`);
    
    const [certs] = await db.execute(
      'SELECT id, certificate_number, title, issuing_organization, issue_date, upload_date, file_path FROM certificates WHERE user_id = ? ORDER BY issue_date DESC',
      [staffId]
    );
    
    console.log(`✅ พบเกียรติบัตร: ${certs?.length || 0} รายการ`);
    res.json(certs || []);
  } catch (err) {
    console.error('❌ โหลดเกียรติบัตรล้มเหลว:', err.message);
    res.status(500).json({ error: 'เกิดข้อผิดพลาดในการโหลดเกียรติบัตร: ' + err.message });
  }
});

// 🔹 แสดงรายการเกียรติบัตรทั้งหมด (สำหรับผู้ดูแลระบบ)
app.get('/admin/certificates', requireLogin, requireAdmin, async (req, res) => {
  try {
    // ✅ เพิ่ม u.role เพื่อแยกประเภทผู้ใช้
    const [certs] = await db.execute(`
      SELECT 
        c.*, 
        u.full_name, 
        u.school_name,
        u.role
      FROM certificates c
      JOIN users u ON c.user_id = u.id
      ORDER BY c.upload_date DESC
    `);

    res.render('admin/certificates', {
      layout: 'layouts/admin',
      title: 'จัดการเกียรติบัตร',
      activePage: 'certificates',
      certificates: certs
    });
  } catch (err) {
    console.error('❌ โหลดเกียรติบัตรล้มเหลว:', err);
    res.status(500).render('error', { 
      layout: 'layouts/admin', 
      message: 'ไม่สามารถโหลดข้อมูลเกียรติบัตรได้' 
    });
  }
});

app.get('/admin/districts', requireLogin, requireAdmin, async (req, res) => {
  try {
    const [totalTeachersResult] = await db.execute('SELECT COUNT(*) AS count FROM users WHERE role = "teacher"');
    const totalTeachers = totalTeachersResult[0]?.count || 0;
    const [rows] = await db.execute(`
      SELECT 
        district,
        COUNT(DISTINCT school_name) AS school_count,
        COUNT(*) AS total_count,
        COUNT(*) AS teacher_count
      FROM users 
      WHERE role = 'teacher'
        AND district IS NOT NULL 
        AND district != ''
        AND school_name IS NOT NULL 
        AND school_name != ''
      GROUP BY district
      ORDER BY district ASC
    `);
    const districts = (rows || []).map(row => ({
      name: row.district || 'ไม่ระบุ',
      schoolCount: row.school_count || 0,
      totalCount: row.total_count || 0,
      teacherCount: row.teacher_count || 0
    }));
    res.render('admin/districts', {
      layout: 'layouts/admin',
      title: 'จัดการอำเภอ',
      activePage: 'districts',
      districts,
      totalSchools: districts.reduce((sum, d) => sum + d.schoolCount, 0),
      totalUsers: districts.reduce((sum, d) => sum + d.totalCount, 0),
      totalTeachers
    });
  } catch (err) {
    console.error('❌ โหลดอำเภอไม่สำเร็จ:', err);
    res.status(500).render('error', { layout: 'layouts/admin', message: 'โหลดข้อมูลไม่สำเร็จ' });
  }
});

// ============================================
// หน้าประวัติการขอหมายเลขเกียรติบัตรทั้งหมด
// ============================================
app.get('/admin/certificate-history', requireLogin, requireAdmin, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    // ดึงข้อมูลผู้ใช้
    const [userRows] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    const user = userRows[0];
    
    if (!user || user.role !== 'admin') {
      return res.redirect('/login');
    }
    
    // ดึงสถิติ
    const [statsRows] = await db.execute(`
      SELECT 
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved_count,
        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_count,
        COUNT(*) as total_requests,
        (SELECT COUNT(*) FROM certificates WHERE status = 'active') as total_certificates
      FROM certificate_requests
    `);
    const stats = statsRows[0];
    
    // ดึงประวัติทั้งหมดพร้อมข้อมูลผู้อนุมัติและหมายเลขเกียรติบัตร
    const [requestsRows] = await db.execute(`
      SELECT 
        cr.*,
        u.full_name as requester_full_name,
        u.school_name,
        u.position_or_subject,
        admin.full_name as approver_name_display,
        GROUP_CONCAT(c.certificate_number SEPARATOR ', ') as certificate_numbers,
        COUNT(c.id) as generated_count
      FROM certificate_requests cr
      LEFT JOIN users u ON cr.user_id = u.id
      LEFT JOIN users admin ON cr.approved_by = admin.id
      LEFT JOIN certificates c ON cr.user_id = c.user_id AND cr.event_name = c.title
      GROUP BY cr.id
      ORDER BY cr.created_at DESC
    `);
    
    // จัดการข้อมูลให้ตรงกับ template
    const allRequests = requestsRows.map(req => ({
      ...req,
      full_name: req.requester_name || req.requester_full_name || '-',
      school_name: req.school_name || '-',
      approver_name: req.approver_name || req.approver_name_display || null,
      certificate_number: req.certificate_numbers || null,
      generated_count: req.generated_count || 0
    }));
    
    res.render('admin/certificate-history', {
      user,
      stats,
      allRequests,
      title: 'ประวัติการขอหมายเลขเกียรติบัตรทั้งหมด'
    });
    
  } catch (error) {
    console.error('❌ Error loading history:', error);
    res.render('admin/certificate-history', {
      error: 'เกิดข้อผิดพลาดในการโหลดข้อมูล: ' + error.message,
      user: req.session.user || {},
      stats: { 
        pending_count: 0, 
        approved_count: 0, 
        rejected_count: 0, 
        total_requests: 0,
        total_certificates: 0 
      },
      allRequests: [],
      title: 'ประวัติการขอหมายเลขเกียรติบัตรทั้งหมด'
    });
  }
});

// ============================================
// ดูรายละเอียดคำขอหมายเลขเกียรติบัตร
// ============================================
app.get('/admin/certificate-requests/:id/detail', requireLogin, requireAdmin, async (req, res) => {
  try {
    const requestId = req.params.id;
    
    // ดึงข้อมูลคำขอหมายเลขเกียรติบัตร
    const [requestRows] = await db.execute(`
      SELECT 
        cr.*,
        u.full_name as requester_full_name,
        u.school_name,
        u.position_or_subject,
        u.email,
        u.phone,
        admin.full_name as approver_full_name,
        GROUP_CONCAT(c.certificate_number SEPARATOR ', ') as certificate_numbers
      FROM certificate_requests cr
      LEFT JOIN users u ON cr.user_id = u.id
      LEFT JOIN users admin ON cr.approved_by = admin.id
      LEFT JOIN certificates c ON cr.user_id = c.user_id AND cr.event_name = c.title
      WHERE cr.id = ?
      GROUP BY cr.id
    `, [requestId]);
    
    if (requestRows.length === 0) {
      return res.status(404).send('<div class="alert alert-danger">ไม่พบข้อมูลคำขอในระบบ</div>');
    }
    
    const request = requestRows[0];
    const eventDate = new Date(request.event_date);
    const createdDate = new Date(request.created_at);
    const approvedDate = request.approved_at ? new Date(request.approved_at) : null;
    
    // สร้าง HTML สำหรับแสดงรายละเอียด
    let html = `
      <div class="detail-section">
        <div class="row mb-3">
          <div class="col-md-6">
            <h6 class="fw-bold text-muted mb-2">ชื่อผู้ขอ</h6>
            <p class="mb-0"><strong>${request.requester_full_name || request.requester_name || '-'}</strong></p>
          </div>
          <div class="col-md-6">
            <h6 class="fw-bold text-muted mb-2">สถานศึกษา</h6>
            <p class="mb-0"><strong>${request.school_name || '-'}</strong></p>
          </div>
        </div>
        
        <div class="row mb-3">
          <div class="col-md-6">
            <h6 class="fw-bold text-muted mb-2">เบอร์โทรศัพท์</h6>
            <p class="mb-0"><a href="tel:${request.phone}">${request.phone || '-'}</a></p>
          </div>
          <div class="col-md-6">
            <h6 class="fw-bold text-muted mb-2">อีเมล</h6>
            <p class="mb-0"><a href="mailto:${request.email}">${request.email || '-'}</a></p>
          </div>
        </div>
        
        <hr class="my-3">
        
        <div class="row mb-3">
          <div class="col-md-6">
            <h6 class="fw-bold text-muted mb-2">ชื่อโครงการ/กิจกรรม</h6>
            <p class="mb-0"><strong>${request.event_name || '-'}</strong></p>
          </div>
          <div class="col-md-6">
            <h6 class="fw-bold text-muted mb-2">ชื่อผู้ลงนาม</h6>
            <p class="mb-0"><strong>${request.signature_owner || '-'}</strong></p>
          </div>
        </div>
        
        <div class="row mb-3">
          <div class="col-md-4">
            <h6 class="fw-bold text-muted mb-2">จำนวนเกียรติบัตร</h6>
            <p class="mb-0"><strong class="badge bg-primary fs-6">${request.certificate_count || 0} ใบ</strong></p>
          </div>
          <div class="col-md-4">
            <h6 class="fw-bold text-muted mb-2">วันที่จัดงาน</h6>
            <p class="mb-0"><strong>${eventDate.toLocaleDateString('th-TH', { year: 'numeric', month: 'long', day: 'numeric' })}</strong></p>
          </div>
          <div class="col-md-4">
            <h6 class="fw-bold text-muted mb-2">วันที่ส่งคำขอ</h6>
            <p class="mb-0"><strong>${createdDate.toLocaleDateString('th-TH', { year: 'numeric', month: 'long', day: 'numeric' })}</strong></p>
          </div>
        </div>
        
        <div class="row mb-3">
          <div class="col-12">
            <h6 class="fw-bold text-muted mb-2">คำอธิบาย/หมายเหตุ</h6>
            <div class="p-2 bg-light rounded">
              <p class="mb-0"><small>${request.description || '-'}</small></p>
            </div>
          </div>
        </div>
        
        <hr class="my-3">
        
        <div class="row mb-3">
          <div class="col-12">
            <h6 class="fw-bold text-muted mb-2">สถานะคำขอ</h6>
            <p class="mb-0">
              ${request.status === 'pending' ? '<span class="badge bg-warning text-dark"><i class="fas fa-clock me-1"></i> รอตรวจสอบ</span>' : ''}
              ${request.status === 'approved' ? '<span class="badge bg-success"><i class="fas fa-check-circle me-1"></i> อนุมัติแล้ว</span>' : ''}
              ${request.status === 'rejected' ? '<span class="badge bg-danger"><i class="fas fa-times-circle me-1"></i> ปฏิเสธ</span>' : ''}
            </p>
          </div>
        </div>
        
        ${request.status === 'approved' ? `
          <div class="row mb-3">
            <div class="col-12">
              <h6 class="fw-bold text-muted mb-2">อนุมัติโดย</h6>
              <p class="mb-0"><strong>${request.approver_full_name || '-'}</strong></p>
              <small class="text-muted">
                <i class="fas fa-calendar me-1"></i>
                ${approvedDate ? approvedDate.toLocaleDateString('th-TH', { year: 'numeric', month: 'long', day: 'numeric' }) : '-'}
              </small>
            </div>
          </div>
        ` : ''}
        
        ${request.status === 'rejected' ? `
          <div class="row mb-3">
            <div class="col-12">
              <h6 class="fw-bold text-muted mb-2">เหตุผลการปฏิเสธ</h6>
              <div class="p-2 bg-danger bg-opacity-10 border border-danger rounded">
                <p class="mb-0 text-danger"><small>${request.rejection_reason || '-'}</small></p>
              </div>
            </div>
          </div>
        ` : ''}
      </div>
      
      <style>
        .detail-section h6 {
          color: #0d4a6b;
        }
        .detail-section p {
          color: #333;
        }
      </style>
    `;
    
    res.send(html);
    
  } catch (error) {
    console.error('❌ Error loading detail:', error);
    res.status(500).send(`<div class="alert alert-danger">เกิดข้อผิดพลาด: ${error.message}</div>`);
  }
});

// ============================================
// อนุมัติคำขอ
// ============================================
app.post('/admin/approve-request/:id', async (req, res) => {
  try {
    const requestId = req.params.id;
    const adminId = req.session.userId;
    
    // ดึงข้อมูลคำขอ
    const [requestRows] = await db.execute(
      'SELECT * FROM certificate_requests WHERE id = ? AND status = "pending"',
      [requestId]
    );
    
    if (requestRows.length === 0) {
      return res.json({ 
        success: false, 
        message: 'ไม่พบคำขอที่รอการอนุมัติ หรือคำขอนี้ได้รับการดำเนินการไปแล้ว' 
      });
    }
    
    const request = requestRows[0];
    
    // ดึงข้อมูลแอดมิน
    const [adminRows] = await db.execute('SELECT * FROM users WHERE id = ?', [adminId]);
    const admin = adminRows[0];
    
    // สร้างหมายเลขเกียรติบัตร
    const currentYear = new Date().getFullYear() + 543;
    const numbers = [];
    
    // ดึงหมายเลขล่าสุด
    const [lastNumRows] = await db.execute(`
      SELECT certificate_number 
      FROM certificates 
      WHERE certificate_number LIKE ? 
      ORDER BY id DESC 
      LIMIT 1
    `, [`%/${currentYear}`]);
    
    let lastNumber = lastNumRows.length > 0 ? 
      parseInt(lastNumRows[0].certificate_number.split('/')[0]) : 10000;
    
    // สร้างหมายเลขใหม่
    for (let i = 0; i < request.certificate_count; i++) {
      lastNumber++;
      const certNumber = `${lastNumber}/${currentYear}`;
      numbers.push(certNumber);
      
      // บันทึกหมายเลขลงฐานข้อมูล
      await db.execute(`
        INSERT INTO certificates 
        (user_id, certificate_number, title, issuing_agency, description, file_path, issue_date, upload_date, status) 
        VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), 'active')
      `, [
        request.user_id,
        certNumber,
        request.event_name,
        'สำนักงานเขตพื้นที่การศึกษาประถมศึกษาขอนแก่น เขต 2',
        request.description || `เกียรติบัตร ${request.event_name}`,
        '',
        request.event_date
      ]);
    }
    
    // อัปเดตสถานะคำขอ
    await db.execute(`
      UPDATE certificate_requests 
      SET status = 'approved', 
          approved_by = ?, 
          approved_at = NOW(),
          approver_name = ?
      WHERE id = ?
    `, [adminId, admin.full_name, requestId]);
    
    res.json({
      success: true,
      message: `✅ อนุมัติคำขอเรียบร้อยแล้ว สร้างหมายเลขเกียรติบัตร ${request.certificate_count} หมายเลข`,
      count: request.certificate_count,
      numbers: numbers.slice(0, 5) // แสดงแค่ 5 หมายเลขแรก
    });
    
  } catch (error) {
    console.error('❌ Error approving request:', error);
    res.json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาด: ' + error.message 
    });
  }
});

// ============================================
// ปฏิเสธคำขอ
// ============================================
app.post('/admin/reject-request/:id', async (req, res) => {
  try {
    const requestId = req.params.id;
    const { reason } = req.body;
    const adminId = req.session.userId;
    
    // ตรวจสอบคำขอ
    const [requestRows] = await db.execute(
      'SELECT * FROM certificate_requests WHERE id = ? AND status = "pending"',
      [requestId]
    );
    
    if (requestRows.length === 0) {
      return res.json({ 
        success: false, 
        message: 'ไม่พบคำขอที่รอการปฏิเสธ' 
      });
    }
    
    // อัปเดตสถานะเป็นปฏิเสธ
    await db.execute(`
      UPDATE certificate_requests 
      SET status = 'rejected', 
          rejection_reason = ?, 
          approved_by = ?, 
          approved_at = NOW()
      WHERE id = ?
    `, [reason, adminId, requestId]);
    
    res.json({
      success: true,
      message: 'ปฏิเสธคำขอเรียบร้อยแล้ว'
    });
    
  } catch (error) {
    console.error('❌ Error rejecting request:', error);
    res.json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาด: ' + error.message 
    });
  }
});
// ============================================
// ปฏิเสธคำขอ
// ============================================
app.post('/admin/reject-request/:id', async (req, res) => {
  try {
    const requestId = req.params.id;
    const { reason } = req.body;
    const adminId = req.session.userId;
    
    // ตรวจสอบคำขอ
    const [requestRows] = await db.execute(
      'SELECT * FROM certificate_requests WHERE id = ? AND status = "pending"',
      [requestId]
    );
    
    if (requestRows.length === 0) {
      return res.json({ 
        success: false, 
        message: 'ไม่พบคำขอที่รอการปฏิเสธ' 
      });
    }
    
    // อัปเดตสถานะเป็นปฏิเสธ
    await db.execute(`
      UPDATE certificate_requests 
      SET status = 'rejected', 
          rejection_reason = ?, 
          approved_by = ?, 
          approved_at = NOW()
      WHERE id = ?
    `, [reason, adminId, requestId]);
    
    res.json({
      success: true,
      message: 'ปฏิเสธคำขอเรียบร้อยแล้ว'
    });
    
  } catch (error) {
    console.error('❌ Error rejecting request:', error);
    res.json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาด: ' + error.message 
    });
  }
});
app.get('/admin/districts/:districtName', requireLogin, requireAdmin, async (req, res) => {
  try {
    const { districtName } = req.params;
    let decodedDistrict = '';
    try {
      decodedDistrict = decodeURIComponent(districtName).trim();
    } catch (e) {
      return res.status(404).render('error', {
        layout: 'layouts/admin',
        title: 'ไม่พบอำเภอ',
        message: 'รูปแบบลิงก์ไม่ถูกต้อง',
        user: req.session.user
      });
    }
    const allowedDistricts = ['โคกโพธิ์ไชย', 'ชนบท', 'บ้านไผ่', 'บ้านแฮด', 'เปือยน้อย', 'มัญจาคีรี'];
    const matchedDistrict = allowedDistricts.find(d => d === decodedDistrict);
    if (!matchedDistrict) {
      return res.status(404).render('error', {
        layout: 'layouts/admin',
        title: 'ไม่พบอำเภอ',
        message: `ไม่พบอำเภอ "${decodedDistrict}" ในระบบ`,
        user: req.session.user
      });
    }
    const finalDistrict = matchedDistrict;
    const [schoolRows] = await db.execute(`
      SELECT 
        school_name,
        COUNT(*) AS total_count
      FROM users 
      WHERE district = ? AND role = 'teacher'
        AND school_name IS NOT NULL AND TRIM(school_name) != ''
      GROUP BY school_name
      ORDER BY school_name ASC
    `, [finalDistrict]);
    const [userRows] = await db.execute(`
      SELECT id, full_name, email, phone, position, subject, school_name
      FROM users 
      WHERE district = ? AND role = 'teacher'
        AND school_name IS NOT NULL AND TRIM(school_name) != ''
      ORDER BY school_name ASC, full_name ASC
    `, [finalDistrict]);
    res.render('admin/district-detail', {
      layout: 'layouts/main',
      title: `รายละเอียดอำเภอ ${finalDistrict}`,
      activePage: 'districts',
      district: finalDistrict,
      schools: schoolRows,
      users: userRows,
      totalSchools: schoolRows.length,
      totalUsers: userRows.length
    });
  } catch (err) {
    console.error('❌ โหลดรายละเอียดอำเภอไม่สำเร็จ:', err);
    res.status(500).render('error', {
      layout: 'layouts/admin',
      title: 'ข้อผิดพลาด',
      message: 'ไม่สามารถโหลดข้อมูลอำเภอได้ในขณะนี้',
      user: req.session.user
    });
  }
});


app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('❌ ล้างเซสชันล้มเหลว:', err);
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
  });
});

// ========================================
// Routes ระบบขอหมายเลขเกียรติบัตร
// ========================================
const certificateRequestRoutes = require('./routes/certificateRequest');
app.use('/', certificateRequestRoutes);

// ========================================
// Super Admin Routes
// ========================================
const superadminRoutes = require('./routes/superadmin');
app.use('/superadmin', superadminRoutes);

// ========================================
// ✅ API: Certificate Validation & Approval (Phase 2 & 3)
// ========================================
const { router: validationRouter } = require('./routes/certificate-validation-api');
app.use('/api/certificates', validationRouter);

// ========================================
// Admin Routes: Certificate Approval Dashboard
// ========================================
app.get('/admin/certificate-approval', requireAdmin, async (req, res) => {
  try {
    const [pendingCerts] = await req.db.execute(
      `SELECT c.*, u.full_name, u.school_name, u.email
       FROM certificates c
       JOIN users u ON c.user_id = u.id
       WHERE c.status = 'pending'
       ORDER BY c.upload_date DESC`
    );

    const [approvedCerts] = await req.db.execute(
      `SELECT c.*, u.full_name, u.school_name
       FROM certificates c
       JOIN users u ON c.user_id = u.id
       WHERE c.status = 'approved'
       ORDER BY c.approval_date DESC`
    );

    const [rejectedCerts] = await req.db.execute(
      `SELECT c.*, u.full_name, u.school_name
       FROM certificates c
       JOIN users u ON c.user_id = u.id
       WHERE c.status = 'rejected'
       ORDER BY c.approval_date DESC`
    );

    res.render('admin/certificate-approval', {
      layout: 'layouts/admin',
      user: req.session.user,
      baseUrl: process.env.BASE_URL || '',
      pending_certificates: pendingCerts,
      approved_certificates: approvedCerts,
      rejected_certificates: rejectedCerts,
      pending_count: pendingCerts.length,
      approved_count: approvedCerts.length,
      rejected_count: rejectedCerts.length,
      activeTab: 'pending'
    });
  } catch (error) {
    console.error('Error loading certificate approval page:', error);
    res.status(500).send('เกิดข้อผิดพลาด: ' + error.message);
  }
});

// ========================
// Error & Server
// ========================
// Debug route to inspect response CSP header
app.get('/__debug_headers', (req, res) => {
  const csp = res.getHeader('Content-Security-Policy') || null;
  res.json({ csp, now: new Date().toISOString() });
});

app.use((req, res) => {
  res.status(404).render('error', { layout: 'layouts/main', message: 'ไม่พบหน้านี้' });
});

app.use((err, req, res, next) => {
  console.error('🚨 Error:', err);
  res.status(500).render('error', { layout: 'layouts/main', message: 'เกิดข้อผิดพลาดภายในระบบ' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ ระบบทำงานที่ http://localhost:${PORT}`);
  console.log(`📘 รูปแบบหมายเลขเกียรติบัตรที่รองรับ: 10437/2568 หรือ ๑๐๔๓๗/๒๕๖๘`);
});

module.exports = { db };

// ========================
// รันเซิร์ฟเวอร์
// ========================
function findAvailablePort(startPort = 3000) {
  const net = require('net');
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(startPort, () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
    server.on('error', () => {
      resolve(findAvailablePort(startPort + 1));
    });
  });
}

findAvailablePort(3000).then((availablePort) => {
  process.env.PORT = availablePort;
  if (!process.env.APP_URL) {
    process.env.APP_URL = `http://localhost:${availablePort}`;
  }
  app.listen(availablePort, () => {
    console.log(`✅ ระบบทำงานที่ ${process.env.APP_URL}`);
    console.log(`🔑 ครูเก่า: ใช้รหัสผ่าน '123456' หากล็อกอินไม่ได้`);
    console.log(`🔒 ลืมรหัสผ่าน: เข้าที่ /forgot-password`);
    if (transporter) {
      console.log(`📧 ระบบส่งอีเมล: เปิดใช้งาน (ใช้ ${process.env.EMAIL_USER})`);
    } else {
      console.log(`📧 ระบบส่งอีเมล: ยังไม่ได้ตั้งค่า`);
    }
  });
}).catch(err => {
  console.error('❌ ไม่สามารถเปิดเซิร์ฟเวอร์ได้:', err);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// 🔧 ติดตั้ง package (รันครั้งเดียว):
// npm install express-rate-limit express-slow-down helmet
module.exports = { db };