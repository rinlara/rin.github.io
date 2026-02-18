// middleware/auth.js

// ✅ ตรวจสอบว่าล็อกอินแล้ว (แบบเดิม - ใช้กับ redirect)
exports.requireLogin = (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/login?error=กรุณาเข้าสู่ระบบ');
  }
  next();
};

// ✅ อนุญาตเฉพาะ super_admin (แบบเดิม)
exports.requireSuperAdmin = (req, res, next) => {
  if (req.session.user?.role !== 'super_admin') {
    return res.redirect('/admin?error=ต้องเป็นซุปเปอร์แอดมินเท่านั้น');
  }
  next();
};

// ✅ อนุญาตทั้ง admin และ super_admin (แบบเดิม)
exports.requireAdmin = (req, res, next) => {
  if (!req.session.user || !['admin', 'super_admin'].includes(req.session.user.role)) {
    return res.redirect('/login?error=ต้องเข้าสู่ระบบในฐานะแอดมิน');
  }
  next();
};

// ✅ Middleware สำหรับตรวจสอบการล็อกอิน + ใช้กับ flash messages (แบบใหม่)
exports.auth = (req, res, next) => {
  if (!req.session.user) {
    req.flash('error', 'กรุณาเข้าสู่ระบบก่อน');
    return res.redirect('/');
  }
  
  // กำหนดค่าให้กับ res.locals เพื่อใช้ในหน้าเว็บ
  res.locals.user = req.session.user;
  next();
};

// ✅ Middleware สำหรับตรวจสอบบทบาทเฉพาะ
exports.requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.session.user || !roles.includes(req.session.user.role)) {
      req.flash('error', 'คุณไม่มีสิทธิ์เข้าถึงหน้านี้');
      return res.redirect('/');
    }
    res.locals.user = req.session.user;
    next();
  };
};

// ✅ Middleware สำหรับตรวจสอบว่าเป็นครูหรือบุคลากร
exports.requireTeacherOrStaff = (req, res, next) => {
  if (!req.session.user || !['teacher', 'staff'].includes(req.session.user.role)) {
    req.flash('error', 'ต้องเข้าสู่ระบบในฐานะครูหรือบุคลากร');
    return res.redirect('/login');
  }
  res.locals.user = req.session.user;
  next();
};

// ✅ Middleware สำหรับตรวจสอบว่าเป็นครูเท่านั้น
exports.requireTeacher = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'teacher') {
    req.flash('error', 'ต้องเข้าสู่ระบบในฐานะครู');
    return res.redirect('/login');
  }
  res.locals.user = req.session.user;
  next();
};

// ✅ Middleware สำหรับตรวจสอบว่าเป็นบุคลากรเท่านั้น
exports.requireStaff = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'staff') {
    req.flash('error', 'ต้องเข้าสู่ระบบในฐานะบุคลากร');
    return res.redirect('/login');
  }
  res.locals.user = req.session.user;
  next();
};

// ✅ Middleware สำหรับตรวจสอบว่าเป็นแอดมิน (รวม super_admin)
exports.requireAdminOrSuper = (req, res, next) => {
  if (!req.session.user || !['admin', 'super_admin'].includes(req.session.user.role)) {
    req.flash('error', 'ต้องเข้าสู่ระบบในฐานะแอดมิน');
    return res.redirect('/login');
  }
  res.locals.user = req.session.user;
  next();
};

// ✅ Middleware สำหรับตรวจสอบและกำหนดค่า user ให้กับ locals (ใช้กับทุกหน้าที่ล็อกอิน)
exports.setUserLocals = (req, res, next) => {
  if (req.session.user) {
    res.locals.user = req.session.user;
  }
  next();
};

// ========================================
// ส่งออก module (รองรับการใช้งานทั้งแบบเดิมและแบบใหม่)
// ========================================

// รองรับการใช้งานแบบเดิม: const auth = require('./middleware/auth');
module.exports = exports.auth;

// หรือใช้แบบนี้ก็ได้:
// const { auth, requireLogin, requireAdmin } = require('./middleware/auth');