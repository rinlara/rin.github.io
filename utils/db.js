// utils/db.js
/**
 * แปลงค่า undefined เป็น null สำหรับใช้กับคำสั่ง SQL
 * @param {Array} params - พารามิเตอร์ที่จะส่งเข้าคำสั่ง SQL
 * @returns {Array} พารามิเตอร์ที่sanitize แล้ว
 */
exports.sanitizeSqlParams = (params) => {
  if (!Array.isArray(params)) return params;
  
  return params.map(p => {
    if (p === undefined) return null;
    if (typeof p === 'string' && p.trim() === '') return null;
    return p;
  });
};

/**
 * ตรวจสอบว่าค่าเป็นจำนวนเต็มที่ถูกต้องหรือไม่
 */
exports.isValidInteger = (value) => {
  return Number.isInteger(value) && value > 0;
};