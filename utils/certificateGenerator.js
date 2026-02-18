// utils/certificateGenerator.js

const { db } = require('../app');

class CertificateGenerator {
  
  // ✅ สร้างหมายเลขเกียรติบัตรแบบเร็วและเสถียร
  static async generateCertificates(requestId, count) {
    const connection = await db.getConnection();
    
    try {
      await connection.beginTransaction();
      
      const certificates = [];
      const currentYear = new Date().getFullYear() + 543; // พ.ศ.
      
      // ดึงหมายเลขลำดับล่าสุดจากตารางแยก (เร็วกว่า query จากตารางใหญ่)
      let sequenceRecord = await connection.query(
        'SELECT last_sequence FROM certificate_sequence WHERE year = ? FOR UPDATE',
        [currentYear]
      );
      
      let lastSequence = 0;
      if (sequenceRecord[0].length > 0) {
        lastSequence = sequenceRecord[0][0].last_sequence;
      } else {
        // ถ้ายังไม่มีปีนี้ในตาราง ให้สร้างใหม่
        await connection.query(
          'INSERT INTO certificate_sequence (year, last_sequence) VALUES (?, 0)',
          [currentYear]
        );
      }
      
      // สร้างหมายเลขเกียรติบัตรแบบ bulk insert (เร็วกว่า insert ทีละตัว)
      const values = [];
      for (let i = 1; i <= count; i++) {
        const sequence = lastSequence + i;
        const certNumber = `KK2-${currentYear}-${String(sequence).padStart(6, '0')}`;
        
        values.push([requestId, certNumber, sequence, currentYear]);
        certificates.push({
          certificate_number: certNumber,
          sequence_number: sequence
        });
      }
      
      // Bulk insert
      await connection.query(
        'INSERT INTO certificates (request_id, certificate_number, sequence_number, year) VALUES ?',
        [values]
      );
      
      // อัพเดทหมายเลขลำดับล่าสุด
      await connection.query(
        'UPDATE certificate_sequence SET last_sequence = ? WHERE year = ?',
        [lastSequence + count, currentYear]
      );
      
      await connection.commit();
      
      return {
        success: true,
        count: certificates.length,
        certificates: certificates
      };
      
    } catch (error) {
      await connection.rollback();
      console.error('❌ Error generating certificates:', error);
      throw error;
    } finally {
      connection.release();
    }
  }
  
  // ✅ ดึงข้อมูลคำขอที่รอการอนุมัติ
  static async getPendingRequests() {
    try {
      const [result] = await db.query(`
        SELECT cr.*, 
               u.full_name, 
               u.email,
               u.school_name,
               CASE 
                 WHEN cr.user_type = 'teacher' THEN u.subject 
                 ELSE u.position 
               END as position_or_subject
        FROM certificate_requests cr
        JOIN users u ON cr.user_id = u.id
        WHERE cr.status = 'pending'
        ORDER BY cr.created_at DESC
      `);
      return result;
    } catch (error) {
      console.error('❌ Error fetching pending requests:', error);
      throw error;
    }
  }
  
  // ✅ อนุมัติคำขอ
  static async approveRequest(requestId, approvedBy) {
    const connection = await db.getConnection();
    
    try {
      await connection.beginTransaction();
      
      // อัพเดทสถานะคำขอ
      await connection.query(
        'UPDATE certificate_requests SET status = "approved", approved_by = ?, approved_at = NOW() WHERE id = ?',
        [approvedBy, requestId]
      );
      
      // ดึงข้อมูลคำขอ
      const [request] = await connection.query(
        'SELECT * FROM certificate_requests WHERE id = ?',
        [requestId]
      );
      
      if (request.length === 0) {
        throw new Error('ไม่พบคำขอ');
      }
      
      // สร้างหมายเลขเกียรติบัตร
      const result = await this.generateCertificates(requestId, request[0].certificate_count);
      
      await connection.commit();
      
      return result;
      
    } catch (error) {
      await connection.rollback();
      console.error('❌ Error approving request:', error);
      throw error;
    } finally {
      connection.release();
    }
  }
  
  // ✅ ปฏิเสธคำขอ
  static async rejectRequest(requestId) {
    try {
      await db.query(
        'UPDATE certificate_requests SET status = "rejected" WHERE id = ?',
        [requestId]
      );
      return true;
    } catch (error) {
      console.error('❌ Error rejecting request:', error);
      throw error;
    }
  }
  
  // ✅ ดึงประวัติคำขอของผู้ใช้
  static async getUserRequests(userId, userType) {
    try {
      const [result] = await db.query(`
        SELECT cr.*, 
               (SELECT COUNT(*) FROM certificates WHERE request_id = cr.id) as generated_count,
               (SELECT COUNT(*) FROM certificates WHERE request_id = cr.id AND used = TRUE) as used_count
        FROM certificate_requests cr
        WHERE cr.user_id = ? AND cr.user_type = ?
        ORDER BY cr.created_at DESC
      `, [userId, userType]);
      return result;
    } catch (error) {
      console.error('❌ Error fetching user requests:', error);
      throw error;
    }
  }
  
  // ✅ ดึงหมายเลขเกียรติบัตรที่สร้างจากคำขอ
  static async getCertificatesByRequest(requestId) {
    try {
      const [result] = await db.query(`
        SELECT c.*, 
               cu.recipient_name,
               cu.recipient_school,
               cu.issued_date
        FROM certificates c
        LEFT JOIN certificate_usage cu ON c.id = cu.certificate_id
        WHERE c.request_id = ?
        ORDER BY c.sequence_number ASC
      `, [requestId]);
      return result;
    } catch (error) {
      console.error('❌ Error fetching certificates:', error);
      throw error;
    }
  }
  
  // ✅ สถิติระบบ
  static async getStatistics() {
    try {
      const [result] = await db.query(`
        SELECT 
          (SELECT COUNT(*) FROM certificate_requests WHERE status = 'pending') as pending_count,
          (SELECT COUNT(*) FROM certificate_requests WHERE status = 'approved') as approved_count,
          (SELECT COUNT(*) FROM certificate_requests WHERE status = 'rejected') as rejected_count,
          (SELECT COUNT(*) FROM certificates WHERE request_id IS NOT NULL) as total_certificates,
          (SELECT COUNT(*) FROM certificates WHERE request_id IS NOT NULL AND used = TRUE) as used_certificates
      `);
      return result[0];
    } catch (error) {
      console.error('❌ Error fetching statistics:', error);
      throw error;
    }
  }
}

module.exports = CertificateGenerator;