// scripts/run-migration.js
// Script สำหรับ run database migration

require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

const migrationFile = path.join(__dirname, '../migrations/01-add-certificate-fields.sql');

async function runMigration() {
  let connection;
  
  try {
    // สร้าง connection
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'certificate_system'
    });

    console.log('✅ เชื่อมต่อ MySQL สำเร็จ');

    // อ่าน migration file
    let sql = fs.readFileSync(migrationFile, 'utf8');

    // แยก SQL statements (ตัดจาก ; แต่ไม่ตัดใน comment)
    const statements = sql
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt && !stmt.startsWith('--') && !stmt.startsWith('/*'));

    let executedCount = 0;

    for (const statement of statements) {
      try {
        await connection.execute(statement);
        console.log(`✅ Executed: ${statement.substring(0, 50)}...`);
        executedCount++;
      } catch (err) {
        // บางอย่างอาจเป็น warning (เช่น column exists)
        if (err.code === 'ER_DUP_FIELDNAME' || err.code === 'ER_DUP_KEYNAME') {
          console.log(`⚠️  Warning (already exists): ${statement.substring(0, 50)}...`);
        } else {
          throw err;
        }
      }
    }

    console.log(`\n✅ Migration สำเร็จ! (${executedCount} statements)`);
    console.log('📝 Database tables updated successfully!');

  } catch (error) {
    console.error('❌ Migration Error:', error.message);
    process.exit(1);
  } finally {
    if (connection) {
      await connection.end();
    }
  }
}

// Run migration
runMigration().then(() => {
  console.log('✅ Done!');
  process.exit(0);
}).catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
