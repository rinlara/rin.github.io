#!/usr/bin/env node

/**
 * Script: Create Super Admin Account
 * Usage: node scripts/create-superadmin.js [email] [password]
 * 
 * Example:
 * node scripts/create-superadmin.js superadmin@example.com MySecurePassword123
 */

const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const readline = require('readline');

// Read database config
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'certificate_system',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(prompt) {
  return new Promise(resolve => {
    rl.question(prompt, resolve);
  });
}

async function createSuperAdmin() {
  let email = process.argv[2];
  let password = process.argv[3];
  let fullName = process.argv[4] || 'Super Administrator';

  try {
    console.log('\n========================================');
    console.log('    Super Admin Account Creator        ');
    console.log('========================================\n');

    // If not provided via command line, ask user
    if (!email) {
      email = await question('📧 Enter Super Admin Email: ');
    }

    if (!password) {
      password = await question('🔐 Enter Super Admin Password: ');
    }

    if (!fullName || fullName === 'Super Administrator') {
      fullName = await question('👤 Enter Full Name (default: Super Administrator): ') || 'Super Administrator';
    }

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.error('\n❌ Invalid email format!');
      process.exit(1);
    }

    // Validate password length
    if (password.length < 8) {
      console.error('\n❌ Password must be at least 8 characters long!');
      process.exit(1);
    }

    console.log('\n⏳ Processing...\n');

    const connection = await pool.getConnection();

    // Check if email already exists
    const [existing] = await connection.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      console.error('❌ Email already exists in the system!\n');
      connection.release();
      process.exit(1);
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create super admin user
    const [result] = await connection.execute(
      `INSERT INTO users (full_name, email, password, role, created_at, updated_at) 
       VALUES (?, ?, ?, ?, NOW(), NOW())`,
      [fullName, email, hashedPassword, 'super_admin']
    );

    if (result.affectedRows === 1) {
      console.log('✅ Super Admin account created successfully!\n');
      console.log('========== SUPER ADMIN CREDENTIALS ==========');
      console.log(`📧 Email: ${email}`);
      console.log(`🔐 Password: ${password}`);
      console.log(`👤 Name: ${fullName}`);
      console.log(`👑 Role: Super Admin`);
      console.log('==========================================\n');
      console.log('🔗 Login URL: http://your-domain/login\n');
      console.log('⚠️  IMPORTANT:');
      console.log('  1. Save these credentials securely');
      console.log('  2. Change the password after first login');
      console.log('  3. Share credentials only with authorized personnel\n');
    } else {
      console.error('❌ Failed to create Super Admin account!\n');
      process.exit(1);
    }

    connection.release();
    rl.close();
    process.exit(0);

  } catch (error) {
    console.error('\n❌ Error:', error.message);
    console.error('\nPlease make sure:');
    console.error('  1. Database is running');
    console.error('  2. .env file is properly configured');
    console.error('  3. Database connection credentials are correct\n');
    process.exit(1);
  }
}

// Run the script
createSuperAdmin();
