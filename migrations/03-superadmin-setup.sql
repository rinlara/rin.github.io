-- Migration: Add superadmin role support and create default superadmin
-- This migration adds superadmin role if it doesn't already exist

-- Check if there's any user with role 'super_admin', if not, create one
-- Note: You should run this migration with appropriate database credentials

-- This file is just informational
-- To use: 
-- 1. Run the database query in MySQL Workbench or CLI
-- 2. Or use the Node.js script: node scripts/create-superadmin.js

-- ==============================================
-- SUPERADMIN SETUP INSTRUCTIONS
-- ==============================================

-- The users table already supports the 'super_admin' role value
-- If you need to check/verify the current schema:

SHOW COLUMNS FROM users;

-- The role column should accept values like:
-- - 'teacher'
-- - 'admin'
-- - 'super_admin'
-- - 'staff'

-- To create an admin as super_admin, use:
-- UPDATE users SET role = 'super_admin' WHERE id = 1;

-- Or use the Node.js script in scripts/create-superadmin.js
