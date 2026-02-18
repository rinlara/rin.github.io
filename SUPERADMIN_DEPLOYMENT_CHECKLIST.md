# 🚀 Super Admin System - Setup Checklist

**Project:** KKN Certificate Management System v2.0  
**Feature:** Super Admin Role with Management Capabilities  
**Status:** ✅ Code Complete | ⏳ Testing Phase  
**Date:** February 2025

---

## 📋 Pre-Deployment Checklist

### 1️⃣ Database Migration

- [ ] Review migration file: `migrations/02-add-request-status-fields.sql`
- [ ] Check database backup exists
- [ ] Execute migration command:
  ```bash
  mysql -u root -p<password> <database_name> < migrations/02-add-request-status-fields.sql
  ```
- [ ] Verify columns added (5 new columns, 3 new indexes)
- [ ] No errors in execution log

### 2️⃣ Code Integration

- [ ] Verify `app.js` has superadmin route registration (lines 2549-2558)
  ```javascript
  const superadminRoutes = require('./routes/superadmin');
  app.use('/superadmin', superadminRoutes);
  ```
- [ ] Verify all required files exist:
  - [ ] `routes/superadmin.js`
  - [ ] `views/admin/superadmin-dashboard.ejs`
  - [ ] `views/admin/superadmin-admins.ejs`
  - [ ] `views/admin/superadmin-admin-edit.ejs`
  - [ ] `views/admin/superadmin-users.ejs`
  - [ ] `views/admin/superadmin-audits.ejs`
  - [ ] `scripts/create-superadmin.js`

### 3️⃣ Environment Setup

- [ ] `.env` file has database credentials
  - [ ] `DB_HOST=localhost`
  - [ ] `DB_USER=root`
  - [ ] `DB_PASSWORD=...`
  - [ ] `DB_NAME=kkn_certificate`
- [ ] Node.js and npm installed
- [ ] All dependencies installed: `npm install`

---

## ⚙️ Deployment Steps

### Step 1: Stop Current Server

- [ ] Stop Node.js process (Ctrl+C or kill process)
- [ ] Verify no processes running on port 3000
  ```bash
  netstat -ano | findstr :3000  # Windows
  # or
  lsof -i :3000  # macOS/Linux
  ```

### Step 2: Execute Database Migration

- [ ] Run migration:
  ```bash
  mysql -u root -p<password> kkn_certificate < migrations/02-add-request-status-fields.sql
  ```
- [ ] Verify in MySQL:
  ```sql
  DESCRIBE certificate_requests;
  SHOW INDEXES FROM certificate_requests;
  ```
- [ ] Check for new columns:
  - [ ] `approved_by`
  - [ ] `approved_at`
  - [ ] `rejected_by`
  - [ ] `rejected_at`
  - [ ] `rejection_reason`

### Step 3: Restart Server

- [ ] Start Node.js server:
  ```bash
  npm start
  # or
  node app.js
  ```
- [ ] Check console for startup messages:
  - [ ] "Express server running on port 3000"
  - [ ] No database connection errors
  - [ ] No route import errors
  - [ ] No middleware errors

### Step 4: Create Super Admin Account

- [ ] Run account creation script:
  ```bash
  node scripts/create-superadmin.js
  ```
- [ ] Or with parameters:
  ```bash
  node scripts/create-superadmin.js admin@kkn2.com SecurePassword123 "Super Administrator"
  ```
- [ ] Save credentials in secure location:
  - [ ] Email: ___________________
  - [ ] Password: ________________
  - [ ] Name: ____________________
  - [ ] Role: super_admin

### Step 5: Test Login

- [ ] Open browser: `http://localhost:3000/login`
- [ ] Enter Super Admin credentials
- [ ] Click "Login"
- [ ] Should redirect to `/superadmin/dashboard`

---

## ✅ Feature Testing Checklist

### Dashboard (`/superadmin/dashboard`)

- [ ] Page loads without errors
- [ ] Statistics cards display:
  - [ ] Admin count (correct number)
  - [ ] Super Admin count (correct number)
  - [ ] Teacher count (correct number)
  - [ ] Staff count (correct number)
  - [ ] Total certificates (correct number)
  - [ ] Approved count (correct number)
  - [ ] Pending count (correct number)
  - [ ] Rejected count (correct number)
- [ ] Admin table displays (shows latest admins)
- [ ] Recent requests table displays (shows latest 5)
- [ ] Quick action cards visible and clickable
- [ ] Page styling matches government theme
- [ ] Responsive on mobile devices

### Admin Management (`/superadmin/admins`)

#### List Admins Tab
- [ ] Tab loads correctly
- [ ] Admin table displays all admins
- [ ] Edit button works (redirects to edit form)
- [ ] Delete button works (shows confirmation)
- [ ] Delete prevent self-deletion
- [ ] Pagination works (if many admins)

#### Add New Admin Tab
- [ ] Form displays all fields:
  - [ ] Full Name
  - [ ] Email
  - [ ] Phone
  - [ ] School
  - [ ] Role dropdown
  - [ ] Password
  - [ ] Confirm Password
- [ ] Submit button creates admin
- [ ] Error handling:
  - [ ] Duplicate email rejected
  - [ ] Weak password rejected (< 8 chars)
  - [ ] Password mismatch rejected
  - [ ] Empty required fields rejected
- [ ] Success message displays

### Edit Admin (`/superadmin/admins/{id}/edit`)

- [ ] Form loads with current admin data
- [ ] Can edit all fields:
  - [ ] Full Name
  - [ ] Email
  - [ ] Phone
  - [ ] School
  - [ ] Role
- [ ] Password field optional (leave blank to keep)
- [ ] Can change role (Admin ↔ Super Admin)
- [ ] Back button returns to admin list
- [ ] Save button updates admin
- [ ] Prevents duplicate email (except current)

### Delete Admin

- [ ] Delete button appears on edit form
- [ ] Confirmation dialog shows
- [ ] Cannot delete Super Admin (edit screen shows only current user)
- [ ] Admin removed from list after deletion
- [ ] System admin not deletable by themselves

### User Management (`/superadmin/users`)

- [ ] Page loads correctly
- [ ] Role filter works:
  - [ ] "All" shows all users
  - [ ] "Teacher" shows teachers only
  - [ ] "Staff" shows staff only
  - [ ] "Admin" shows admins only
  - [ ] "Super Admin" shows super admins only
- [ ] Search functionality works:
  - [ ] Search by name
  - [ ] Search by email
  - [ ] Search by school
  - [ ] Combined with role filter
- [ ] User table displays correctly:
  - [ ] ID column
  - [ ] Full Name column
  - [ ] Email column
  - [ ] School column
  - [ ] Role with badges (different colors)
  - [ ] Created date column
  - [ ] Delete button
- [ ] Delete user functionality:
  - [ ] Shows confirmation
  - [ ] User removed from database
  - [ ] User table updates
- [ ] Empty state message shows when no results
- [ ] Pagination works (if many users)

### Audit Log (`/superadmin/audits`)

- [ ] Page loads correctly
- [ ] Audit table displays:
  - [ ] Event Name column (certificate project name)
  - [ ] Requester column (teacher name)
  - [ ] Status column (Approved/Rejected badges)
  - [ ] Handler Name column (admin who approved/rejected)
  - [ ] Date column (action timestamp)
  - [ ] Notes/Reason column (rejection reason if applicable)
- [ ] Status badges display correctly:
  - [ ] ✅ Green badge for approved
  - [ ] ❌ Red badge for rejected
- [ ] Rejection reasons visible (tooltip for truncated)
- [ ] Empty state message shows when no audits
- [ ] Timestamps formatted correctly (Thai locale)

---

## 🔒 Security Verification

- [ ] Middleware `requireSuperAdmin` blocks non-super-admins
- [ ] Try accessing `/superadmin/dashboard` as regular admin
  - [ ] Should show 403 error or redirect
- [ ] Try accessing `/superadmin/dashboard` as logged-out user
  - [ ] Should redirect to login
- [ ] Passwords hashed in database (bcrypt, not plaintext)
- [ ] Session tokens working correctly
- [ ] CSRF protection enabled (if applicable)
- [ ] SQL injection prevented (prepared statements used)

---

## 🐛 Common Issues & Resolution

### Issue: "500 Error on /superadmin/dashboard"
**Check:**
- [ ] Database migration was executed
- [ ] Database columns exist (approved_by, etc.)
- [ ] Database credentials correct in .env
- [ ] app.js route registration correct

**Fix:**
```bash
# Re-run migration
mysql -u root -p<password> kkn_certificate < migrations/02-add-request-status-fields.sql

# Restart server
npm start
```

### Issue: "Cannot find module 'superadmin'"
**Check:**
- [ ] `routes/superadmin.js` exists
- [ ] app.js imports superadmin correctly
- [ ] Path is correct: `./routes/superadmin`

**Fix:**
```bash
# Verify file exists
ls routes/superadmin.js  # or dir routes\superadmin.js on Windows

# Check app.js line 2549-2558 for correct import
```

### Issue: "User not found" when accessing admin panel
**Check:**
- [ ] Super Admin account was created
- [ ] Email and password are correct
- [ ] Database has user with role='super_admin'

**Fix:**
```bash
# Create Super Admin account
node scripts/create-superadmin.js

# Or check database
mysql -u root -p<password> kkn_certificate
SELECT * FROM users WHERE role = 'super_admin';
```

### Issue: "Unauthorized" accessing /superadmin/dashboard
**Check:**
- [ ] Logged-in as Super Admin (not regular admin)
- [ ] role = 'super_admin' in users table

**Fix:**
```sql
-- Change user role to super_admin
UPDATE users SET role = 'super_admin' WHERE email = 'your-email@example.com';

-- Logout and login again
```

---

## 📊 Post-Deployment Verification

### Browser Console Check
```javascript
// Open browser DevTools (F12) and check console for errors
// Should be clean with no red errors
```

### API Response Check
```javascript
// Test dashboard endpoint
fetch('/superadmin/dashboard')
  .then(r => r.text())
  .then(html => console.log('OK: Dashboard loads'))
  .catch(e => console.error('ERROR:', e))
```

### Database Connectivity Check
```sql
-- Verify database is online
SELECT COUNT(*) as admin_count FROM users WHERE role IN ('admin', 'super_admin');

-- Should return a number (0 or more)
```

### Session Check
```javascript
// After login, check if session cookie exists
// Open DevTools > Application > Cookies
// Should see 'connect.sid' cookie
```

---

## 📈 Performance Baseline

**Expected Response Times:**
- Dashboard load: < 500ms
- Admin list: < 300ms
- User search: < 500ms
- Audit log: < 1000ms (depending on number of records)

**Database Queries Optimization:**
- All queries use indexes
- Added indexes on: `approved_by`, `approved_at`, `rejected_by`, `rejected_at`
- No N+1 query problems
- Pagination limits to 100 records

---

## 🎓 Training Checklists

### For Super Admin User
- [ ] Trained on dashboard functionality
- [ ] Trained on creating admins
- [ ] Trained on managing users
- [ ] Trained on viewing audit logs
- [ ] Understands role hierarchy
- [ ] Understands password requirements

### For System Administrator
- [ ] Knows how to restart server
- [ ] Knows how to check logs
- [ ] Knows how to backup database
- [ ] Knows how to recover Super Admin password
- [ ] Knows how to create additional Super Admins

---

## 📝 Sign-Off

**Deployment Team:**
- [ ] Code Review: _________________ Date: _______
- [ ] Database Backup: ______________ Date: _______
- [ ] Migration Execution: __________ Date: _______
- [ ] Server Restart: ______________ Date: _______
- [ ] Testing Complete: ___________ Date: _______
- [ ] Go Live Approval: ___________ Date: _______

**Super Admin Account Details:**
```
Email: _______________________________
Initial Password: _____________________
Temporary: [X] Yes  [ ] No
Changed on: _______________________________
```

---

## 📞 Support Contacts

**Technical Issues:**
- Database Admin: ________________________
- Server Admin: ________________________
- Development Lead: ______________________

**Feature Questions:**
- Super Admin Training: ___________________
- Help Desk: ______________________________

---

**Document Version:** 1.0  
**Last Updated:** February 2025  
**Status:** ✅ Ready for Production Deployment
