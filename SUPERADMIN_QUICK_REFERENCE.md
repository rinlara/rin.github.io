# 🚀 Super Admin System - Quick Reference Card

## 📌 Essential Commands

### Create Super Admin Account
```bash
# Interactive mode
node scripts/create-superadmin.js

# Direct mode with parameters
node scripts/create-superadmin.js admin@kkn2.com MyPassword123 "Admin Name"
```

### Database Migration
```bash
mysql -u root -p<password> kkn_certificate < migrations/02-add-request-status-fields.sql
```

### Start Server
```bash
npm start
# or
node app.js
```

### Check Super Admins in Database
```bash
mysql -u root -p<password> kkn_certificate
SELECT id, full_name, email, role, created_at FROM users WHERE role = 'super_admin';
```

### Convert Admin to Super Admin
```bash
mysql -u root -p<password> kkn_certificate
UPDATE users SET role = 'super_admin' WHERE email = 'admin@example.com';
```

---

## 🌐 Super Admin URLs

| Page | URL | Purpose |
|------|-----|---------|
| Dashboard | `/superadmin/dashboard` | Overview & statistics |
| Manage Admins | `/superadmin/admins` | CRUD admins |
| Edit Admin | `/superadmin/admins/{id}/edit` | Edit admin details |
| Manage Users | `/superadmin/users` | Search & manage users |
| Audit Log | `/superadmin/audits` | View approvals/rejections |

---

## 🔑 Default Login

**URL:** `http://localhost:3000/login`

**Credentials (After Creation):**
```
Email: admin@kkn2.com
Password: MyPassword123
```

---

## 📊 File Structure

```
project/
├── routes/
│   └── superadmin.js                    # 367 lines - Superadmin routes
├── views/admin/
│   ├── superadmin-dashboard.ejs         # 400+ lines - Dashboard
│   ├── superadmin-admins.ejs            # 350+ lines - Admin management
│   ├── superadmin-admin-edit.ejs        # 200+ lines - Edit admin
│   ├── superadmin-users.ejs             # 300+ lines - User management
│   └── superadmin-audits.ejs            # 250+ lines - Audit log
├── scripts/
│   └── create-superadmin.js             # 150+ lines - Account creation
├── migrations/
│   └── 02-add-request-status-fields.sql # Database migration
├── SUPERADMIN_GUIDE.md                  # Complete user guide
├── SUPERADMIN_DEPLOYMENT_CHECKLIST.md   # Deployment checklist
└── SUPERADMIN_QUICK_REFERENCE.md        # This file
```

---

## 🔍 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| "500 Error" | Re-run migration, restart server |
| "Not authorized" | Change user role to 'super_admin' |
| "Cannot create admin" | Check database migration was successful |
| "Email already exists" | Use different email or delete existing |
| "Password too weak" | Use password with 8+ characters |
| "Access denied" | Verify you're logged in as Super Admin |

---

## 🎯 Features Matrix

| Feature | Super Admin | Admin | Teacher | Staff |
|---------|:-----------:|:-----:|:-------:|:-----:|
| View Dashboard | ✅ | ✅ | ✅ | - |
| Manage Admins | ✅ | - | - | - |
| Manage Users | ✅ | - | - | - |
| View Audits | ✅ | - | - | - |
| Approve Certificates | ✅ | ✅ | - | - |
| Request Certificate | - | ✅ | ✅ | ✅ |
| Upload Certificate | - | ✅ | ✅ | ✅ |

---

## 📋 Role Hierarchy

```
┌─────────────────┐
│  Super Admin    │  ← Full system access + admin management
└────────┬────────┘
         │
         └──→ Can create/edit/delete Admin
         └──→ Can manage all users
         └──→ Can view audit logs
         
┌─────────────────┐
│    Admin        │  ← Certificate approval + admin access
└────────┬────────┘
         │
         └──→ Can approve/reject certificates
         └──→ Can view user data
         └──→ Cannot access /superadmin/*
         
┌─────────────────┐
│    Teacher      │  ← Certificate requests only
└────────┬────────┘
         │
         └──→ Can request certificates
         └──→ Can upload documents
         └──→ Can view own certificates
         
┌─────────────────┐
│     Staff       │  ← Certificate requests only
└────────┬────────┘
         │
         └──→ Same as Teacher
```

---

## 💾 Database Schema Changes

### New Columns in `certificate_requests` table:
```sql
approved_by         VARCHAR(255)      -- Admin who approved
approved_at         TIMESTAMP         -- When approved
rejected_by         VARCHAR(255)      -- Admin who rejected
rejected_at         TIMESTAMP         -- When rejected
rejection_reason    TEXT              -- Why rejected
```

### New Indexes:
```sql
INDEX idx_approved_by (approved_by)
INDEX idx_rejected_by (rejected_by)
INDEX idx_request_status (status)
```

---

## 🔐 Password Requirements

- ✅ Minimum 8 characters
- ✅ Any mix of letters, numbers, special chars
- ❌ No minimum complexity rules enforced
- ✅ Hashed with bcrypt (10 rounds)

**Example Strong Passwords:**
```
SecurePass123!
MyAdminPass2025
admin@kkn2.com-pwd
```

---

## 📱 Responsive Design

All Super Admin pages are responsive:
- ✅ Desktop (1920px+)
- ✅ Laptop (1024px+)
- ✅ Tablet (768px+)
- ✅ Mobile (480px+)

---

## 🎨 Color Theme

Consistent government-style colors:
```css
--primary-navy:     #003d7a   /* Thai government blue */
--primary-blue:     #0052a3   /* Action color */
--secondary-gold:   #d4af37   /* Prestige accent */
--light-bg:         #f5f7fa   /* Background */
--border-color:     #e2e8f0   /* Borders */
--success:          #10b981   /* Approvals */
--danger:           #ef4444   /* Rejections */
--warning:          #f59e0b   /* Pending */
```

---

## 🔄 Database Transactions

Supported for critical operations:
```javascript
// Example: Update with rollback on error
await conn.beginTransaction();
try {
  await conn.execute('UPDATE users SET role = ? WHERE id = ?', 
                     ['super_admin', userId]);
  await conn.commit();
} catch (err) {
  await conn.rollback();
}
```

---

## 📊 Pagination Settings

Default pagination: **100 records per page**

### Override in code:
```javascript
const limit = 100;
const offset = (page - 1) * limit;
// Then use in query: LIMIT ? OFFSET ?
```

---

## 🧪 Test Accounts Data

For testing without creating real accounts:

### Test Super Admin (After creation):
```
Email: test.superadmin@kkn2.com
Password: TestPass123
Name: Test Super Administrator
Role: super_admin
```

### Create test admin:
```
Email: test.admin@kkn2.com
Password: TestPass123
Name: Test Administrator
Role: admin
```

---

## 📞 Error Messages Reference

### User-Facing (Frontend)
```
"Email is already in use"
"Password must be at least 8 characters"
"Passwords do not match"
"Invalid email format"
"User not found"
"Cannot delete yourself"
"Operation failed, please try again"
```

### Server Logs (Check if errors occur)
```
Database connection error
Duplicate entry for key 'email'
Missing required fields
Invalid role selected
SQL syntax error
```

---

## 🚀 Performance Tips

1. **Dashboard loads slow?**
   - Check database indexes are created
   - Verify no large COUNT queries without indexes

2. **Search users slow?**
   - Ensure indexes on: name, email, school

3. **Audit log slow?**
   - Pagination is important for large databases
   - Consider archiving old audits to separate table

---

## 📚 Documentation Files

| File | Purpose |
|------|---------|
| SUPERADMIN_GUIDE.md | Complete user manual |
| SUPERADMIN_DEPLOYMENT_CHECKLIST.md | Pre/post deployment checks |
| SUPERADMIN_QUICK_REFERENCE.md | This file - quick commands |
| INSTALLATION_GUIDE.md | System setup instructions |
| SYSTEM_SETUP_COMPLETE.md | Setup status |

---

## ✨ Features Implemented

✅ Super Admin Dashboard with 8 statistics cards  
✅ Admin Management (Create, Read, Update, Delete)  
✅ User Management with Search & Filter  
✅ Approval Audit Trail  
✅ Interactive Account Creation Script  
✅ Role-based Access Control  
✅ Password Hashing with bcrypt  
✅ Responsive Design  
✅ Government-style Branding  
✅ SQL Injection Prevention (Prepared Statements)  
✅ Self-Delete Prevention  
✅ Duplicate Email Prevention  

---

## 🎯 Next Steps

1. **Execute Migration:**
   ```bash
   mysql -u root -p < migrations/02-add-request-status-fields.sql
   ```

2. **Restart Server:**
   ```bash
   npm start
   ```

3. **Create Super Admin:**
   ```bash
   node scripts/create-superadmin.js
   ```

4. **Login & Test:**
   - Go to `http://localhost:3000/login`
   - Use created credentials
   - Explore `/superadmin/dashboard`

5. **Read Full Guide:**
   - Open `SUPERADMIN_GUIDE.md` for detailed instructions

---

**Last Updated:** February 2025  
**Status:** ✅ Ready to Deploy  
**Version:** 1.0

---

## Quick Copy-Paste

```bash
# Full deployment sequence
mysql -u root -pYourPassword kkn_certificate < migrations/02-add-request-status-fields.sql
npm start
node scripts/create-superadmin.js superadmin@kkn2.com SecurePass123 "ผู้ดูแลระบบ"
```

Then open: `http://localhost:3000/login`
