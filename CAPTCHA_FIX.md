# 🔧 CipherGate CAPTCHA Fix - Troubleshooting Guide

## ✅ What Was Fixed

### Problem 1: Broken server.js
- ❌ Previous version: Used Supabase instead of MySQL
- ❌ CAPTCHA stored in global variable (not session-safe)
- ❌ Wrong API endpoints (`/auth/login` instead of `/api/login`)
- ✅ Fixed: Full MySQL implementation with session-based CAPTCHA storage

### Problem 2: HTML/JS Element Mismatch
- ❌ Old inline script: Looked for `#captcha-question` 
- ❌ Actual element: `#captchaQuestion` (camelCase)
- ✅ Fixed: Removed broken inline script, using auth.js `loadCAPTCHA()` function

### Problem 3: Frontend Setup
- ❌ Didn't load CAPTCHA on page initialization
- ✅ Fixed: Added `DOMContentLoaded` listener in login.html

## 🚀 Complete Setup Instructions

### Step 1: Install Dependencies
```bash
npm install
```

Dependencies needed:
- express
- express-session
- bcryptjs
- mysql2
- dotenv

### Step 2: Setup MySQL Database

```bash
# Connect to MySQL
mysql -u root -p

# Run this:
mysql> CREATE DATABASE ciphergate;
mysql> USE ciphergate;
mysql> source schema.sql;
```

**Verify tables created:**
```sql
SHOW TABLES;
-- Should show: logs, users
```

### Step 3: Create .env File

```bash
cp .env.example .env
```

Edit `.env`:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=ciphergate
SESSION_SECRET=your_super_secret_session_key_change_this_in_production
PORT=3000
NODE_ENV=development
```

### Step 4: Start Server

```bash
npm run dev
# or
npm start
```

You should see:
```
╔════════════════════════════════════════╗
║   CIPHERGATE Security System Online    ║
║   Advanced Access Control Running      ║
╚════════════════════════════════════════╝
Server running on: http://localhost:3000
```

### Step 5: Test CAPTCHA

1. Open browser: `http://localhost:3000`
2. Click "Login" button
3. You should see:
   - Math CAPTCHA question loaded (e.g., "Solve: 7 + 3 = ?")
   - "🔄 New" button to generate new CAPTCHA
   - Input field for answer

### Step 6: Login with Demo Credentials

**Admin Account:**
- Username: `admin`
- Password: `Admin@123`
- Security Answer: `blue`

**User Account:**
- Username: `testuser`
- Password: `User@123`
- Security Answer: `fluffy`

## 🧪 Testing Feature 10 (CAPTCHA)

### Test 1: CAPTCHA Loads
1. Go to login page
2. Wait for page to load completely
3. **Expected**: Math problem appears (e.g., "Solve: 5 + 3 = ?")
4. **Verify**: Element updates with new question format

### Test 2: CAPTCHA Generates New Challenge
1. Click "🔄 New" button
2. **Expected**: New math problem appears
3. **Verify**: Different numbers/operators

### Test 3: CAPTCHA Validation
1. Login attempt with correct CAPTCHA answer
   - **Expected**: Login continues
2. Login attempt with wrong CAPTCHA answer
   - **Expected**: Error: "Invalid CAPTCHA"
   - New CAPTCHA generated automatically

### Test 4: CAPTCHA + Feature 3 (Lockout)
1. Fail login 3 times with wrong passwords
2. **Expected**: "Account locked for 30 seconds"
3. Even with correct CAPTCHA, cannot login
4. Wait 30 seconds or admin unlock to proceed

## 🔍 Debugging CAPTCHA Issues

### Issue: "Error loading CAPTCHA"

**Solution 1: Check server is running**
```bash
# Terminal
npm start

# In another terminal, test endpoint
curl http://localhost:3000/api/captcha
```

Should return JSON like:
```json
{
  "question": "7 + 3",
  "sessionId": "abc123..."
}
```

**Solution 2: Check browser console**
- Open DevTools (F12)
- Go to Console tab
- Check for JavaScript errors
- Verify `/api/captcha` fetch request in Network tab

### Issue: CAPTCHA works but login always fails

**Solution 1: Check element IDs**
In browser console:
```javascript
// Should return the element
document.getElementById('captchaQuestion')

// Should return the input
document.getElementById('captchaAnswer')
```

**Solution 2: Verify session cookies**
- Open DevTools → Application → Cookies
- Look for `connect.sid` cookie
- Should be HttpOnly, Path: /

### Issue: Wrong CAPTCHA answer accepted

**This shouldn't happen** - session-based validation

Try:
1. Clear cookies (DevTools → Application → Clear All)
2. Refresh page
3. Try again

## 📊 Feature Flow Diagram

```
Page Load
    ↓
DOMContentLoaded fires
    ↓
loadCAPTCHA() called
    ↓
GET /api/captcha
    ↓
Server generates math problem
Stores answer in req.session.captcha
    ↓
Returns { question: "7 + 3", sessionId: "..." }
    ↓
HTML element #captchaQuestion updated
    ↓
User sees: "Solve: 7 + 3 = ?"
User enters: 10
    ↓
User submits login form
    ↓
POST /api/login with username, password, captchaAnswer
    ↓
Server validates:
- Is CAPTCHA answer == req.session.captcha ? ✓
- Password matches bcrypt hash? ✓
- Account not locked? ✓
    ↓
Create session + Redirect to dashboard
```

## 🛡️ Security Verification

### Session-Based CAPTCHA ✅
- Answer stored in `req.session.captcha`
- Each request has unique session ID
- Cookie carries `sessionID`
- Server matches answer + session
- **Result**: Prevents CAPTCHA reuse attacks

### Bcrypt Password Hashing ✅
- Passwords never stored plaintext
- 10 salt rounds
- Timing-safe comparison
- **Result**: Secure password verification

### Feature 3: Lockout ✅
- Failed attempts tracked
- After 3 fails: 30-second lockout
- Admin can unlock manually
- **Result**: Prevents brute-force attacks

### Feature 6: Sessions ✅
- HTTP-only cookies
- 24-hour timeout
- Session destruction on logout
- **Result**: Prevents XSS + session hijacking

## 📝 Common Commands

```bash
# Check if MySQL is running
mysql -u root -p -e "SELECT VERSION();"

# View CipherGate database
mysql -u root -p ciphergate -e "SELECT * FROM users;"

# View activity logs
mysql -u root -p ciphergate -e "SELECT * FROM logs;"

# Stop server
# Press Ctrl+C in terminal

# Run with nodemon (auto-restart on changes)
npm run dev

# Production start
NODE_ENV=production npm start
```

## 🐛 Known Issues & Solutions

| Issue | Solution |
|-------|----------|
| "Cannot find module 'mysql2'" | Run `npm install` |
| Database connection errors | Check `.env` DB credentials |
| CAPTCHA not updating | Hard refresh (Ctrl+F5) or clear cache |
| Session not persisting | Check `SESSION_SECRET` is set in `.env` |
| 403 Unauthorized on dashboard | Check role ('admin' or 'user') |

## ✨ Next Steps

1. ✅ Test login with demo credentials
2. ✅ Try incorrect CAPTCHA to verify validation
3. ✅ Test Feature 3: Fail 3 times to trigger lockout
4. ✅ Test Feature 4: Admin vs User different dashboards
5. ✅ Test Feature 14: Toggle dark/light theme

---

**CipherGate CAPTCHA**: Now Fully Functional! 🎉

For detailed security documentation, see: [SECURITY.md](SECURITY.md)
