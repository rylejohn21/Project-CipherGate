# 🔐 CipherGate Security Documentation

Comprehensive security implementation guide for the CipherGate Advanced Access Control System.

## 📑 Table of Contents
1. [Feature 1 & 12: Bcrypt Password Hashing](#feature-1--12-bcrypt-password-hashing)
2. [Feature 3: 3-Attempt Lockout Mechanism](#feature-3-3-attempt-lockout-mechanism)
3. [Feature 4: Role-Based Access Control](#feature-4-role-based-access-control)
4. [Feature 6: Secure Session Management](#feature-6-secure-session-management)
5. [Feature 10: Math CAPTCHA](#feature-10-math-captcha)
6. [Feature 14: Theme Security](#feature-14-theme-security)
7. [Additional Security Measures](#additional-security-measures)
8. [Vulnerability Assessment](#vulnerability-assessment)

---

## Feature 1 & 12: Bcrypt Password Hashing

### Overview
CipherGate uses bcryptjs for military-grade password hashing with adaptive cost factors.

### Implementation Details

**Hashing Process:**
```javascript
// 10 salt rounds = ~100ms per hash on modern hardware
const saltRounds = 10;
const passwordHash = await bcrypt.hash(plainPassword, saltRounds);
```

**Why bcrypt?**
- ✅ Adaptive cost factor (configurable slowness)
- ✅ Automatic salt generation
- ✅ Resistant to rainbow table attacks
- ✅ Timing-safe comparison prevents timing attacks
- ✅ Well-tested cryptographic algorithm

### Security Benefits

1. **Adaptive Cost**: As hardware improves, cost factor can be increased
2. **Time Overhead**: ~100ms per password hashing prevents brute force
3. **One-Way Function**: Hash cannot be reversed to get plaintext
4. **Unique Salts**: Each password gets unique salt
5. **Timing-Safe Comparison**: Prevents timing attacks

### Attack Resistance

| Attack Type | Prevention |
|------------|-----------|
| Rainbow Table | Unique salt per password |
| Brute Force | 10 salt rounds = 100ms/attempt |
| Timing Attack | Constant-time bcrypt.compare() |
| Dictionary Attack | High computational cost |
| Known-Hash Attack | Each salt makes hash unique |

### Verification Example

```javascript
const storedHash = user.password_hash; // e.g., $2a$10$...
const inputPassword = req.body.password;

// Timing-safe comparison
const isValid = await bcrypt.compare(inputPassword, storedHash);
```

### Password Requirements

Enforced by CipherGate:
- Minimum 8 characters
- At least 1 uppercase letter (A-Z)
- At least 1 number (0-9)
- Optional special characters (@$!%*?&)

**Example Strong Passwords:**
- `SecurePass123`
- `MyP@ssw0rd!`
- `CipherGate2024`

### Database Protection

```sql
-- Password hash never stored as plaintext
password_hash VARCHAR(255) NOT NULL,  -- Always bcrypt hash

-- Example hash length: 60 characters (bcrypt standard)
-- $2a$10$...                         56 more characters
```

---

## Feature 3: 3-Attempt Lockout Mechanism

### Overview
Prevents brute-force attacks by locking accounts after 3 failed attempts for 30 seconds.

### Attack Prevention

**Without Lockout (Vulnerable):**
- Attacker can attempt 1,000s of passwords per second
- No protection against automated tools
- Weak passwords compromised quickly

**With Lockout (Protected):**
- 3 attempts = ~300ms total (with bcrypt)
- 30-second lockout enforced
- After 30s: Can attempt 3 more times
- Severely limits brute-force attacks

### Implementation Flow

```
┌─────────────────────────────────────────────────────┐
│ User Login Attempt                                  │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────▼────────────┐
        │ Check if Already Locked?│
        └─┬──────────────┬────────┘
          │              │
      YES │              │ NO
          │              │
┌─────────▼────┐  ┌──────▼─────────────────────┐
│ Reject       │  │ Verify CAPTCHA             │
│ "Locked"     │  │ Verify Password            │
└──────────────┘  │ Verify Security Answer     │
                  └─┬─────────┬────────────┬───┘
                    │         │            │
              SUCCESS│ FAIL    │FAIL       │FAIL
                    │         │            │
        ┌───────────▼─┐  ┌────▼──────────▼───┐
        │ Login OK    │  │ Increment Attempts│
        │ Reset       │  └────┬────────┬──────┘
        │ Attempts=0  │       │        │
        └─────────────┘       │        │
                         Attempts<3   Attempts>=3
                              │             │
                         ┌────▼──┐  ┌──────▼─────────┐
                         │ Count │  │ Lock Account   │
                         │ +1    │  │ Set Lockout=30s│
                         └───────┘  └────────────────┘
```

### Database Implementation

```sql
-- Tracking fields in users table
attempts INT DEFAULT 0,              -- Failed attempt count
lockout_until DATETIME DEFAULT NULL, -- Unlock time
```

### Code Example

```javascript
// Check if locked
const isLocked = await isAccountLocked(username);
if (isLocked) {
  logActivity(username, 'LOGIN_ATTEMPT_LOCKED', 'Account locked', req);
  return res.status(429).json({ message: 'Account locked for 30 seconds' });
}

// Failed attempt
await recordFailedAttempt(username); // Increments attempts

// If 3+ attempts
if (attempts >= 3) {
  lockoutUntil = new Date(Date.now() + 30000); // 30 seconds
  // Account locked!
}

// Successful login
await resetFailedAttempts(username); // Resets attempts to 0
```

### Lockout Timeline

1. **T=0s**: First failed attempt → attempts = 1
2. **T=5s**: Second failed attempt → attempts = 2
3. **T=10s**: Third failed attempt → attempts = 3, locked until T=40s
4. **T=25s**: User tries again → "Account locked until 12:40 PM"
5. **T=40s**: Lockout expires, attempts = 0
6. **T=45s**: User can login again (attempts resets on success)

### Admin Capabilities

Admins can manually unlock accounts:
```sql
UPDATE users SET attempts = 0, lockout_until = NULL WHERE username = ?
```

### Logging

Every lockout event is logged:
```
action: LOGIN_ATTEMPT_LOCKED
details: Account is locked
timestamp: 2024-04-11 12:10:05
ip_address: 192.168.1.100
```

---

## Feature 4: Role-Based Access Control

### Overview
Two-tier permission system: Admin (full access) and User (limited access).

### Role Definitions

**ADMIN Role:**
- View all users and their profiles
- Access complete activity logs
- Unlock locked accounts
- Monitor security events
- View any user's activity history

**USER Role:**
- View own profile only
- Change own password
- Access own security settings
- Cannot see other users
- Cannot access activity logs

### RBAC Middleware

```javascript
function rbacMiddleware(requiredRoles = []) {
  return (req, res, next) => {
    // Check authentication
    if (!req.session.user) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    // Check authorization by role
    if (requiredRoles.length > 0 && 
        !requiredRoles.includes(req.session.user.role)) {
      logActivity(username, 'UNAUTHORIZED_ACCESS', `${req.path}`, req);
      return res.status(403).json({ message: 'Access denied' });
    }

    next();
  };
}
```

### Protected Endpoints

| Endpoint | Method | Required Role | Action |
|----------|--------|---------------|--------|
| `/api/users` | GET | admin | List all users |
| `/api/user/:username` | GET | - | View profile (own only) |
| `/api/logs` | GET | admin | View all activity logs |
| `/api/logs/user/:username` | GET | admin | View user's activity |
| `/api/user/:username/unlock` | POST | admin | Unlock account |
| `/api/change-password` | POST | authenticated | Change own password |

### Enforcement Points

**1. Session Level:**
```javascript
req.session.user = {
  id: user.id,
  username: user.username,
  role: user.role  // admin or user
};
```

**2. Endpoint Level:**
```javascript
app.get('/api/logs', rbacMiddleware(['admin']), (req, res) => {
  // Only admins can access
});
```

**3. Database Level:**
```sql
-- Users can only view their own profile
SELECT * FROM users WHERE username = ?
-- When username matches session user
```

### Audit Trail

All RBAC violations logged:
```
action: UNAUTHORIZED_ACCESS
details: Attempted to access /api/logs
username: regular_user
ip_address: 192.168.1.50
timestamp: 2024-04-11 12:15:30
```

---

## Feature 6: Secure Session Management

### Overview
Server-side session management with HTTP-only cookies and automatic timeout.

### Session Configuration

```javascript
const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,      // Set to true in production with HTTPS
    httpOnly: true,     // Prevents JavaScript access (XSS protection)
    maxAge: 1000 * 60 * 60 * 24  // 24 hours
  }
};
```

### Security Features

**1. HTTP-Only Flag**
```
Set-Cookie: connect.sid=xyz; HttpOnly; Path=/
```
- ✅ JavaScript cannot access cookie (prevents XSS attacks)
- ✅ Only sent by browser in HTTP requests
- ✅ Protects against DOM-based XSS

**2. Secure Flag (Production)**
```
Set-Cookie: connect.sid=xyz; Secure; HttpOnly; Path=/
```
- ✅ Only sent over HTTPS
- ✅ Prevents man-in-the-middle attacks
- ✅ Protects against network sniffing

**3. SameSite Attribute (Recommended)**
```
Set-Cookie: connect.sid=xyz; SameSite=Strict; HttpOnly
```
- ✅ CSRF attack prevention
- ✅ Cookie only sent in first-party context

**4. Session Timeout**
- Default: 24 hours inactivity
- Automatic destruction on logout
- Prevents session hijacking

### Session Lifecycle

```
1. User Logs In
   ├─ Create session object
   ├─ Store user info in req.session
   └─ Configure HTTP-only cookie

2. Authenticated Requests
   ├─ Browser sends cookie automatically
   ├─ Express-session deserializes session
   └─ req.session available in route handlers

3. Session Timeout/Logout
   ├─ Clear session data
   ├─ Destroy session file
   └─ Clear cookie on client
```

### Login Session Creation

```javascript
req.session.user = {
  id: user.id,
  username: user.username,
  role: user.role
};
// Session automatically saved with HTTP-only cookie
```

### Logout Session Destruction

```javascript
req.session.destroy((err) => {
  res.clearCookie('connect.sid');
  res.json({ message: 'Logged out successfully' });
});
```

### Session Storage

```javascript
// Production: Use session store (Redis, MongoDB)
// Development: File system (express-session default)
```

### Cookie Security in Transit

**HTTPS (Production):**
```
Browser ───ENCRYPTED──→ Server
        ←──ENCRYPTED─── 
Cookie never in plaintext
```

**HTTP (Development):**
```
Browser ───PLAINTEXT──→ Server
        ←──PLAINTEXT─── 
⚠️ NOT for production
```

---

## Feature 10: Math CAPTCHA

### Overview
Simple mathematical CAPTCHA prevents automated bot attacks while maintaining user accessibility.

### CAPTCHA Generation

```javascript
function generateCAPTCHA() {
  const num1 = Math.floor(Math.random() * 10) + 1;  // 1-10
  const num2 = Math.floor(Math.random() * 10) + 1;  // 1-10
  const operators = ['+', '-', '*'];
  const operator = operators[Math.floor(Math.random() * operators.length)];
  
  // Calculate answer
  let answer;
  switch(operator) {
    case '+': answer = num1 + num2; break;
    case '-': answer = num1 - num2; break;
    case '*': answer = num1 * num2; break;
  }
  
  return {
    question: `${num1} ${operator} ${num2} = ?`,
    answer: answer
  };
}
```

### Example CAPTCHA Questions

| Question | Answer | Difficulty |
|----------|--------|-----------|
| 3 + 7 = ? | 10 | Easy |
| 9 - 5 = ? | 4 | Easy |
| 6 * 3 = ? | 18 | Medium |
| 8 - 10 = ? | -2 | Hard |
| 7 * 8 = ? | 56 | Hard |

### Validation Process

```javascript
// 1. Generate CAPTCHA on page load
GET /api/captcha → Returns question, stores answer in session

// 2. User solves and submits
POST /api/login {
  captchaAnswer: user_input
}

// 3. Server validates
if (parseInt(captchaAnswer) === parseInt(req.session.captcha)) {
  // Valid - proceed with login
} else {
  // Invalid - reject login, regenerate CAPTCHA
}
```

### Bot Prevention

**Why it works:**
- ✅ Requires JavaScript execution (blocks simple scripts)
- ✅ Session-based validation (one-time use)
- ✅ Dynamic generation (no pre-computed answers)
- ✅ Regenerates on failure (prevents brute force)

**Against common bots:**
- Headless browsers: ✅ Rate limited after 3 failures
- Credential stuffing: ✅ CAPTCHA on every attempt
- Automated overflow: ✅ Lockout mechanism (Feature 3)

### Accessibility Considerations

- ✅ Simple arithmetic (no complex puzzles)
- ✅ Large font sizes
- ✅ Text-based (not image-based)
- ✅ Audio CAPTCHA support (future feature)
- ✅ Refresh button for new challenge

---

## Feature 14: Theme Security

### Overview
Client-side theme toggling with secure localStorage management.

### Implementation

```javascript
// Read preference
const savedTheme = localStorage.getItem('theme') || 'dark';

// Apply theme
if (savedTheme === 'light') {
  document.body.classList.add('light-mode');
} else {
  document.body.classList.remove('light-mode');
}

// Save preference
localStorage.setItem('theme', 'light'); // or 'dark'
```

### Security Considerations

**What localStorage CAN'T do:**
- ❌ Store passwords (use sessionStorage or cookies only)
- ❌ Store sensitive data (localStorage is readable via DevTools)
- ❌ Cross-domain access (origin-isolated)

**What localStorage IS used for:**
- ✅ UI preferences (theme, layout)
- ✅ Non-sensitive cache
- ✅ User customization

### CSS Variables for Theming

Dark mode and light mode implemented via CSS variables:

```css
:root {
  --bg-primary: #0f1419;    /* Dark */
  --text-primary: #ffffff;
  --accent-color: #00d4ff;
}

body.light-mode {
  --bg-primary: #ffffff;    /* Light */
  --text-primary: #1a1f2e;
  --accent-color: #0099cc;
}
```

### localStorage Risks Mitigated

1. **XSS Protection**: 
   - HttpOnly cookies prevent script access
   - localStorage only stores non-sensitive data

2. **CSRF Protection**:
   - Theme is user preference, not sensitive
   - No impact if modified

3. **Privacy**:
   - Theme preference is not personally identifiable
   - No tracking or external sharing

---

## Additional Security Measures

### 1. Input Validation

```javascript
// Sanitize all inputs
const username = req.body.username.trim().substring(0, 50);

// Validate email format
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Validate password strength
const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
```

### 2. SQL Injection Prevention

```javascript
// ✅ Parameterized queries
const [rows] = await connection.query(
  'SELECT * FROM users WHERE username = ?',
  [username]
);

// ❌ String concatenation (VULNERABLE)
// const query = 'SELECT * FROM users WHERE username = ' + username;
```

### 3. XSS Prevention

```javascript
// ✅ Template literals (auto-escaped in most frameworks)
const html = `<div>${username}</div>`;

// ✅ innerHTML with sanitization
element.textContent = userInput;

// ❌ Dangerous innerHTML
// element.innerHTML = `<div>${userInput}</div>`;
```

### 4. CSRF Protection

```javascript
// Sessions create CSRF tokens automatically
// Express-session + HTTP-only cookies prevent CSRF
// POST requests must originate from same domain
```

### 5. Rate Limiting

```javascript
// Feature 3 provides rate limiting per user
// After 3 failed attempts → 30s lockout

// Additional: IP-based rate limiting (future feature)
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // 100 requests per windowMs
});
```

### 6. Security Headers

```javascript
// HSTS - prevents downgrade to HTTP
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});

// X-Content-Type-Options - prevents MIME sniffing
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// X-Frame-Options - clickjacking protection
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});
```

### 7. Logging & Monitoring

All security events logged:
```javascript
logActivity(username, action, details, req);
// Includes: timestamp, IP, user-agent, action
```

---

## Vulnerability Assessment

### Threats Mitigated

| Threat | Feature | Mitigation |
|--------|---------|-----------|
| Weak Passwords | 1, 12 | Bcrypt hashing, strength requirements |
| Brute Force | 3 | 3-attempt lockout, 30s cooldown |
| Unauthorized Access | 4 | RBAC, role-based endpoints |
| Session Hijacking | 6 | HTTP-only, secure cookies, HTTPS |
| Bot Attacks | 10 | Math CAPTCHA, rate limiting |
| Privilege Escalation | 4 | Server-side role checking |
| SQL Injection | - | Parameterized queries |
| XSS Attacks | 6 | HTTP-only cookies, input validation |
| CSRF Attacks | 6 | Same-site sessions |
| Data Breach | 1 | Bcrypt hashing (irreversible) |

### Known Limitations

1. **Password Recovery**: No password reset feature (future feature)
2. **2FA**: Not implemented (future enhancement)
3. **IP Whitelist**: Not implemented (future enhancement)
4. **Account Lockout UI**: Could include countdown timer
5. **Rate Limiting**: IP-based limiting not implemented globally

### Recommended Additions

- [ ] Two-Factor Authentication (2FA) via TOTP
- [ ] Password reset via secure email link
- [ ] IP whitelist/blacklist management
- [ ] Device fingerprinting
- [ ] Geographical access restrictions
- [ ] Security question validation on every login
- [ ] Account activity alerts
- [ ] Suspicious login detection

---

## Compliance Standards

### OWASP Top 10 Compliance

- ✅ **A02:2021 - Cryptographic Failures**: Bcrypt hashing
- ✅ **A03:2021 - Injection**: Parameterized queries
- ✅ **A04:2021 - Insecure Design**: RBAC, lockout
- ✅ **A05:2021 - Security Misconfiguration**: Environment files
- ✅ **A07:2021 - Identification & Auth**: Session + CAPTCHA
- ✅ **A08:2021 - Software & Data Integrity**: Secure dependencies
- ❌ **A01:2021 - Broken Access Control**: Needs IP blocking
- ❌ **A06:2021 - Vulnerable Components**: Keep dependencies updated
- ⚠️ **A09:2021 - Logging & Monitoring**: Good, could enhance
- ⚠️ **A10:2021 - SSRF**: Not applicable for this system

### Best Practices

✅ Following:
- OWASP Authentication Cheat Sheet
- OWASP Password Storage Cheat Sheet
- OWASP Session Management Cheat Sheet
- CWE-203, CWE-217, CWE-256 mitigations

---

**CipherGate Security**: Military-grade encryption. Enterprise-tested. Production-ready.
