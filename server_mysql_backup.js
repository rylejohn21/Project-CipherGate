// ============================================================================
// CIPHERGATE: Advanced Code Breaker Security System
// Secure Access Control Server with RBAC & Session Management
// ============================================================================

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================================
// SECURITY CONFIGURATION - Feature 6: Session Management
// ============================================================================

const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true, // Prevents XSS attacks
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  }
};

// ============================================================================
// DATABASE POOL CONFIGURATION - Feature 1 & 12: MySQL Integration
// ============================================================================

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'ciphergate',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ============================================================================
// MIDDLEWARE SETUP
// ============================================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session(sessionConfig));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// SECURITY UTILITY FUNCTIONS
// ============================================================================

/**
 * Feature 1 & 12: Bcrypt Password Hashing
 * Securely hashes passwords using bcryptjs with 10 salt rounds
 * @param {string} password - Plain text password to hash
 * @returns {Promise<string>} Hashed password
 */
async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

/**
 * Feature 1 & 12: Bcrypt Password Verification
 * Compares plain text password with stored hash
 * @param {string} password - Plain text password
 * @param {string} hash - Stored password hash
 * @returns {Promise<boolean>} True if password matches
 */
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

/**
 * Feature 10: Generate Math CAPTCHA Challenge
 * Creates a simple arithmetic problem for CAPTCHA verification
 * @returns {Object} CAPTCHA challenge with operands, operator, and answer
 */
function generateCAPTCHA() {
  const num1 = Math.floor(Math.random() * 10) + 1;
  const num2 = Math.floor(Math.random() * 10) + 1;
  const operators = ['+', '-', '*'];
  const operator = operators[Math.floor(Math.random() * operators.length)];
  
  let answer;
  switch(operator) {
    case '+':
      answer = num1 + num2;
      break;
    case '-':
      answer = num1 - num2;
      break;
    case '*':
      answer = num1 * num2;
      break;
  }
  
  return {
    question: `${num1} ${operator} ${num2}`,
    answer: answer
  };
}

/**
 * Feature 3: Check Account Lockout Status
 * Checks if account is locked due to failed attempts
 * @param {string} username - User to check lockout status
 * @returns {Promise<boolean>} True if account is locked
 */
async function isAccountLocked(username) {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query(
      'SELECT lockout_until FROM users WHERE username = ?',
      [username]
    );
    connection.release();

    if (rows.length === 0) return false;
    
    const lockoutUntil = rows[0].lockout_until;
    if (!lockoutUntil) return false;
    
    const now = new Date();
    if (now < new Date(lockoutUntil)) {
      return true;
    }
    
    // Unlock account if lockout period has expired
    const connection2 = await pool.getConnection();
    await connection2.query(
      'UPDATE users SET lockout_until = NULL, attempts = 0 WHERE username = ?',
      [username]
    );
    connection2.release();
    
    return false;
  } catch (error) {
    console.error('Error checking account lockout:', error);
    return false;
  }
}

/**
 * Feature 3: Record Failed Login Attempt
 * Increments attempt counter and applies lockout after 3 attempts
 * @param {string} username - User with failed attempt
 */
async function recordFailedAttempt(username) {
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query(
      'SELECT attempts FROM users WHERE username = ?',
      [username]
    );
    
    const currentAttempts = rows[0].attempts + 1;
    
    if (currentAttempts >= 3) {
      // Lock account for 30 seconds
      const lockoutUntil = new Date(Date.now() + 30000);
      await connection.query(
        'UPDATE users SET attempts = ?, lockout_until = ? WHERE username = ?',
        [currentAttempts, lockoutUntil, username]
      );
      console.log(`Account locked for ${username} until ${lockoutUntil}`);
    } else {
      await connection.query(
        'UPDATE users SET attempts = ? WHERE username = ?',
        [currentAttempts, username]
      );
    }
    
    connection.release();
  } catch (error) {
    console.error('Error recording failed attempt:', error);
  }
}

/**
 * Feature 3: Reset Failed Attempts
 * Clears attempt counter on successful login
 * @param {string} username - User with successful login
 */
async function resetFailedAttempts(username) {
  try {
    const connection = await pool.getConnection();
    await connection.query(
      'UPDATE users SET attempts = 0, lockout_until = NULL WHERE username = ?',
      [username]
    );
    connection.release();
  } catch (error) {
    console.error('Error resetting failed attempts:', error);
  }
}

/**
 * Feature 4: Log User Activity
 * Records all user actions for audit trail
 * @param {string} username - User performing action
 * @param {string} action - Action being performed
 * @param {string} details - Additional details
 * @param {Object} req - Express request object for IP tracking
 */
async function logActivity(username, action, details = '', req = null) {
  try {
    const connection = await pool.getConnection();
    const ip = req ? req.ip || req.connection.remoteAddress : 'unknown';
    const userAgent = req ? req.get('user-agent') || 'unknown' : 'unknown';
    
    await connection.query(
      'INSERT INTO logs (username, action, details, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
      [username, action, details, ip, userAgent]
    );
    connection.release();
  } catch (error) {
    console.error('Error logging activity:', error);
  }
}

/**
 * Feature 4: RBAC Authentication Middleware
 * Checks if user is authenticated and has required role
 * @param {Array} requiredRoles - Array of roles allowed to access route
 */
function rbacMiddleware(requiredRoles = []) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    if (requiredRoles.length > 0 && !requiredRoles.includes(req.session.user.role)) {
      logActivity(req.session.user.username, 'UNAUTHORIZED_ACCESS', `Attempted to access ${req.path}`);
      return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
    }

    next();
  };
}

// ============================================================================
// ROUTES: AUTHENTICATION
// ============================================================================

/**
 * Route: GET /api/captcha
 * Feature 10: Generate and return CAPTCHA challenge
 */
app.get('/api/captcha', (req, res) => {
  const captcha = generateCAPTCHA();
  req.session.captcha = captcha.answer;
  
  res.json({
    question: captcha.question,
    sessionId: req.sessionID
  });
});

/**
 * Route: POST /api/login
 * Feature 1 & 12: Authenticate user with bcrypt password verification
 * Feature 3: Apply lockout after 3 failed attempts
 * Feature 6: Create session on successful login
 * Feature 10: Validate CAPTCHA before login
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, captchaAnswer, securityAnswer } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }

    // Feature 3: Check if account is locked
    if (await isAccountLocked(username)) {
      logActivity(username, 'LOGIN_ATTEMPT_LOCKED', 'Account is locked', req);
      return res.status(429).json({ 
        message: 'Account locked due to multiple failed attempts. Try again in 30 seconds.' 
      });
    }

    // Feature 10: Verify CAPTCHA
    if (!captchaAnswer || parseInt(captchaAnswer) !== parseInt(req.session.captcha)) {
      logActivity(username, 'LOGIN_CAPTCHA_FAILURE', 'Invalid CAPTCHA', req);
      return res.status(400).json({ message: 'Invalid CAPTCHA' });
    }

    // Retrieve user from database
    const connection = await pool.getConnection();
    const [rows] = await connection.query(
      'SELECT id, username, password_hash, role, security_question, security_answer FROM users WHERE username = ?',
      [username]
    );
    connection.release();

    if (rows.length === 0) {
      logActivity(username, 'LOGIN_FAILURE', 'User not found', req);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = rows[0];

    // Feature 1 & 12: Verify password using bcrypt
    const passwordMatch = await verifyPassword(password, user.password_hash);
    if (!passwordMatch) {
      await recordFailedAttempt(username);
      logActivity(username, 'LOGIN_FAILURE', 'Invalid password', req);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify Security Question Answer
    if (user.security_answer && securityAnswer) {
      if (securityAnswer.toLowerCase() !== user.security_answer.toLowerCase()) {
        await recordFailedAttempt(username);
        logActivity(username, 'LOGIN_SECURITY_FAILURE', 'Invalid security answer', req);
        return res.status(401).json({ message: 'Invalid security answer' });
      }
    }

    // Feature 3: Reset failed attempts on successful login
    await resetFailedAttempts(username);

    // Feature 6: Create and establish session
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role
    };

    logActivity(username, 'LOGIN_SUCCESS', 'User logged in successfully', req);
    res.json({ 
      message: 'Login successful', 
      user: req.session.user,
      redirect: user.role === 'admin' ? '/admin_dashboard.html' : '/user_dashboard.html'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * Route: POST /api/register
 * Feature 1 & 12: Register new user with bcrypt password hashing
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, securityQuestion, securityAnswer } = req.body;

    if (!username || !password || !securityQuestion || !securityAnswer) {
      return res.status(400).json({ message: 'All fields required' });
    }

    // Validate password strength (at least 8 chars, 1 uppercase, 1 number)
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ 
        message: 'Password must be at least 8 chars with 1 uppercase letter and 1 number' 
      });
    }

    // Feature 1 & 12: Hash password before storing
    const passwordHash = await hashPassword(password);

    const connection = await pool.getConnection();
    try {
      // Check if username already exists
      const [existing] = await connection.query(
        'SELECT id FROM users WHERE username = ?',
        [username]
      );

      if (existing.length > 0) {
        return res.status(409).json({ message: 'Username already exists' });
      }

      // Insert new user
      await connection.query(
        'INSERT INTO users (username, password_hash, security_question, security_answer) VALUES (?, ?, ?, ?)',
        [username, passwordHash, securityQuestion, securityAnswer]
      );

      logActivity(username, 'USER_REGISTRATION', 'New user registered', req);
      res.status(201).json({ message: 'User registered successfully' });

    } finally {
      connection.release();
    }

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * Route: GET /api/current-user
 * Feature 6: Get current logged-in user information
 */
app.get('/api/current-user', rbacMiddleware(), (req, res) => {
  res.json(req.session.user);
});

/**
 * Route: POST /api/logout
 * Feature 6: Secure session logout
 */
app.post('/api/logout', (req, res) => {
  if (req.session.user) {
    const username = req.session.user.username;
    logActivity(username, 'LOGOUT', 'User logged out', req);
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', error);
      return res.status(500).json({ message: 'Logout failed' });
    }
    res.clearCookie('connect.sid'); // Default session cookie name
    res.json({ message: 'Logged out successfully' });
  });
});

// ============================================================================
// ROUTES: USER MANAGEMENT (Feature 4: RBAC)
// ============================================================================

/**
 * Route: GET /api/users
 * Feature 4: Admin only - retrieve all users
 */
app.get('/api/users', rbacMiddleware(['admin']), async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT id, username, role, attempts, lockout_until, created_at FROM users'
    );
    connection.release();

    logActivity(req.session.user.username, 'VIEW_ALL_USERS', 'Admin viewed user list', req);
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * Route: GET /api/user/:username
 * Feature 4: User can only see their own profile; Admin can see any
 */
app.get('/api/user/:username', rbacMiddleware(), async (req, res) => {
  try {
    const { username } = req.params;
    const currentUser = req.session.user;

    // Regular users can only view their own profile
    if (currentUser.role === 'user' && currentUser.username !== username) {
      logActivity(currentUser.username, 'UNAUTHORIZED_USER_VIEW', `Attempted to view ${username}`, req);
      return res.status(403).json({ message: 'Cannot view other user profiles' });
    }

    const connection = await pool.getConnection();
    const [rows] = await connection.query(
      'SELECT id, username, role, created_at FROM users WHERE username = ?',
      [username]
    );
    connection.release();

    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * Route: POST /api/user/:username/unlock
 * Feature 4: Admin only - unlock locked account
 * Feature 3: Reset lockout status
 */
app.post('/api/user/:username/unlock', rbacMiddleware(['admin']), async (req, res) => {
  try {
    const { username } = req.params;

    const connection = await pool.getConnection();
    await connection.query(
      'UPDATE users SET attempts = 0, lockout_until = NULL WHERE username = ?',
      [username]
    );
    connection.release();

    logActivity(req.session.user.username, 'UNLOCK_ACCOUNT', `Unlocked account for ${username}`, req);
    res.json({ message: `Account ${username} unlocked successfully` });
  } catch (error) {
    console.error('Error unlocking account:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * Route: POST /api/change-password
 * Feature 1 & 12: Change user password with bcrypt hashing
 */
app.post('/api/change-password', rbacMiddleware(), async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const username = req.session.user.username;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current and new password required' });
    }

    const connection = await pool.getConnection();
    const [rows] = await connection.query(
      'SELECT password_hash FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'User not found' });
    }

    // Feature 1 & 12: Verify current password
    const passwordMatch = await verifyPassword(currentPassword, rows[0].password_hash);
    if (!passwordMatch) {
      connection.release();
      logActivity(username, 'PASSWORD_CHANGE_FAILURE', 'Invalid current password', req);
      return res.status(401).json({ message: 'Current password incorrect' });
    }

    // Feature 1 & 12: Hash new password
    const newPasswordHash = await hashPassword(newPassword);
    await connection.query(
      'UPDATE users SET password_hash = ? WHERE username = ?',
      [newPasswordHash, username]
    );
    connection.release();

    logActivity(username, 'PASSWORD_CHANGED', 'User changed password', req);
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ============================================================================
// ROUTES: ACTIVITY LOGS (Feature 4: RBAC)
// ============================================================================

/**
 * Route: GET /api/logs
 * Feature 4: Admin only - retrieve all activity logs
 */
app.get('/api/logs', rbacMiddleware(['admin']), async (req, res) => {
  try {
    const connection = await pool.getConnection();
    const [logs] = await connection.query(
      `SELECT id, username, action, details, ip_address, timestamp 
       FROM logs 
       ORDER BY timestamp DESC 
       LIMIT 100`
    );
    connection.release();

    logActivity(req.session.user.username, 'VIEW_LOGS', 'Admin viewed activity logs', req);
    res.json(logs);
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * Route: GET /api/logs/user/:username
 * Feature 4: Admin only - retrieve logs for specific user
 */
app.get('/api/logs/user/:username', rbacMiddleware(['admin']), async (req, res) => {
  try {
    const { username } = req.params;

    const connection = await pool.getConnection();
    const [logs] = await connection.query(
      `SELECT id, username, action, details, ip_address, timestamp 
       FROM logs 
       WHERE username = ? 
       ORDER BY timestamp DESC 
       LIMIT 50`,
      [username]
    );
    connection.release();

    logActivity(req.session.user.username, 'VIEW_USER_LOGS', `Viewed logs for ${username}`, req);
    res.json(logs);
  } catch (error) {
    console.error('Error fetching user logs:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ============================================================================
// ROUTES: STATUS ENDPOINTS
// ============================================================================

/**
 * Route: GET /
 * Serve main landing page
 */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/**
 * Route: GET /api/status
 * Health check endpoint
 */
app.get('/api/status', (req, res) => {
  res.json({ status: 'CipherGate Security System is online', timestamp: new Date() });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// ============================================================================
// SERVER STARTUP
// ============================================================================

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║   CIPHERGATE Security System Online    ║
║   Advanced Access Control Running      ║
╚════════════════════════════════════════╝
Server running on: http://localhost:${PORT}
Database: Connected to MySQL
  `);
});

module.exports = app;
