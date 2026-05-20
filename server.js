// ============================================================================
// CIPHERGATE: Advanced Code Breaker Security System
// Secure Access Control Server with RBAC & Session Management
// ============================================================================

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const RESET_CODE_EXPIRY_MINUTES = parseInt(process.env.RESET_CODE_EXPIRY_MINUTES || '10', 10);
const LOGIN_OTP_EXPIRY_MINUTES = parseInt(process.env.LOGIN_OTP_EXPIRY_MINUTES || '10', 10);
const ALLOWED_SECURITY_QUESTIONS = [
  'What is your favorite color?',
  'What are your favorite animals?'
];
const DEMO_USERS = [
  {
    username: 'admin',
    password_hash: '$2a$10$v73.4y9DaFQgtH1iBBnrlurQ8i8DtPRTaTX8uk5qnFpSJwzFkRYJa',
    email: 'admin@example.com',
    mobile_number: '+15550000001',
    role: 'admin',
    security_question: 'What is your favorite color?',
    security_answer: 'blue',
    attempts: 0,
    failed_login_count: 0,
    lockout_until: null
  },
  {
    username: 'testuser',
    password_hash: '$2a$10$dvy11AoYqqret.hDfF1t0O/D8sWxhgOQUvTKAEGmzX9ocUo3i4exi',
    email: 'testuser@example.com',
    mobile_number: '+15550000002',
    role: 'user',
    security_question: 'What are your favorite animals?',
    security_answer: 'fluffy',
    attempts: 0,
    failed_login_count: 0,
    lockout_until: null
  }
];
let nodemailer = null;

try {
  nodemailer = require('nodemailer');
} catch (error) {
  console.warn('nodemailer is not installed. Email reset delivery is unavailable.');
}

// ============================================================================
// SECURITY CONFIGURATION - Feature 6: Session Management
// ============================================================================

const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true, // Prevents XSS attacks
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
};

// ============================================================================
// SUPABASE CONFIGURATION - Feature 1 & 12: Supabase Integration
// ============================================================================

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  throw new Error('Missing Supabase configuration. Set SUPABASE_URL and SUPABASE_ANON_KEY in your .env file.');
}

const supabase = createClient(supabaseUrl, supabaseKey);

class SupabaseSessionStore extends session.Store {
  constructor(options = {}) {
    super();
    this.supabase = options.supabase;
    this.tableName = options.tableName || 'sessions';
  }

  get(sid, callback) {
    this.supabase
      .from(this.tableName)
      .select('sess, expire')
      .eq('sid', sid)
      .single()
      .then(({ data, error }) => {
        if (error || !data) {
          callback(null, null);
          return;
        }

        if (data.expire && new Date(data.expire) <= new Date()) {
          this.destroy(sid, () => callback(null, null));
          return;
        }

        callback(null, data.sess);
      })
      .catch((error) => callback(error));
  }

  set(sid, sessionData, callback = () => {}) {
    const expire = sessionData?.cookie?.expires
      ? new Date(sessionData.cookie.expires).toISOString()
      : new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

    this.supabase
      .from(this.tableName)
      .upsert([{ sid, sess: sessionData, expire }], { onConflict: 'sid' })
      .then(({ error }) => callback(error || null))
      .catch((error) => callback(error));
  }

  destroy(sid, callback = () => {}) {
    this.supabase
      .from(this.tableName)
      .delete()
      .eq('sid', sid)
      .then(({ error }) => callback(error || null))
      .catch((error) => callback(error));
  }

  touch(sid, sessionData, callback = () => {}) {
    const expire = sessionData?.cookie?.expires
      ? new Date(sessionData.cookie.expires).toISOString()
      : new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

    this.supabase
      .from(this.tableName)
      .update({ expire })
      .eq('sid', sid)
      .then(({ error }) => callback(error || null))
      .catch((error) => callback(error));
  }
}

// ============================================================================
// MIDDLEWARE SETUP
// ============================================================================

sessionConfig.store = new SupabaseSessionStore({ supabase, tableName: 'sessions' });
sessionConfig.name = 'ciphergate.sid';
sessionConfig.rolling = true;

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

function isAllowedOrigin(origin = '') {
  if (!origin) return false;

  if (allowedOrigins.includes(origin)) {
    return true;
  }

  return /^https?:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin)
    || /^https:\/\/[a-z0-9-]+\.github\.io$/i.test(origin)
    || /^https:\/\/[a-z0-9-]+\.vercel\.app$/i.test(origin);
}

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }

  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

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

function normalizeEmail(email = '') {
  return email.trim().toLowerCase();
}

function normalizePhoneNumber(phoneNumber = '') {
  const trimmed = phoneNumber.trim();
  if (!trimmed) return '';

  const digitsOnly = trimmed.replace(/\D/g, '');

  if (trimmed.startsWith('+')) {
    return `+${digitsOnly}`;
  }

  // PH local mobile formats:
  // 09XXXXXXXXX -> +639XXXXXXXXX
  // 639XXXXXXXXX -> +639XXXXXXXXX
  if (/^09\d{9}$/.test(digitsOnly)) {
    return `+63${digitsOnly.slice(1)}`;
  }

  if (/^639\d{9}$/.test(digitsOnly)) {
    return `+${digitsOnly}`;
  }

  return digitsOnly;
}

function normalizeUsername(username = '') {
  return username.trim();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizeEmail(email));
}

function isValidPhoneNumber(phoneNumber) {
  const normalized = normalizePhoneNumber(phoneNumber);
  return /^\+?\d{10,15}$/.test(normalized);
}

function generateResetCode() {
  return `${crypto.randomInt(100000, 1000000)}`;
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function signValue(value) {
  return crypto
    .createHmac('sha256', sessionConfig.secret)
    .update(value)
    .digest('base64url');
}

function createCaptchaToken(answer) {
  const payload = JSON.stringify({
    answer,
    expiresAt: Date.now() + 1000 * 60 * 10,
    nonce: crypto.randomBytes(16).toString('hex')
  });
  const encodedPayload = base64UrlEncode(payload);
  const signature = signValue(encodedPayload);

  return `${encodedPayload}.${signature}`;
}

function verifyCaptchaToken(token, submittedAnswer) {
  if (!token || !submittedAnswer) {
    return false;
  }

  const [encodedPayload, signature] = token.split('.');
  if (!encodedPayload || !signature) {
    return false;
  }

  const expectedSignature = signValue(encodedPayload);
  const providedSignature = Buffer.from(signature);
  const validSignature = Buffer.from(expectedSignature);

  if (
    providedSignature.length !== validSignature.length
    || !crypto.timingSafeEqual(providedSignature, validSignature)
  ) {
    return false;
  }

  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload));

    if (!payload.expiresAt || Date.now() > payload.expiresAt) {
      return false;
    }

    return parseInt(submittedAnswer, 10) === parseInt(payload.answer, 10);
  } catch (error) {
    return false;
  }
}

function hashResetCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

async function sendResetCodeByEmail(email, username, code) {
  if (!nodemailer) {
    throw new Error('Email delivery dependency is not installed.');
  }

  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    throw new Error('Gmail reset delivery is not configured.');
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD
    }
  });

  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.GMAIL_USER,
    to: email,
    subject: 'CipherGate Password Reset Code',
    text: `Hello ${username}, your CipherGate password reset code is ${code}. It expires in ${RESET_CODE_EXPIRY_MINUTES} minutes.`,
    html: `<p>Hello <strong>${username}</strong>,</p><p>Your CipherGate password reset code is:</p><h2 style="letter-spacing: 4px;">${code}</h2><p>This code expires in ${RESET_CODE_EXPIRY_MINUTES} minutes.</p>`
  });
}

/**
 * Feature 10: Generate Math CAPTCHA Challenge
 * Creates a simple arithmetic problem for CAPTCHA verification
 * @returns {Object} CAPTCHA challenge with question and signed token
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
    answer,
    captchaToken: createCaptchaToken(answer)
  };
}

async function sendLoginOtpByEmail(email, username, code) {
  if (!nodemailer) {
    throw new Error('Email delivery dependency is not installed.');
  }

  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    throw new Error('Gmail OTP delivery is not configured.');
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD
    }
  });

  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.GMAIL_USER,
    to: email,
    subject: 'CipherGate Login OTP',
    text: `Hello ${username}, your CipherGate login OTP is ${code}. It expires in ${LOGIN_OTP_EXPIRY_MINUTES} minutes.`,
    html: `<p>Hello <strong>${username}</strong>,</p><p>Your CipherGate login OTP is:</p><h2 style="letter-spacing: 4px;">${code}</h2><p>This code expires in ${LOGIN_OTP_EXPIRY_MINUTES} minutes.</p>`
  });
}

function maskEmail(email = '') {
  const [localPart, domain] = email.split('@');

  if (!localPart || !domain) {
    return 'your registered email';
  }

  const visibleLocal = localPart.length <= 2
    ? `${localPart[0] || ''}*`
    : `${localPart.slice(0, 2)}${'*'.repeat(Math.min(localPart.length - 2, 4))}`;

  return `${visibleLocal}@${domain}`;
}

async function createPendingLogin(req, user, email) {
  const otpCode = generateResetCode();

  await sendLoginOtpByEmail(email, user.username, otpCode);

  req.session.pendingLogin = {
    user: {
      id: user.id,
      username: user.username,
      role: user.role
    },
    email,
    otpHash: hashResetCode(otpCode),
    expiresAt: Date.now() + LOGIN_OTP_EXPIRY_MINUTES * 60 * 1000
  };
}

function isLoginOtpExemptUser(user) {
  return ['admin', 'testuser'].includes((user?.username || '').toLowerCase());
}

function createAuthenticatedSession(req, user) {
  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role
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
    const { data, error } = await supabase
      .from('users')
      .select('lockout_until')
      .eq('username', username)
      .single();

    if (error || !data) return false;
    
    const lockoutUntil = data.lockout_until;
    if (!lockoutUntil) return false;
    
    const now = new Date();
    if (now < new Date(lockoutUntil)) {
      return true;
    }
    
    // Unlock account if lockout period has expired
    await supabase.from('users').update({ lockout_until: null, attempts: 0 }).eq('username', username);
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
    const { data } = await supabase
      .from('users')
      .select('attempts, failed_login_count')
      .eq('username', username)
      .single();
    const currentAttempts = (data?.attempts || 0) + 1;
    const failedLoginCount = (data?.failed_login_count || 0) + 1;
    
    if (currentAttempts >= 3) {
      // Lock account for 30 seconds
      const lockoutUntil = new Date(Date.now() + 30000);
      await supabase
        .from('users')
        .update({
          attempts: currentAttempts,
          failed_login_count: failedLoginCount,
          lockout_until: lockoutUntil
        })
        .eq('username', username);
      console.log(`Account locked for ${username} until ${lockoutUntil}`);
    } else {
      await supabase
        .from('users')
        .update({ attempts: currentAttempts, failed_login_count: failedLoginCount })
        .eq('username', username);
    }
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
    await supabase
      .from('users')
      .update({ attempts: 0, lockout_until: null })
      .eq('username', username);
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
    const ip = req ? req.ip || req.connection.remoteAddress : 'unknown';
    const userAgent = req ? req.get('user-agent') || 'unknown' : 'unknown';
    
    await supabase.from('logs').insert([{ 
      username, 
      action, 
      details, 
      ip_address: ip, 
      user_agent: userAgent 
    }]);
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
      logActivity(req.session.user.username, 'UNAUTHORIZED_ACCESS', `Attempted to access ${req.path}`, req);
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
 * Returns a signed token so validation does not depend on session refresh timing
 */
app.get('/api/captcha', (req, res) => {
  const captcha = generateCAPTCHA();

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

  res.json({
    question: captcha.question,
    captchaToken: captcha.captchaToken
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
    const { username, password, captchaAnswer, captchaToken, securityAnswer } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password required' });
    }

    // Feature 3: Check if account is locked
    const normalizedUsername = normalizeUsername(username);

    if (await isAccountLocked(normalizedUsername)) {
      logActivity(normalizedUsername, 'LOGIN_ATTEMPT_LOCKED', 'Account is locked', req);
      return res.status(429).json({ 
        message: 'Account locked due to multiple failed attempts. Try again in 30 seconds.' 
      });
    }

    // Feature 10: Verify CAPTCHA
    if (!captchaToken) {
      return res.status(400).json({ message: 'CAPTCHA expired. Click New and solve the latest CAPTCHA.' });
    }

    if (!verifyCaptchaToken(captchaToken, captchaAnswer)) {
      if (normalizedUsername) {
        await recordFailedAttempt(normalizedUsername);
      }
      logActivity(normalizedUsername, 'LOGIN_CAPTCHA_FAILURE', 'Invalid CAPTCHA', req);
      return res.status(400).json({ message: 'Invalid CAPTCHA' });
    }

    // Retrieve user from database
    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, password_hash, role, email, security_question, security_answer')
      .ilike('username', normalizedUsername)
      .single();

    if (error && error.code !== 'PGRST116') {
      console.error('User lookup error:', error);
      return res.status(500).json({ message: 'Database connection error. Check your Supabase settings and internet connection.' });
    }

    if (!user) {
      logActivity(normalizedUsername, 'LOGIN_FAILURE', 'User not found', req);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Feature 1 & 12: Verify password using bcrypt
    const passwordMatch = await verifyPassword(password, user.password_hash);
    if (!passwordMatch) {
      await recordFailedAttempt(normalizedUsername);
      logActivity(normalizedUsername, 'LOGIN_FAILURE', 'Invalid password', req);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Verify Security Question Answer
    if (user.security_answer && securityAnswer) {
      if (securityAnswer.toLowerCase() !== user.security_answer.toLowerCase()) {
        await recordFailedAttempt(normalizedUsername);
        logActivity(normalizedUsername, 'LOGIN_SECURITY_FAILURE', 'Invalid security answer', req);
        return res.status(401).json({ message: 'Invalid security answer' });
      }
    }

    // Feature 3: Reset failed attempts on successful login
    await resetFailedAttempts(normalizedUsername);

    if (isLoginOtpExemptUser(user)) {
      createAuthenticatedSession(req, user);
      await logActivity(username, 'LOGIN_SUCCESS', 'Demo account logged in without OTP', req);
      return res.json({
        message: 'Login successful.',
        user: req.session.user,
        redirect: req.session.user.role === 'admin' ? '/admin_dashboard.html' : '/user_dashboard.html'
      });
    }

    if (!user.email || !isValidEmail(user.email)) {
      return res.status(400).json({ message: 'This account does not have a valid email for OTP verification' });
    }

    await createPendingLogin(req, user, normalizeEmail(user.email));

    logActivity(username, 'LOGIN_OTP_SENT', 'Login OTP sent via email', req);
    res.json({
      message: 'Credentials verified. Check your Gmail/email for the OTP.',
      email: maskEmail(user.email),
      redirect: '/otp.html'
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: error.message || 'Server error' });
  }
});

/**
 * Route: GET /api/login-otp/status
 * Returns information about a pending OTP challenge.
 */
app.get('/api/login-otp/status', (req, res) => {
  const pendingLogin = req.session.pendingLogin;

  if (!pendingLogin || !pendingLogin.user) {
    return res.status(401).json({ message: 'No OTP verification is pending' });
  }

  if (!pendingLogin.expiresAt || Date.now() > pendingLogin.expiresAt) {
    delete req.session.pendingLogin;
    return res.status(401).json({ message: 'Your OTP expired. Please log in again.' });
  }

  res.json({
    username: pendingLogin.user.username,
    email: maskEmail(pendingLogin.email),
    expiresAt: pendingLogin.expiresAt
  });
});

/**
 * Route: POST /api/login-otp/verify
 * Completes login only after the Gmail/email OTP is verified.
 */
app.post('/api/login-otp/verify', async (req, res) => {
  try {
    const { otpCode } = req.body;
    const pendingLogin = req.session.pendingLogin;

    if (!pendingLogin || !pendingLogin.user) {
      return res.status(401).json({ message: 'No OTP verification is pending. Please log in again.' });
    }

    if (!otpCode) {
      return res.status(400).json({ message: 'OTP code is required' });
    }

    if (!pendingLogin.expiresAt || Date.now() > pendingLogin.expiresAt) {
      delete req.session.pendingLogin;
      return res.status(400).json({ message: 'OTP expired. Please log in again.' });
    }

    if (hashResetCode(otpCode) !== pendingLogin.otpHash) {
      await recordFailedAttempt(pendingLogin.user.username);
      await logActivity(pendingLogin.user.username, 'LOGIN_OTP_FAILURE', 'Invalid login OTP', req);

      if (await isAccountLocked(pendingLogin.user.username)) {
        delete req.session.pendingLogin;
        return res.status(429).json({
          message: 'Account locked due to multiple failed attempts. Try again in 30 seconds.'
        });
      }

      return res.status(401).json({ message: 'Invalid OTP code' });
    }

    createAuthenticatedSession(req, pendingLogin.user);
    delete req.session.pendingLogin;

    await resetFailedAttempts(req.session.user.username);
    await logActivity(req.session.user.username, 'LOGIN_SUCCESS', 'User completed OTP login successfully', req);

    res.json({
      message: 'OTP verified. Login successful.',
      user: req.session.user,
      redirect: req.session.user.role === 'admin' ? '/admin_dashboard.html' : '/user_dashboard.html'
    });
  } catch (error) {
    console.error('Login OTP verification error:', error);
    res.status(500).json({ message: 'Unable to verify OTP' });
  }
});

/**
 * Route: POST /api/login-otp/resend
 * Sends a fresh OTP for the current pending login.
 */
app.post('/api/login-otp/resend', async (req, res) => {
  try {
    const pendingLogin = req.session.pendingLogin;

    if (!pendingLogin || !pendingLogin.user || !pendingLogin.email) {
      return res.status(401).json({ message: 'No OTP verification is pending. Please log in again.' });
    }

    const otpCode = generateResetCode();
    pendingLogin.otpHash = hashResetCode(otpCode);
    pendingLogin.expiresAt = Date.now() + LOGIN_OTP_EXPIRY_MINUTES * 60 * 1000;
    req.session.pendingLogin = pendingLogin;

    await sendLoginOtpByEmail(pendingLogin.email, pendingLogin.user.username, otpCode);
    await logActivity(pendingLogin.user.username, 'LOGIN_OTP_RESENT', 'Login OTP resent via email', req);

    res.json({
      message: 'A new OTP was sent to your Gmail/email.',
      email: maskEmail(pendingLogin.email),
      expiresAt: pendingLogin.expiresAt
    });
  } catch (error) {
    console.error('Login OTP resend error:', error);
    res.status(500).json({ message: error.message || 'Unable to resend OTP' });
  }
});

/**
 * Route: POST /api/register
 * Feature 1 & 12: Register new user with bcrypt password hashing
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email, securityQuestion, securityAnswer } = req.body;

    if (!username || !password || !email || !securityQuestion || !securityAnswer) {
      return res.status(400).json({ message: 'All fields required' });
    }

    // Validate password strength (at least 8 chars, 1 uppercase, 1 number)
    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ 
        message: 'Password must be at least 8 chars with 1 uppercase letter and 1 number' 
      });
    }

    const normalizedUsername = normalizeUsername(username);
    const normalizedEmail = normalizeEmail(email);

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ message: 'Enter a valid email address' });
    }

    if (!ALLOWED_SECURITY_QUESTIONS.includes(securityQuestion)) {
      return res.status(400).json({ message: 'Choose one of the allowed security questions only' });
    }

    // Feature 1 & 12: Hash password before storing
    const passwordHash = await hashPassword(password);

    const { data: existingUsername } = await supabase.from('users').select('id').ilike('username', normalizedUsername).single();
    if (existingUsername) {
      return res.status(409).json({ message: 'Username already exists' });
    }

    const { data: existingEmail } = await supabase.from('users').select('id').eq('email', normalizedEmail).single();
    if (existingEmail) {
      return res.status(409).json({ message: 'Email is already in use' });
    }

    // Insert new user
    await supabase.from('users').insert([{ 
      username: normalizedUsername, 
      password_hash: passwordHash, 
      email: normalizedEmail,
      security_question: securityQuestion, 
      security_answer: securityAnswer 
    }]);

    logActivity(username, 'USER_REGISTRATION', 'New user registered', req);
    res.status(201).json({ message: 'User registered successfully' });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * Route: POST /api/dev/reset-demo-users
 * Development helper for restoring demo credentials after database changes.
 */
app.post('/api/dev/reset-demo-users', async (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ message: 'Endpoint not found' });
  }

  try {
    const { error } = await supabase
      .from('users')
      .upsert(DEMO_USERS, { onConflict: 'username' });

    if (error) {
      return res.status(500).json({ message: error.message });
    }

    res.json({
      message: 'Demo users reset',
      users: DEMO_USERS.map(({ username, role }) => ({ username, role }))
    });
  } catch (error) {
    console.error('Demo user reset error:', error);
    res.status(500).json({ message: 'Unable to reset demo users' });
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
      console.error('Logout error:', err);
      return res.status(500).json({ message: 'Logout failed' });
    }
  res.clearCookie(sessionConfig.name, {
    httpOnly: true,
    secure: sessionConfig.cookie.secure,
    sameSite: sessionConfig.cookie.sameSite
  });
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
    const { data: users, error } = await supabase
      .from('users')
      .select('id, username, role, attempts, failed_login_count, lockout_until, created_at');

    if (error) {
      console.error('Error fetching users from Supabase:', error);
      return res.status(500).json({ message: 'Failed to fetch users' });
    }

    logActivity(req.session.user.username, 'VIEW_ALL_USERS', 'Admin viewed user list', req);
    res.json(users || []);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

/**
 * Route: POST /api/forgot-password/request
 * Sends a one-time reset code to the user's email or mobile number
 */
app.post('/api/forgot-password/request', async (req, res) => {
  try {
    const { username, recoveryValue } = req.body;
    const normalizedUsername = normalizeUsername(username);

    if (!normalizedUsername || !recoveryValue) {
      return res.status(400).json({ message: 'Username and email are required' });
    }

    const method = 'email';
    const normalizedRecoveryValue = normalizeEmail(recoveryValue);

    if (!isValidEmail(normalizedRecoveryValue)) {
      return res.status(400).json({ message: 'Enter a valid email address' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('username, email')
      .ilike('username', normalizedUsername)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: 'No matching user found' });
    }

    const contactMatches = normalizeEmail(user.email || '') === normalizedRecoveryValue;

    if (!contactMatches) {
      return res.status(400).json({ message: 'The provided email does not match this account' });
    }

    const resetCode = generateResetCode();
    const resetCodeHash = hashResetCode(resetCode);
    const resetCodeExpiresAt = new Date(Date.now() + RESET_CODE_EXPIRY_MINUTES * 60 * 1000).toISOString();

    const { error: updateError } = await supabase
      .from('users')
      .update({
        reset_code_hash: resetCodeHash,
        reset_code_method: method,
        reset_code_expires_at: resetCodeExpiresAt
      })
      .ilike('username', normalizedUsername);

    if (updateError) {
      console.error('Error storing password reset code:', updateError);
      return res.status(500).json({ message: 'Unable to store reset code' });
    }

    await sendResetCodeByEmail(normalizedRecoveryValue, username, resetCode);

    await logActivity(username, 'PASSWORD_RESET_CODE_SENT', 'Reset code sent via email', req);
    res.json({ message: 'A reset code was sent to your email address' });
  } catch (error) {
    console.error('Forgot password request error:', error);
    res.status(500).json({ message: error.message || 'Unable to send reset code' });
  }
});

/**
 * Route: POST /api/forgot-password/reset
 * Verifies a reset code and updates the user's password
 */
app.post('/api/forgot-password/reset', async (req, res) => {
  try {
    const { username, verificationCode, newPassword } = req.body;
    const normalizedUsername = normalizeUsername(username);

    if (!normalizedUsername || !verificationCode || !newPassword) {
      return res.status(400).json({ message: 'All reset fields are required' });
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)[a-zA-Z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        message: 'Password must be at least 8 chars with 1 uppercase letter and 1 number'
      });
    }

    const method = 'email';
    const { data: user, error } = await supabase
      .from('users')
      .select('username, reset_code_hash, reset_code_method, reset_code_expires_at')
      .ilike('username', normalizedUsername)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.reset_code_hash || !user.reset_code_expires_at) {
      return res.status(400).json({ message: 'No reset code has been requested for this account' });
    }

    if (user.reset_code_method !== method) {
      return res.status(400).json({ message: 'Reset code method does not match the selected recovery method' });
    }

    if (new Date(user.reset_code_expires_at) < new Date()) {
      return res.status(400).json({ message: 'Reset code has expired. Request a new one.' });
    }

    if (hashResetCode(verificationCode) !== user.reset_code_hash) {
      return res.status(400).json({ message: 'Invalid verification code' });
    }

    const passwordHash = await hashPassword(newPassword);
    const { error: updateError } = await supabase
      .from('users')
      .update({
        password_hash: passwordHash,
        attempts: 0,
        lockout_until: null,
        reset_code_hash: null,
        reset_code_method: null,
        reset_code_expires_at: null
      })
      .ilike('username', normalizedUsername);

    if (updateError) {
      console.error('Error updating password after reset:', updateError);
      return res.status(500).json({ message: 'Unable to update password' });
    }

    await logActivity(username, 'PASSWORD_RESET_SUCCESS', `Password reset completed via ${method}`, req);
    res.json({ message: 'Password reset successful. You can now log in with your new password.' });
  } catch (error) {
    console.error('Forgot password reset error:', error);
    res.status(500).json({ message: 'Unable to reset password' });
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

    const { data: user, error } = await supabase
      .from('users')
      .select('id, username, role, created_at')
      .eq('username', username)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
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

    await supabase
      .from('users')
      .update({ attempts: 0, lockout_until: null })
      .eq('username', username);
      
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

    const { data: user, error } = await supabase
      .from('users')
      .select('password_hash')
      .eq('username', username)
      .single();

    if (error || !user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Feature 1 & 12: Verify current password
    const passwordMatch = await verifyPassword(currentPassword, user.password_hash);
    if (!passwordMatch) {
      logActivity(username, 'PASSWORD_CHANGE_FAILURE', 'Invalid current password', req);
      return res.status(401).json({ message: 'Current password incorrect' });
    }

    const newPasswordHash = await hashPassword(newPassword);
    await supabase.from('users').update({ password_hash: newPasswordHash }).eq('username', username);

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
    const { data: logs } = await supabase
      .from('logs')
      .select('id, username, action, details, ip_address, timestamp')
      .order('timestamp', { ascending: false })
      .limit(100);

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

    const { data: logs } = await supabase
      .from('logs')
      .select('id, username, action, details, ip_address, timestamp')
      .eq('username', username)
      .order('timestamp', { ascending: false })
      .limit(50);

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

if (require.main === module) {
  app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════╗
║   CIPHERGATE Security System Online    ║
║   Advanced Access Control Running      ║
╚════════════════════════════════════════╝
Server running on: http://localhost:${PORT}
Database: Connected to Supabase
  `);
  });
}

module.exports = app;
