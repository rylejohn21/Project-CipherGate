# 🔐 CipherGate - Advanced Code Breaker Security System

Enterprise-grade secure access control system with Role-Based Access Control (RBAC), bcryptjs encryption, and real-time activity monitoring.

## 📋 Project Overview

CipherGate is a complete authentication and authorization system featuring:
- **Secure password hashing** with bcryptjs (10 salt rounds)
- **Brute-force protection** with 3-attempt lockout and 30-second cooldown
- **Role-Based Access Control (RBAC)** for granular permissions
- **Secure session management** with HTTP-only cookies
- **Math CAPTCHA verification** to prevent bot attacks
- **Complete activity audit trail** with IP tracking
- **Modern dark/light theme** with dynamic switching

## 🏗️ Project Structure

```
CipherGate/
├── server.js                 # Main Express server with all backend logic
├── schema.sql               # MySQL database schema
├── package.json             # Node.js dependencies
├── .env.example             # Environment configuration template
├── README.md                # This file
└── public/                  # Frontend files
    ├── index.html           # Landing page
    ├── login.html           # Login/Registration page
    ├── user_dashboard.html  # User dashboard
    ├── admin_dashboard.html # Admin dashboard
    ├── style.css            # Main stylesheet with theme support
    └── js/
        ├── theme.js         # Feature 14: Day/Night mode toggle
        ├── auth.js          # Login/Registration logic
        ├── dashboard.js     # User dashboard logic
        └── admin-dashboard.js # Admin dashboard logic
```

## 🔒 Security Features

### Feature 1 & 12: Bcrypt Password Hashing
- **10 salt rounds** for password hashing
- **Timing-safe comparison** to prevent timing attacks
- **No plaintext passwords** stored in database
- **Secure password verification** on every login attempt

```javascript
// Example: Password hashing
const passwordHash = await bcrypt.hash(password, 10);
const isMatch = await bcrypt.compare(inputPassword, passwordHash);
```

### Feature 3: 3-Attempt Lockout with 30s Cooldown
- **Automated attempt tracking** per user
- **Automatic account lock** after 3 failed attempts
- **30-second lockdown** period
- **Admin unlock capability** for legitimate users
- **Automatic unlock** when cooldown expires

**Lockout Flow:**
1. First failed attempt: attempts = 1
2. Second failed attempt: attempts = 2
3. Third failed attempt: Account locked for 30 seconds
4. Further attempts: Rejected until lockout expires
5. Successful login: Attempts reset to 0

### Feature 4: Role-Based Access Control (RBAC)
- **Two roles**: Admin and User
- **Admin privileges**:
  - View all users and their details
  - Access complete activity logs
  - Unlock locked accounts
  - Monitor security events
- **User privileges**:
  - View own profile only
  - Change own password
  - Access own security settings
- **Unauthorized access logging** for security monitoring

### Feature 6: Secure Session Management
- **HTTP-only cookies** prevent XSS attacks
- **Secure flag** enabled in production (HTTPS)
- **24-hour session timeout** for inactivity
- **Session destruction** on logout
- **Server-side session storage** with express-session

### Feature 10: Simple Math CAPTCHA
- **Algorithm**: Generates random math problems (addition, subtraction, multiplication)
- **Validation**: Session-based verification
- **Regeneration**: New CAPTCHA on each failed attempt
- **Example**: "Solve: 7 + 3 = ?"

### Feature 14: Day/Night Mode Theme Toggle
- **Dark mode** (default): Cybersecurity-themed dark colors
- **Light mode**: Professional light theme
- **Persistent preference**: Saved to localStorage
- **Smooth transitions**: CSS-based theme switching
- **Full coverage**: Applied to all pages and components

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'user') DEFAULT 'user',
  security_question VARCHAR(255),
  security_answer VARCHAR(255),
  attempts INT DEFAULT 0,
  lockout_until DATETIME DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

### Logs Table
```sql
CREATE TABLE logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  action VARCHAR(100) NOT NULL,
  details VARCHAR(500),
  ip_address VARCHAR(45),
  user_agent VARCHAR(500),
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (username) REFERENCES users(username)
);
```

## 🚀 Installation & Setup

### Prerequisites
- Node.js (v14 or higher)
- MySQL Server
- npm or yarn

### Step 1: Install Dependencies
```bash
npm install
```

### Step 2: Setup Database
```bash
# Create MySQL database
mysql -u root -p

mysql> CREATE DATABASE ciphergate;
mysql> USE ciphergate;
mysql> source schema.sql;
```

### Step 3: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=ciphergate
SESSION_SECRET=your_super_secret_key_here
```

### Step 4: Start Server
```bash
# Production
npm start

# Development (with auto-reload)
npm run dev
```

Server runs on `http://localhost:3000`

## 📝 API Endpoints

### Authentication
- `POST /api/captcha` - Generate CAPTCHA challenge
- `POST /api/login` - User login with CAPTCHA
- `POST /api/register` - New user registration
- `GET /api/current-user` - Get current user info
- `POST /api/logout` - Logout and destroy session

### User Management
- `GET /api/users` - Get all users (Admin only)
- `GET /api/user/:username` - Get user profile
- `POST /api/user/:username/unlock` - Unlock account (Admin only)
- `POST /api/change-password` - Change password

### Activity Logs
- `GET /api/logs` - Get all logs (Admin only)
- `GET /api/logs/user/:username` - Get user logs (Admin only)

## 👥 Demo Credentials

### Admin Account
```
Username: admin
Password: Admin@123
Security Answer: blue
```

### Regular User Account
```
Username: testuser
Password: User@123
Security Answer: fluffy
```

## 🔐 Security Best Practices

### Password Requirements
- Minimum 8 characters
- At least 1 uppercase letter (A-Z)
- At least 1 number (0-9)
- Example: `Secure@Pass123`

### Login Security
1. CAPTCHA validation (Feature 10)
2. Lockout check (Feature 3)
3. Bcrypt password verification (Feature 1 & 12)
4. Security question verification (optional)
5. Session creation (Feature 6)
6. Activity logging (Feature 4)

### Admin Access
- Only admins can view all users and logs
- Admin actions are logged for accountability
- Unauthorized access attempts are tracked and logged

## 🎨 Frontend Features

### Theme System (Feature 14)
- **Dark Mode**: 
  - Primary: #0f1419
  - Accent: #00d4ff
  - Perfect for cybersecurity aesthetic
- **Light Mode**:
  - Primary: #ffffff
  - Accent: #0099cc
  - Professional appearance

### Responsive Design
- Mobile-friendly layouts
- Tablet optimization
- Desktop enhancements
- Touch-friendly button sizes

### User Interface
- **Landing Page**: Features overview and architecture
- **Login Page**: Form with CAPTCHA and security verification
- **User Dashboard**: Profile and security settings
- **Admin Dashboard**: Statistics, user management, and activity logs

## 🧪 Testing the System

### Test Login Flow
1. Navigate to `/login.html`
2. Use demo credentials (admin or testuser)
3. Solve the math CAPTCHA
4. Enter security answer
5. Dashboard loads based on role

### Test Lockout Mechanism (Feature 3)
1. Enter wrong password 3 times
2. Account locks for 30 seconds
3. Attempt to login again → "Account locked" message
4. Wait 30 seconds or admin can unlock

### Test RBAC (Feature 4)
1. Login as regular user → limited dashboard
2. Login as admin → full feature access
3. Try accessing `/api/logs` as regular user → Forbidden (403)
4. Try accessing `/api/logs` as admin → Success

### Test Theme Toggle (Feature 14)
1. Click theme toggle button (🌙 or ☀️)
2. Page switches between dark and light modes
3. Refresh page → theme persists
4. All pages respect the theme setting

## 📊 Activity Logging

All activities are logged with:
- **Timestamp**: Exact time of action
- **Username**: Who performed the action
- **Action**: Type of activity
- **Details**: Additional information
- **IP Address**: User's IP address
- **User Agent**: Browser/client information

### Logged Actions
- ✅ `LOGIN_SUCCESS` - Successful login
- ❌ `LOGIN_FAILURE` - Failed login attempt
- 🚫 `LOGIN_ATTEMPT_LOCKED` - Attempt while locked (Feature 3)
- ❌ `LOGIN_CAPTCHA_FAILURE` - CAPTCHA validation failed
- 🔐 `PASSWORD_CHANGED` - User changed password
- 🚪 `LOGOUT` - User logout
- 📋 `VIEW_LOGS` - Admin viewed logs
- 👥 `VIEW_ALL_USERS` - Admin viewed user list
- 🔓 `UNLOCK_ACCOUNT` - Admin unlocked account

## 🔧 Configuration

### Security Settings (.env)
```env
# Feature 3: Lockout duration in milliseconds
LOGIN_LOCKOUT_DURATION=30000

# Feature 10: CAPTCHA range
CAPTCHA_MIN_RANGE=1
CAPTCHA_MAX_RANGE=10

# Feature 6: Session timeout in milliseconds
SESSION_TIMEOUT=86400000
```

### Production Deployment
1. Set `NODE_ENV=production`
2. Enable HTTPS/SSL
3. Set `secure: true` in session cookie
4. Use strong `SESSION_SECRET`
5. Configure database backups
6. Enable CORS appropriately
7. Use environment variables for all secrets

## 📱 Browser Support
- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## 🐛 Troubleshooting

### Database Connection Error
```
Error: connect ECONNREFUSED 127.0.0.1:3306
```
**Solution**: Ensure MySQL is running and credentials in `.env` are correct

### CAPTCHA Not Loading
```
Error loading CAPTCHA
```
**Solution**: Check `/api/captcha` endpoint is accessible

### Session Not Persisting
**Solution**: Verify `SESSION_SECRET` is set in `.env`

### Theme Not Persisting
**Solution**: Check browser allows localStorage

## 📚 Documentation

### Code Comments
All code includes detailed comments explaining:
- Feature numbers they implement
- Security implications
- Implementation details
- Usage examples

### Feature References
Each security feature is marked with its number:
- Feature 1 & 12: Bcrypt hashing
- Feature 3: Lockout mechanism
- Feature 4: RBAC
- Feature 6: Session management
- Feature 10: CAPTCHA
- Feature 14: Theme toggle

## 📄 License

MIT License - Free for educational and commercial use

## 🤝 Contributing

Contributions welcome! Areas for enhancement:
- Two-factor authentication (2FA)
- Password recovery via email
- Account activity history
- IP whitelist/blacklist
- Rate limiting per IP
- Advanced security analytics

## 📞 Support

For issues or questions:
1. Check the troubleshooting section
2. Review code comments for implementation details
3. Check API endpoints documentation
4. Verify environment configuration

---

**CipherGate**: Enterprise-Grade Security. Encrypted by Default. Secured by Design.
