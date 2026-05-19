# 🚀 CipherGate Deployment Guide

Complete guide for deploying CipherGate to production environments.

## 🏢 Local Development Setup

### 1. Install Dependencies
```bash
npm install
```

### 2. Start MySQL Server
```bash
# Windows
net start MySQL80

# macOS
brew services start mysql

# Linux
sudo systemctl start mysql
```

### 3. Create Database
```bash
mysql -u root -p -e "CREATE DATABASE ciphergate;"
mysql -u root -p ciphergate < schema.sql
```

### 4. Configure Environment
```bash
cp .env.example .env
```

Edit `.env`:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=ciphergate
SESSION_SECRET=your_super_secret_session_key_here
PORT=3000
NODE_ENV=development
```

### 5. Start Development Server
```bash
npm run dev
```

Access at: `http://localhost:3000`

## 🌐 Production Deployment

### 1. Environment Configuration

Create `.env` for production:
```env
# Database
DB_HOST=prod-database-host.com
DB_USER=ciphergate_user
DB_PASSWORD=strong_database_password_here
DB_NAME=ciphergate_prod
DB_PORT=3306

# Session
SESSION_SECRET=use_a_very_long_random_string_here_like_this_one_generated_with_crypto

# Server
PORT=3000
NODE_ENV=production

# Security
LOGIN_ATTEMPT_LIMIT=3
LOGIN_LOCKOUT_DURATION=30000
```

### 2. Generate Secure Session Secret
```bash
# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. Setup MySQL Server

**AWS RDS Example:**
```bash
# Create RDS instance
# - Engine: MySQL 8.0
# - Multi-AZ: Yes
# - Storage: 100GB (Auto-scaling enabled)
# - Backup: 30 days
```

**Create database user:**
```sql
CREATE USER 'ciphergate_user'@'%' IDENTIFIED BY 'strong_password_here';
GRANT ALL PRIVILEGES ON ciphergate_prod.* TO 'ciphergate_user'@'%';
FLUSH PRIVILEGES;
```

**Initialize schema:**
```bash
mysql -h rds-endpoint.amazonaws.com -u ciphergate_user -p ciphergate_prod < schema.sql
```

### 4. Using PM2 for Process Management

**Install PM2:**
```bash
npm install -g pm2
```

**Create ecosystem.config.js:**
```javascript
module.exports = {
  apps: [{
    name: 'ciphergate',
    script: './server.js',
    instances: 4,
    exec_mode: 'cluster',
    env: {
      NODE_ENV: 'production'
    },
    error_file: 'logs/pm2-error.log',
    out_file: 'logs/pm2-out.log',
    log_file: 'logs/combined.log',
    time_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true
  }]
};
```

**Start with PM2:**
```bash
pm2 start ecosystem.config.js
pm2 startup
pm2 save
```

### 5. Nginx Reverse Proxy

**Install Nginx:**
```bash
# Ubuntu/Debian
sudo apt-get install nginx

# CentOS/RHEL
sudo yum install nginx
```

**Configure Nginx (/etc/nginx/sites-available/ciphergate):**
```nginx
upstream ciphergate {
  server 127.0.0.1:3000;
  server 127.0.0.1:3001;
  server 127.0.0.1:3002;
  server 127.0.0.1:3003;
  keepalive 64;
}

server {
  listen 80;
  server_name yourdomain.com www.yourdomain.com;

  # Redirect HTTP to HTTPS
  return 301 https://$server_name$request_uri;
}

server {
  listen 443 ssl http2;
  server_name yourdomain.com www.yourdomain.com;

  # SSL Certificate (Let's Encrypt)
  ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

  # Security Headers
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-XSS-Protection "1; mode=block" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;

  client_max_body_size 10M;

  location / {
    proxy_pass http://ciphergate;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_cache_bypass $http_upgrade;
  }

  # Caching static assets
  location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
  }
}
```

**Enable site:**
```bash
sudo ln -s /etc/nginx/sites-available/ciphergate /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 6. SSL Certificate with Let's Encrypt

**Install Certbot:**
```bash
sudo apt-get install certbot python3-certbot-nginx
```

**Get certificate:**
```bash
sudo certbot certonly --nginx -d yourdomain.com -d www.yourdomain.com
```

**Auto-renewal:**
```bash
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

### 7. Database Backups

**Automated MySQL backups:**
```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="/var/backups/ciphergate"
DATE=$(date +%Y%m%d_%H%M%S)

mysqldump -u ciphergate_user -p$DB_PASSWORD ciphergate_prod > $BACKUP_DIR/ciphergate_$DATE.sql
gzip $BACKUP_DIR/ciphergate_$DATE.sql

# Keep only last 30 days
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
```

**Cron job (daily backup at 2 AM):**
```bash
0 2 * * * /usr/local/bin/backup.sh
```

### 8. Monitoring & Logging

**Install Node.js monitoring:**
```bash
npm install --save winston winston-daily-rotate-file
```

**Configure logging:**
```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.DailyRotateFile({
      filename: 'logs/application-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxDays: '14d'
    })
  ]
});
```

### 9. Security Checklist

- [x] Use HTTPS/SSL (Let's Encrypt)
- [x] Set `NODE_ENV=production`
- [x] Generate strong `SESSION_SECRET`
- [x] Configure CORS appropriately
- [x] Enable security headers in Nginx
- [x] Use environment variables for secrets
- [x] Enable database backups
- [x] Configure firewall rules
- [x] Setup monitoring & alerting
- [x] Enable HSTS
- [x] Disable X-Powered-By header
- [x] Implement rate limiting
- [x] Use strong database passwords
- [x] Enable SSL/TLS for database connections

### 10. Health Check Endpoint

```bash
curl https://yourdomain.com/api/status
```

Expected response:
```json
{
  "status": "CipherGate Security System is online",
  "timestamp": "2024-04-11T10:30:00Z"
}
```

## ☁️ Cloud Deployment

### AWS EC2

**1. Launch Instance**
- AMI: Ubuntu 22.04 LTS
- Instance Type: t3.medium (4GB RAM recommended)
- Security Group: Allow 80, 443, and restrict SSH

**2. Setup:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs

# Install MySQL client
sudo apt install -y mysql-client

# Clone repository
git clone your-repo-url /opt/ciphergate
cd /opt/ciphergate
npm install
```

**3. Deploy:**
```bash
pm2 start ecosystem.config.js
pm2 save
```

### DigitalOcean App Platform

**1. Connect Repository**
- Authorize GitHub access
- Select CipherGate repository

**2. Configure App Spec**
```yaml
name: ciphergate
services:
- name: web
  github:
    repo: your-github/ciphergate
    branch: main
  build_command: npm install
  run_command: npm start
  http_port: 3000
  environment_slug: node-js
  health_check:
    http_path: /api/status
```

### Docker Deployment

**Create Dockerfile:**
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
EXPOSE 3000

CMD ["npm", "start"]
```

**Build image:**
```bash
docker build -t ciphergate:latest .
```

**Run container:**
```bash
docker run -p 3000:3000 \
  -e DB_HOST=mysql-server \
  -e DB_USER=ciphergate_user \
  -e DB_PASSWORD=secure_password \
  -e SESSION_SECRET=your_secret \
  ciphergate:latest
```

## 📊 Performance Optimization

### Connection Pooling
```javascript
const pool = mysql.createPool({
  connectionLimit: 20,
  queueLimit: 10
});
```

### Caching Strategy
- Static assets: 1 year expiry
- API responses: Cache where appropriate
- Database queries: Connection pooling

### Compression
```javascript
const compression = require('compression');
app.use(compression());
```

## 🔍 Monitoring

**PM2 Monitoring:**
```bash
pm2 monit
```

**Key Metrics:**
- Memory usage
- CPU usage
- Event loop lag
- Error rates
- Request latency

## 🚨 Troubleshooting Production Issues

**High Memory Usage:**
```bash
pm2 logs ciphergate
```

**Database Connection Errors:**
```bash
mysql -h db-host -u user -p -e "SELECT VERSION();"
```

**Slow Requests:**
- Check database query performance
- Monitor Nginx logs
- Check server resources

## 📝 Maintenance

### Regular Tasks
- Update Node.js dependencies: `npm audit fix`
- Check SSL certificate expiry: `certbot certificates`
- Monitor disk space: `df -h`
- Review application logs: `pm2 logs`
- Test database backups

### Scaling
- Increase PM2 instances for multi-core
- Use load balancer for multiple servers
- Scale database separately (RDS read replicas)

---

**CipherGate**: Enterprise Security in Production.
