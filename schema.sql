-- ============================================================================
-- CIPHERGATE: Advanced Code Breaker Security System
-- Supabase/Postgres Schema for Secure Access Control
-- ============================================================================

-- Enable extension for UUID generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Safe setup: do not drop existing tables, so real accounts are preserved

-- Create Users Table
-- Feature 1 & 12: Bcrypt password hashing with secure storage
-- Feature 3: Attempt tracking and lockout mechanism
-- Feature 4: Role-based access control (RBAC)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE,
  mobile_number VARCHAR(30) UNIQUE,
  role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
  security_question VARCHAR(255),
  security_answer VARCHAR(255),
  -- Feature 3: 3-attempt lockout tracking
  attempts INTEGER DEFAULT 0,
  -- Persistent admin-visible count of failed login-related events
  failed_login_count INTEGER DEFAULT 0,
  reset_code_hash VARCHAR(255),
  reset_code_method VARCHAR(20),
  reset_code_expires_at TIMESTAMPTZ DEFAULT NULL,
  -- Feature 3: Lockout cooldown until timestamp
  lockout_until TIMESTAMPTZ DEFAULT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_mobile_number ON users (mobile_number);

-- Create Activity Logs Table
-- Feature 4: Logging all user activities for admin audit trail
-- Feature 6: Session and action tracking
CREATE TABLE IF NOT EXISTS logs (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  action VARCHAR(100) NOT NULL,
  details VARCHAR(500),
  ip_address VARCHAR(45),
  user_agent VARCHAR(500),
  timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_logs_username FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_logs_username ON logs (username);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp);

-- Create Persistent Sessions Table
-- Keeps sessions alive across server restarts and supports concurrent device logins
CREATE TABLE IF NOT EXISTS sessions (
  sid VARCHAR(255) PRIMARY KEY,
  sess JSONB NOT NULL,
  expire TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions (expire);
