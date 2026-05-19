-- Demo seed data for local testing only.
-- Safe to run on an existing database because it updates only the demo users.

INSERT INTO users (username, password_hash, email, mobile_number, role, security_question, security_answer)
VALUES (
  'admin',
  '$2a$10$v73.4y9DaFQgtH1iBBnrlurQ8i8DtPRTaTX8uk5qnFpSJwzFkRYJa',
  'admin@example.com',
  '+15550000001',
  'admin',
  'What is your favorite color?',
  'blue'
) ON CONFLICT (username) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  email = EXCLUDED.email,
  mobile_number = EXCLUDED.mobile_number,
  role = EXCLUDED.role,
  security_question = EXCLUDED.security_question,
  security_answer = EXCLUDED.security_answer,
  attempts = 0,
  failed_login_count = 0,
  lockout_until = NULL;

INSERT INTO users (username, password_hash, email, mobile_number, role, security_question, security_answer)
VALUES (
  'testuser',
  '$2a$10$dvy11AoYqqret.hDfF1t0O/D8sWxhgOQUvTKAEGmzX9ocUo3i4exi',
  'testuser@example.com',
  '+15550000002',
  'user',
  'What are your favorite animals?',
  'fluffy'
) ON CONFLICT (username) DO UPDATE SET
  password_hash = EXCLUDED.password_hash,
  email = EXCLUDED.email,
  mobile_number = EXCLUDED.mobile_number,
  role = EXCLUDED.role,
  security_question = EXCLUDED.security_question,
  security_answer = EXCLUDED.security_answer,
  attempts = 0,
  failed_login_count = 0,
  lockout_until = NULL;
