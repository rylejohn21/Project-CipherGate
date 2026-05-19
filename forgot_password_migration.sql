ALTER TABLE users
ADD COLUMN IF NOT EXISTS email VARCHAR(255) UNIQUE,
ADD COLUMN IF NOT EXISTS mobile_number VARCHAR(30) UNIQUE,
ADD COLUMN IF NOT EXISTS reset_code_hash VARCHAR(255),
ADD COLUMN IF NOT EXISTS reset_code_method VARCHAR(20),
ADD COLUMN IF NOT EXISTS reset_code_expires_at TIMESTAMPTZ DEFAULT NULL;

UPDATE users
SET email = 'admin@example.com',
    mobile_number = '+15550000001'
WHERE username = 'admin' AND (email IS NULL OR mobile_number IS NULL);

UPDATE users
SET email = 'testuser@example.com',
    mobile_number = '+15550000002'
WHERE username = 'testuser' AND (email IS NULL OR mobile_number IS NULL);
