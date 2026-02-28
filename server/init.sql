-- Create users table
CREATE TABLE IF NOT EXISTS users (
id SERIAL PRIMARY KEY,
username VARCHAR(100) NOT NULL,
email VARCHAR(255) UNIQUE NOT NULL,
hash VARCHAR(255) NOT NULL,
salt VARCHAR(255) NOT NULL,
code varchar(255) NOT NULL,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on hash column for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_hash ON users(hash);

-- Insert some sample data
INSERT INTO users (username, email, hash, salt, code) VALUES
('john_doe', 'john@example.com', '3fb59244865105ace09b074d05b502b69443669ce435f22d9b090a4fda2a6ff2', '7a8f3c4d9e2b1a5f6c8d3e7a2b9f4c1d', 'ce09b074d0'),
('jane_smith', 'jane@example.com', ' 64e604787cbf194841e7b68d7cd28786f6c9a0a3ab9f8b0a0e87cb4387ab0107', 'b8e9d2a1f4c6b3d5e7f8a9c0d1e2f3a4', 'eju58gn84g8'),
('bob_wilson', 'bob@example.com', 'ebfcc97dd85a5ecfaf84ebc9926cd794017022144fe2439b568974520454b601', '5d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a', 'nc23vj67v3')
ON CONFLICT (email) DO NOTHING;