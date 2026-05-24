CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin INTEGER DEFAULT 0,
  disabled INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  direction TEXT NOT NULL,
  sender TEXT,
  recipient TEXT,
  subject TEXT,
  body_text TEXT,
  body_html TEXT DEFAULT '',
  status TEXT DEFAULT 'unread',
  starred INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attachments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email_id INTEGER NOT NULL,
  filename TEXT,
  mime_type TEXT,
  size INTEGER,
  content BLOB
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_emails_user_status ON emails(user_id, status);
CREATE INDEX IF NOT EXISTS idx_emails_user_starred ON emails(user_id, starred);
CREATE INDEX IF NOT EXISTS idx_emails_updated_at ON emails(updated_at);
CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id);
