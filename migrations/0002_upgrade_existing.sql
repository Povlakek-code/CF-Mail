-- 旧版数据库升级脚本。字段已存在时报 duplicate column name，可忽略并继续执行其他语句。
ALTER TABLE users ADD COLUMN disabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE emails ADD COLUMN body_html TEXT DEFAULT '';
ALTER TABLE emails ADD COLUMN starred INTEGER DEFAULT 0;
ALTER TABLE emails ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_emails_user_status ON emails(user_id, status);
CREATE INDEX IF NOT EXISTS idx_emails_user_starred ON emails(user_id, starred);
CREATE INDEX IF NOT EXISTS idx_emails_updated_at ON emails(updated_at);
CREATE INDEX IF NOT EXISTS idx_attachments_email_id ON attachments(email_id);
