# 数据库说明

当前 Worker 使用三张表：

- `users`
- `emails`
- `attachments`

字段与 `migrations/0001_init.sql` 完全一致。

## users

- `username`：登录邮箱，必须唯一
- `password_hash`：PBKDF2 哈希，旧明文密码登录后自动迁移
- `is_admin`：管理员标记
- `disabled`：停用标记

## emails

- `status` 可为 `unread`、`read`、`sent`、`trash`、`draft`
- `body_text` 保存纯文本正文
- `body_html` 保存清洗后的 HTML 正文
- `starred` 控制星标

## attachments

附件以 BLOB 形式保存在 D1。轻量使用没问题，大附件建议后续迁移到 R2。
