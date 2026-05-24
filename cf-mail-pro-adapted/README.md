# Cloudflare Mail Pro

基于 **Cloudflare Workers + Email Routing + D1 + KV + Resend** 的多用户邮箱 Web 系统。

本仓库已经适配 `src/index.js` 中的最新 Worker：绑定名、环境变量、D1 表结构、API 路由、前端功能和部署脚本保持一致。

## 功能

- 多用户邮箱登录
- PBKDF2-SHA256 + salt 密码哈希
- 旧明文密码首次登录自动迁移
- Cloudflare Email Routing 收信
- MIME 解析、HTML 清洗、附件入库
- Resend 发信
- 未读、已读、已发送、星标、草稿、废纸篓、全部邮件
- 搜索、无限滚动、移动端底部导航
- 草稿本地保存 + 云端自动保存
- 管理员创建、删除、重置密码、启用/停用用户
- 域名限制：`ALLOWED_EMAIL_DOMAIN`

## 快速部署

```bash
npm install
cp wrangler.toml.example wrangler.toml
npx wrangler d1 create mail-pro-db
npx wrangler kv namespace create EMAIL_AUTH_KV
npx wrangler secret put RESEND_API_KEY
npm run db:init
npm run deploy
```

创建第一个管理员：

```bash
npx wrangler d1 execute mail-pro-db --remote --command "INSERT INTO users (username, password_hash, is_admin, disabled) VALUES ('admin@example.com', 'your-temp-password', 1, 0);"
```

首次登录后，临时明文密码会自动升级为 PBKDF2 哈希。

## 必需绑定

`wrangler.toml` 需要：

- D1: `MY_EMAIL_DB`
- KV: `EMAIL_AUTH_KV`
- Secret: `RESEND_API_KEY`
- Vars: `ALLOWED_EMAIL_DOMAIN`, `SESSION_TTL_SECONDS`

## 文档

- [部署文档](docs/DEPLOYMENT.md)
- [数据库说明](docs/DATABASE.md)
- [环境变量](docs/ENVIRONMENT.md)
- [故障排查](docs/TROUBLESHOOTING.md)
- [GitHub Actions Secrets](docs/GITHUB_SECRETS.md)

## License

MIT
