# 部署文档

本部署文档适配当前 `src/index.js`。

## 1. 安装

```bash
npm install
```

## 2. 创建 Cloudflare 资源

```bash
npx wrangler d1 create mail-pro-db
npx wrangler kv namespace create EMAIL_AUTH_KV
```

将输出的 ID 填入 `wrangler.toml`。

## 3. 配置

```bash
cp wrangler.toml.example wrangler.toml
```

修改：

```toml
ALLOWED_EMAIL_DOMAIN = "你的域名.com"
database_id = "你的 D1 ID"
id = "你的 KV ID"
```

## 4. 设置 Resend Secret

```bash
npx wrangler secret put RESEND_API_KEY
```

## 5. 初始化 D1

新项目：

```bash
npm run db:init
```

旧项目升级：

```bash
npm run db:upgrade
```

## 6. 创建管理员

```bash
npx wrangler d1 execute mail-pro-db --remote --command "INSERT INTO users (username, password_hash, is_admin, disabled) VALUES ('admin@example.com', 'your-temp-password', 1, 0);"
```

## 7. 部署

```bash
npm run deploy
```

## 8. Email Routing

在 Cloudflare 域名控制台启用 Email Routing，并将邮件路由目标设置为该 Worker。
