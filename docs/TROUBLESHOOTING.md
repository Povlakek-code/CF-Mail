# 故障排查

## 报字段不存在

执行：

```bash
npm run db:upgrade
```

## 登录失败

检查：

- 用户是否存在
- `disabled` 是否为 1
- `ALLOWED_EMAIL_DOMAIN` 是否正确
- 密码是否正确

## 发信失败

检查：

- 是否设置 `RESEND_API_KEY`
- Resend 域名是否验证
- 发件人是否属于 Resend 验证域名

## 收信失败

检查：

- Cloudflare Email Routing 是否开启
- 路由是否指向 Worker
- 收件人是否在 `users` 表
