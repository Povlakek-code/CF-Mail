# 环境变量和绑定

## D1

```toml
[[d1_databases]]
binding = "MY_EMAIL_DB"
database_name = "mail-pro-db"
database_id = "your-d1-database-id"
```

## KV

```toml
[[kv_namespaces]]
binding = "EMAIL_AUTH_KV"
id = "your-kv-namespace-id"
```

## Vars

```toml
[vars]
ALLOWED_EMAIL_DOMAIN = "example.com"
SESSION_TTL_SECONDS = "604800"
```

## Secret

```bash
npx wrangler secret put RESEND_API_KEY
```
