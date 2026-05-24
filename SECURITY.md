# Security Policy

- Passwords use PBKDF2-SHA256 with salt.
- Legacy plaintext passwords are migrated after successful login.
- Sessions are stored in KV with TTL.
- Attachment downloads are user-scoped.
- HTML email is sanitized before rendering.

Please report vulnerabilities privately rather than opening a public issue with exploit details.
