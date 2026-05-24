/**
 * COMPLETE Cloudflare Worker: D1 + KV + Resend 多用户邮箱系统
 *
 * 功能：
 * - PBKDF2-SHA256 + salt 密码哈希
 * - 兼容旧明文密码，首次登录后自动迁移为哈希
 * - MIME 邮件解析
 * - text/plain 优先显示
 * - HTML 正文安全清洗
 * - 接收邮件附件解析并入库
 * - 管理员创建 / 删除 / 重置密码 / 启用停用用户
 * - 域名限制：ALLOWED_EMAIL_DOMAIN
 * - 移动端底部导航栏
 * - 邮件分页无限滚动
 * - 草稿箱 Drafts：本地 + 云端自动保存
 * - Resend 发信
 * - 附件鉴权下载
 *
 * Bindings:
 * - MY_EMAIL_DB      D1 Database
 * - EMAIL_AUTH_KV    KV Namespace
 * - RESEND_API_KEY   Secret
 *
 * Variables:
 * - ALLOWED_EMAIL_DOMAIN  例如 example.com，留空则不限制
 * - SESSION_TTL_SECONDS   可选，默认 604800
 */

const SESSION_TTL = 604800;
const PBKDF2_ITERATIONS = 120000;
const MAX_ATTACHMENT_SIZE = 1024 * 1024;
const MAX_TOTAL_ATTACHMENT_SIZE = 5 * 1024 * 1024;

export default {
  /**
   * Cloudflare Email Routing 收信事件
   */
  async email(message, env, ctx) {
    const recipient = String(message.to || "").trim().toLowerCase();

    const domain = validateAllowedDomain(recipient, env);
    if (!domain.ok) {
      message.setReject("Recipient domain is not allowed.");
      return;
    }

    const user = await env.MY_EMAIL_DB.prepare(
      "SELECT id, COALESCE(disabled, 0) AS disabled FROM users WHERE lower(username) = ?"
    ).bind(recipient).first();

    if (!user || Number(user.disabled) === 1) {
      message.setReject("User not found or disabled.");
      return;
    }

    const rawBytes = new Uint8Array(await new Response(message.raw).arrayBuffer());
    const raw = new TextDecoder("utf-8", { fatal: false }).decode(rawBytes);
    const parsed = parseMimeMessage(raw);

    const subject = decodeMimeHeader(parsed.headers.subject || "无主题");
    const sender = decodeMimeHeader(parsed.headers.from || message.from || "unknown");

    const bodyText = parsed.text || htmlToText(parsed.html || "") || raw;
    const bodyHtml = parsed.html ? sanitizeHtml(parsed.html) : "";

    const result = await env.MY_EMAIL_DB.prepare(
      `INSERT INTO emails 
       (user_id, direction, sender, recipient, subject, body_text, body_html, status, starred)
       VALUES (?, 'inbound', ?, ?, ?, ?, ?, 'unread', 0)`
    ).bind(
      user.id,
      sender,
      recipient,
      subject,
      bodyText,
      bodyHtml
    ).run();

    const emailId = result.meta.last_row_id;

    for (const attachment of parsed.attachments) {
      if (!attachment.content || attachment.content.byteLength === 0) continue;
      if (attachment.content.byteLength > MAX_ATTACHMENT_SIZE) continue;

      await env.MY_EMAIL_DB.prepare(
        `INSERT INTO attachments 
         (email_id, filename, mime_type, size, content)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(
        emailId,
        safeFilename(attachment.filename),
        attachment.mimeType || "application/octet-stream",
        attachment.content.byteLength,
        attachment.content
      ).run();
    }
  },

  /**
   * HTTP Web + API
   */
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === "/" || path === "/index.html") {
      return new Response(getHtml(), {
        headers: {
          "Content-Type": "text/html;charset=UTF-8",
          "Cache-Control": "no-store"
        }
      });
    }

    if (path === "/api/health") {
      return json({
        ok: true,
        time: new Date().toISOString()
      });
    }

    /**
     * 登录
     */
    if (path === "/api/auth/login" && method === "POST") {
      try {
        const { username, password } = await request.json();

        const email = String(username || "").trim().toLowerCase();

        if (!email || !password) {
          return json({ error: "请输入邮箱和密码" }, 400);
        }

        const domain = validateAllowedDomain(email, env);
        if (!domain.ok) {
          return json({ error: domain.error }, 400);
        }

        const user = await env.MY_EMAIL_DB.prepare(
          "SELECT * FROM users WHERE lower(username) = ?"
        ).bind(email).first();

        if (!user || Number(user.disabled || 0) === 1) {
          return json({ error: "用户名或密码错误，或账户已停用" }, 401);
        }

        const ok = await verifyPassword(password, user.password_hash || "");
        if (!ok) {
          return json({ error: "用户名或密码错误" }, 401);
        }

        /**
         * 兼容旧版明文密码：
         * 如果 password_hash 不是 pbkdf2_sha256$ 开头，登录成功后自动升级。
         */
        if (!String(user.password_hash || "").startsWith("pbkdf2_sha256$")) {
          await env.MY_EMAIL_DB.prepare(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
          ).bind(
            await hashPassword(password),
            user.id
          ).run();
        }

        const token = crypto.randomUUID();

        await env.EMAIL_AUTH_KV.put(
          token,
          JSON.stringify({
            id: user.id,
            username: user.username,
            is_admin: Number(user.is_admin) === 1
          }),
          {
            expirationTtl: Number(env.SESSION_TTL_SECONDS || SESSION_TTL)
          }
        );

        return json({
          token,
          user: {
            username: user.username,
            is_admin: Number(user.is_admin) === 1
          }
        });
      } catch (e) {
        return json({ error: "登录请求错误" }, 400);
      }
    }

    if (!path.startsWith("/api/")) {
      return new Response("Not Found", { status: 404 });
    }

    /**
     * API 鉴权
     */
    const auth = await getCurrentUser(request, env);
    if (!auth.ok) {
      return json({ error: auth.error }, auth.status || 401);
    }

    const currentUser = auth.user;

    /**
     * 登出
     */
    if (path === "/api/auth/logout" && method === "POST") {
      await env.EMAIL_AUTH_KV.delete(auth.token);
      return json({ success: true });
    }

    /**
     * 当前用户
     */
    if (path === "/api/me" && method === "GET") {
      return json({ user: currentUser });
    }

    /**
     * 邮件列表，支持分页和搜索
     */
    if (path === "/api/emails" && method === "GET") {
      const folder = url.searchParams.get("status") || "unread";
      const q = String(url.searchParams.get("q") || "").trim();
      const page = clampInt(url.searchParams.get("page"), 1, 999999, 1);
      const limit = clampInt(url.searchParams.get("limit"), 10, 100, 30);
      const offset = (page - 1) * limit;

      const allowed = [
        "unread",
        "read",
        "sent",
        "trash",
        "starred",
        "all",
        "draft"
      ];

      if (!allowed.includes(folder)) {
        return json({ error: "无效文件夹" }, 400);
      }

      let where = "WHERE user_id = ?";
      const params = [currentUser.id];

      if (folder === "starred") {
        where += " AND starred = 1 AND status != 'trash'";
      } else if (folder === "all") {
        where += " AND status != 'trash' AND status != 'draft'";
      } else {
        where += " AND status = ?";
        params.push(folder);
      }

      if (q) {
        where += " AND (sender LIKE ? OR recipient LIKE ? OR subject LIKE ? OR body_text LIKE ?)";
        const like = `%${q}%`;
        params.push(like, like, like, like);
      }

      const list = await env.MY_EMAIL_DB.prepare(
        `SELECT 
           id, direction, sender, recipient, subject, status, starred, created_at, updated_at
         FROM emails 
         ${where}
         ORDER BY COALESCE(updated_at, created_at) DESC
         LIMIT ? OFFSET ?`
      ).bind(
        ...params,
        limit,
        offset
      ).all();

      const total = await env.MY_EMAIL_DB.prepare(
        `SELECT COUNT(*) AS total FROM emails ${where}`
      ).bind(...params).first();

      const counts = await env.MY_EMAIL_DB.prepare(
        "SELECT status, COUNT(*) AS count FROM emails WHERE user_id = ? GROUP BY status"
      ).bind(currentUser.id).all();

      const starred = await env.MY_EMAIL_DB.prepare(
        "SELECT COUNT(*) AS count FROM emails WHERE user_id = ? AND starred = 1 AND status != 'trash'"
      ).bind(currentUser.id).first();

      return json({
        mails: list.results || [],
        counts: counts.results || [],
        starredCount: starred?.count || 0,
        page,
        limit,
        total: total?.total || 0,
        hasMore: offset + (list.results || []).length < Number(total?.total || 0)
      });
    }

    /**
     * 单封邮件详情
     */
    if (
      path.startsWith("/api/emails/") &&
      method === "GET" &&
      !path.endsWith("/attachments-all")
    ) {
      const id = path.split("/")[3];

      const email = await env.MY_EMAIL_DB.prepare(
        "SELECT * FROM emails WHERE id = ? AND user_id = ?"
      ).bind(id, currentUser.id).first();

      if (!email) {
        return json({ error: "Mail not found" }, 404);
      }

      if (email.status === "unread") {
        await env.MY_EMAIL_DB.prepare(
          "UPDATE emails SET status = 'read', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"
        ).bind(id, currentUser.id).run();

        email.status = "read";
      }

      const attachments = await env.MY_EMAIL_DB.prepare(
        "SELECT id, filename, mime_type, size FROM attachments WHERE email_id = ?"
      ).bind(id).all();

      email.attachments = attachments.results || [];

      return json(email);
    }

    /**
     * 所有附件，供前端 ZIP 打包
     */
    if (
      path.startsWith("/api/emails/") &&
      path.endsWith("/attachments-all") &&
      method === "GET"
    ) {
      const id = path.split("/")[3];

      const mail = await env.MY_EMAIL_DB.prepare(
        "SELECT id FROM emails WHERE id = ? AND user_id = ?"
      ).bind(id, currentUser.id).first();

      if (!mail) {
        return json({ error: "Mail not found" }, 404);
      }

      const rows = await env.MY_EMAIL_DB.prepare(
        "SELECT filename, content FROM attachments WHERE email_id = ?"
      ).bind(id).all();

      return json(
        (rows.results || []).map((r) => ({
          filename: r.filename,
          base64Data: bytesToBase64(r.content)
        }))
      );
    }

    /**
     * 草稿保存
     */
    if (path === "/api/drafts" && method === "POST") {
      const { id, to, subject, body } = await request.json();

      if (id) {
        await env.MY_EMAIL_DB.prepare(
          `UPDATE emails 
           SET recipient = ?, subject = ?, body_text = ?, status = 'draft', updated_at = CURRENT_TIMESTAMP
           WHERE id = ? AND user_id = ? AND status = 'draft'`
        ).bind(
          to || "",
          subject || "",
          body || "",
          id,
          currentUser.id
        ).run();

        return json({ success: true, id });
      }

      const r = await env.MY_EMAIL_DB.prepare(
        `INSERT INTO emails 
         (user_id, direction, sender, recipient, subject, body_text, status, starred)
         VALUES (?, 'outbound', ?, ?, ?, ?, 'draft', 0)`
      ).bind(
        currentUser.id,
        currentUser.username,
        to || "",
        subject || "",
        body || ""
      ).run();

      return json({
        success: true,
        id: r.meta.last_row_id
      });
    }

    /**
     * 用户设置
     */
    if (path === "/api/user/settings" && method === "POST") {
      const { new_username, new_password } = await request.json();

      if (new_password) {
        if (String(new_password).length < 8) {
          return json({ error: "新密码至少需要 8 位" }, 400);
        }

        await env.MY_EMAIL_DB.prepare(
          "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(
          await hashPassword(new_password),
          currentUser.id
        ).run();
      }

      if (new_username && new_username !== currentUser.username) {
        const email = String(new_username).trim().toLowerCase();

        const domain = validateAllowedDomain(email, env);
        if (!domain.ok) {
          return json({ error: domain.error }, 400);
        }

        try {
          await env.MY_EMAIL_DB.prepare(
            "UPDATE users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
          ).bind(
            email,
            currentUser.id
          ).run();
        } catch (e) {
          return json({ error: "该邮箱用户名已被占用" }, 400);
        }
      }

      return json({ success: true });
    }

    /**
     * 发送邮件
     */
    if (path === "/api/emails/send" && method === "POST") {
      if (!env.RESEND_API_KEY) {
        return json({ error: "未配置 RESEND_API_KEY" }, 500);
      }

      const form = await request.formData();

      const to = String(form.get("to") || "").trim().toLowerCase();
      const subject = String(form.get("subject") || "").trim();
      const body = String(form.get("body") || "").trim();
      const draftId = String(form.get("draft_id") || "").trim();
      const files = form.getAll("files");

      if (!isValidEmail(to) || !subject || !body) {
        return json({ error: "收件人、主题、正文不能为空，且收件人必须是邮箱格式" }, 400);
      }

      let totalSize = 0;

      for (const f of files) {
        if (f && f.size > 0) {
          totalSize += f.size;

          if (f.size > MAX_ATTACHMENT_SIZE) {
            return json({ error: `文件 ${f.name} 超过 1MB 限制` }, 400);
          }
        }
      }

      if (totalSize > MAX_TOTAL_ATTACHMENT_SIZE) {
        return json({ error: "附件总大小超过 5MB 限制" }, 400);
      }

      let emailId;

      if (draftId) {
        await env.MY_EMAIL_DB.prepare(
          `UPDATE emails 
           SET recipient = ?, subject = ?, body_text = ?, status = 'sent', updated_at = CURRENT_TIMESTAMP
           WHERE id = ? AND user_id = ? AND status = 'draft'`
        ).bind(
          to,
          subject,
          body,
          draftId,
          currentUser.id
        ).run();

        emailId = Number(draftId);
      } else {
        const r = await env.MY_EMAIL_DB.prepare(
          `INSERT INTO emails 
           (user_id, direction, sender, recipient, subject, body_text, status, starred)
           VALUES (?, 'outbound', ?, ?, ?, ?, 'sent', 0)`
        ).bind(
          currentUser.id,
          currentUser.username,
          to,
          subject,
          body
        ).run();

        emailId = r.meta.last_row_id;
      }

      const resendAttachments = [];

      for (const file of files) {
        if (file && file.size > 0) {
          const data = new Uint8Array(await file.arrayBuffer());
          const name = safeFilename(file.name);

          await env.MY_EMAIL_DB.prepare(
            "INSERT INTO attachments (email_id, filename, mime_type, size, content) VALUES (?, ?, ?, ?, ?)"
          ).bind(
            emailId,
            name,
            file.type || "application/octet-stream",
            file.size,
            data
          ).run();

          resendAttachments.push({
            filename: name,
            content: bytesToBase64(data)
          });
        }
      }

      const resp = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.RESEND_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: currentUser.username,
          to: [to],
          subject,
          text: body,
          attachments: resendAttachments.length ? resendAttachments : undefined
        })
      });

      const txt = await resp.text();

      if (!resp.ok) {
        return json({
          error: "Resend 投递失败，但本地已保存",
          detail: txt.slice(0, 500)
        }, 502);
      }

      return json({ success: true });
    }

    /**
     * 附件下载，带用户鉴权
     */
    if (path.startsWith("/api/attachments/") && method === "GET") {
      const id = path.split("/")[3];

      const att = await env.MY_EMAIL_DB.prepare(
        `SELECT a.* 
         FROM attachments a
         JOIN emails e ON a.email_id = e.id
         WHERE a.id = ? AND e.user_id = ?`
      ).bind(
        id,
        currentUser.id
      ).first();

      if (!att) {
        return new Response("Attachment Not Found", { status: 404 });
      }

      return new Response(att.content, {
        headers: {
          "Content-Type": att.mime_type || "application/octet-stream",
          "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(att.filename || "attachment")}`
        }
      });
    }

    /**
     * 管理员用户管理
     */
    if (path.startsWith("/api/admin/users")) {
      if (!currentUser.is_admin) {
        return json({ error: "Forbidden" }, 403);
      }

      const userId = path.split("/")[4];

      if (method === "GET" && !userId) {
        const rows = await env.MY_EMAIL_DB.prepare(
          "SELECT id, username, is_admin, COALESCE(disabled, 0) AS disabled FROM users ORDER BY id DESC"
        ).all();

        return json(rows.results || []);
      }

      if (method === "POST" && !userId) {
        const { username, password, is_admin } = await request.json();

        const email = String(username || "").trim().toLowerCase();

        const domain = validateAllowedDomain(email, env);
        if (!domain.ok) {
          return json({ error: domain.error }, 400);
        }

        if (!password || String(password).length < 8) {
          return json({ error: "密码至少需要 8 位" }, 400);
        }

        try {
          await env.MY_EMAIL_DB.prepare(
            "INSERT INTO users (username, password_hash, is_admin, disabled) VALUES (?, ?, ?, 0)"
          ).bind(
            email,
            await hashPassword(password),
            is_admin ? 1 : 0
          ).run();

          return json({ success: true });
        } catch (e) {
          return json({ error: "用户已存在或参数错误" }, 400);
        }
      }

      if (userId && method === "DELETE") {
        if (Number(userId) === Number(currentUser.id)) {
          return json({ error: "不能删除当前登录账户" }, 400);
        }

        await env.MY_EMAIL_DB.prepare(
          "DELETE FROM users WHERE id = ?"
        ).bind(userId).run();

        return json({ success: true });
      }

      if (userId && method === "PATCH") {
        const { action, password, disabled, is_admin } = await request.json();

        if (action === "reset-password") {
          if (!password || String(password).length < 8) {
            return json({ error: "密码至少需要 8 位" }, 400);
          }

          await env.MY_EMAIL_DB.prepare(
            "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
          ).bind(
            await hashPassword(password),
            userId
          ).run();
        } else if (action === "set-disabled") {
          if (Number(userId) === Number(currentUser.id)) {
            return json({ error: "不能停用当前登录账户" }, 400);
          }

          await env.MY_EMAIL_DB.prepare(
            "UPDATE users SET disabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
          ).bind(
            disabled ? 1 : 0,
            userId
          ).run();
        } else if (action === "set-admin") {
          await env.MY_EMAIL_DB.prepare(
            "UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
          ).bind(
            is_admin ? 1 : 0,
            userId
          ).run();
        } else {
          return json({ error: "未知管理员操作" }, 400);
        }

        return json({ success: true });
      }
    }

    /**
     * 邮件动作
     */
    if (path.startsWith("/api/emails/action/") && method === "POST") {
      const id = path.split("/")[4];
      const { action } = await request.json();

      if (action === "trash") {
        await env.MY_EMAIL_DB.prepare(
          "UPDATE emails SET status = 'trash', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"
        ).bind(id, currentUser.id).run();
      } else if (action === "delete") {
        await env.MY_EMAIL_DB.prepare(
          "DELETE FROM emails WHERE id = ? AND user_id = ?"
        ).bind(id, currentUser.id).run();
      } else if (action === "empty-trash") {
        await env.MY_EMAIL_DB.prepare(
          "DELETE FROM emails WHERE status = 'trash' AND user_id = ?"
        ).bind(currentUser.id).run();
      } else if (action === "restore") {
        await env.MY_EMAIL_DB.prepare(
          "UPDATE emails SET status = 'read', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND status = 'trash'"
        ).bind(id, currentUser.id).run();
      } else if (action === "mark-read") {
        await env.MY_EMAIL_DB.prepare(
          "UPDATE emails SET status = 'read', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND status != 'sent'"
        ).bind(id, currentUser.id).run();
      } else if (action === "mark-unread") {
        await env.MY_EMAIL_DB.prepare(
          "UPDATE emails SET status = 'unread', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND status != 'sent'"
        ).bind(id, currentUser.id).run();
      } else if (action === "toggle-star") {
        await env.MY_EMAIL_DB.prepare(
          "UPDATE emails SET starred = CASE WHEN starred = 1 THEN 0 ELSE 1 END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"
        ).bind(id, currentUser.id).run();
      } else {
        return json({ error: "Unknown action" }, 400);
      }

      return json({ success: true });
    }

    return json({ error: "Not Found" }, 404);
  }
};

/**
 * 鉴权
 */
async function getCurrentUser(request, env) {
  const h = request.headers.get("Authorization");

  if (!h || !h.startsWith("Bearer ")) {
    return {
      ok: false,
      status: 401,
      error: "Unauthorized"
    };
  }

  const token = h.slice(7);
  const sessionStr = await env.EMAIL_AUTH_KV.get(token);

  if (!sessionStr) {
    return {
      ok: false,
      status: 401,
      error: "Session expired"
    };
  }

  try {
    const session = JSON.parse(sessionStr);

    const user = await env.MY_EMAIL_DB.prepare(
      "SELECT COALESCE(disabled, 0) AS disabled FROM users WHERE id = ?"
    ).bind(session.id).first();

    if (!user || Number(user.disabled) === 1) {
      return {
        ok: false,
        status: 401,
        error: "Account disabled"
      };
    }

    return {
      ok: true,
      token,
      user: {
        id: session.id,
        username: session.username,
        is_admin: session.is_admin === true || session.is_admin === 1
      }
    };
  } catch (e) {
    return {
      ok: false,
      status: 401,
      error: "Session invalid"
    };
  }
}

/**
 * JSON response
 */
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json;charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

/**
 * 工具
 */
function clampInt(v, min, max, fallback) {
  const n = Number(v);
  return Number.isInteger(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

function isValidEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || ""));
}

function validateAllowedDomain(email, env) {
  if (!isValidEmail(email)) {
    return {
      ok: false,
      error: "请输入完整邮箱格式"
    };
  }

  const allowed = String(env.ALLOWED_EMAIL_DOMAIN || "")
    .trim()
    .toLowerCase()
    .replace(/^@/, "");

  if (!allowed) {
    return { ok: true };
  }

  const domain = String(email).split("@").pop().toLowerCase();

  return domain === allowed
    ? { ok: true }
    : {
        ok: false,
        error: `只允许 @${allowed} 域名邮箱`
      };
}

function safeFilename(n) {
  return String(n || "attachment")
    .replace(/[\/\\:*?"<>|]/g, "_")
    .slice(0, 180);
}

function bytesToBase64(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let bin = "";

  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }

  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(String(b64 || "").replace(/\s/g, ""));
  const out = new Uint8Array(bin.length);

  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }

  return out;
}

/**
 * PBKDF2-SHA256 password hash
 */
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  stored = String(stored || "");

  /**
   * 兼容旧版明文密码
   */
  if (!stored.startsWith("pbkdf2_sha256$")) {
    return stored === password;
  }

  const [, iterStr, saltB64, hashB64] = stored.split("$");

  const salt = base64ToBytes(saltB64);
  const expected = base64ToBytes(hashB64);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: Number(iterStr),
      hash: "SHA-256"
    },
    key,
    expected.length * 8
  );

  const actual = new Uint8Array(bits);

  if (actual.length !== expected.length) {
    return false;
  }

  let diff = 0;

  for (let i = 0; i < actual.length; i++) {
    diff |= actual[i] ^ expected[i];
  }

  return diff === 0;
}

/**
 * MIME parsing
 */
function parseHeaders(block) {
  const headers = {};
  const unfolded = String(block || "").replace(/\r?\n[\t ]+/g, " ");

  for (const line of unfolded.split(/\r?\n/)) {
    const i = line.indexOf(":");

    if (i > 0) {
      headers[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim();
    }
  }

  return headers;
}

function splitHeaderBody(raw) {
  const m = String(raw || "").match(/\r?\n\r?\n/);

  if (!m) {
    return [raw, ""];
  }

  return [
    raw.slice(0, m.index),
    raw.slice(m.index + m[0].length)
  ];
}

function headerParam(v, name) {
  const re = new RegExp(`${name}\\*?=(?:"([^"]+)"|([^;]+))`, "i");
  const m = String(v || "").match(re);

  return m ? decodeMimeHeader((m[1] || m[2] || "").trim()) : "";
}

function decodeMimeHeader(value) {
  return String(value || "").replace(
    /=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g,
    (_, charset, enc, data) => {
      try {
        let bytes;

        if (enc.toUpperCase() === "B") {
          bytes = base64ToBytes(data);
        } else {
          const s = data
            .replace(/_/g, " ")
            .replace(/=([A-Fa-f0-9]{2})/g, (_, h) =>
              String.fromCharCode(parseInt(h, 16))
            );

          bytes = Uint8Array.from(s, (c) => c.charCodeAt(0));
        }

        return new TextDecoder(charset.toLowerCase(), { fatal: false }).decode(bytes);
      } catch (e) {
        return data;
      }
    }
  );
}

function decodeQP(str) {
  const s = String(str || "").replace(/=\r?\n/g, "");
  const bytes = [];

  for (let i = 0; i < s.length; i++) {
    if (
      s[i] === "=" &&
      /[0-9a-fA-F]{2}/.test(s.slice(i + 1, i + 3))
    ) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      bytes.push(s.charCodeAt(i));
    }
  }

  return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
}

function decodePart(body, enc, isText) {
  enc = String(enc || "").toLowerCase();

  try {
    if (enc === "base64") {
      const b = base64ToBytes(body);
      return isText
        ? new TextDecoder("utf-8", { fatal: false }).decode(b)
        : b;
    }

    if (enc === "quoted-printable") {
      const t = decodeQP(body);
      return isText ? t : new TextEncoder().encode(t);
    }
  } catch (e) {}

  return isText
    ? String(body || "")
    : new TextEncoder().encode(String(body || ""));
}

function parseMimeMessage(raw) {
  const [h, b] = splitHeaderBody(raw);
  const headers = parseHeaders(h);

  const out = {
    headers,
    text: "",
    html: "",
    attachments: []
  };

  walkMime(headers, b, out);

  return out;
}

function walkMime(headers, body, out) {
  const ct = headers["content-type"] || "text/plain";
  const disp = headers["content-disposition"] || "";
  const enc = headers["content-transfer-encoding"] || "";
  const mime = ct.split(";")[0].trim().toLowerCase();
  const boundary = headerParam(ct, "boundary");

  if (boundary && mime.startsWith("multipart/")) {
    const marker = "--" + boundary;

    const parts = String(body)
      .split(marker)
      .slice(1)
      .filter((p) => !p.startsWith("--"));

    for (let p of parts) {
      p = p.replace(/^\r?\n/, "").replace(/\r?\n$/, "");

      const [ph, pb] = splitHeaderBody(p);

      walkMime(parseHeaders(ph), pb, out);
    }

    return;
  }

  const filename = headerParam(disp, "filename") || headerParam(ct, "name");
  const isAttachment = /attachment/i.test(disp) || !!filename;

  if (isAttachment) {
    out.attachments.push({
      filename: filename || "attachment",
      mimeType: mime,
      content: decodePart(body, enc, false)
    });

    return;
  }

  if (mime === "text/plain") {
    out.text ||= decodePart(body, enc, true).trim();
  } else if (mime === "text/html") {
    out.html ||= sanitizeHtml(decodePart(body, enc, true));
  }
}

function sanitizeHtml(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<iframe[\s\S]*?<\/iframe>/gi, "")
    .replace(/<object[\s\S]*?<\/object>/gi, "")
    .replace(/<embed[\s\S]*?>/gi, "")
    .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/\s(href|src)\s*=\s*("|')\s*javascript:[\s\S]*?\2/gi, "");
}

function htmlToText(html) {
  return sanitizeHtml(html)
    .replace(/<br\s*\/?\s*>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .trim();
}

/**
 * 前端 HTML
 */
function getHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>Mail Pro</title>
https://cdn.tailwindcss.comscript>
https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@latest/tabler-icons.min.css
https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.jsscript>
<style>
:root {
  --bg: #f5f7fb;
  --panel: rgba(255,255,255,.78);
  --solid: #fff;
  --text: #101828;
  --muted: #667085;
  --border: rgba(16,24,40,.12);
  --active: rgba(37,99,235,.12);
  --accent: #2563eb;
  --danger: #ef4444;
}
.dark {
  --bg: #09090b;
  --panel: rgba(24,24,27,.78);
  --solid: #18181b;
  --text: #f4f4f5;
  --muted: #a1a1aa;
  --border: rgba(255,255,255,.1);
  --active: rgba(96,165,250,.16);
  --accent: #60a5fa;
  --danger: #fb7185;
}
body {
  margin: 0;
  height: 100vh;
  overflow: hidden;
  color: var(--text);
  background:
    radial-gradient(circle at 10% 0%, rgba(59,130,246,.22), transparent 30%),
    radial-gradient(circle at 90% 10%, rgba(168,85,247,.18), transparent 28%),
    var(--bg);
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
}
.glass {
  background: var(--panel);
  backdrop-filter: blur(28px) saturate(160%);
  border-color: var(--border);
}
.solid {
  background: var(--solid);
  border-color: var(--border);
}
.nav {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: .58rem .75rem;
  border-radius: 1rem;
  color: var(--muted);
  cursor: pointer;
}
.nav:hover,
.nav.active {
  background: var(--active);
  color: var(--accent);
  font-weight: 800;
}
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: .35rem;
  border-radius: 1rem;
  padding: .58rem .85rem;
  font-size: .78rem;
  font-weight: 800;
  cursor: pointer;
}
.primary {
  background: linear-gradient(135deg,#2563eb,#7c3aed);
  color: white;
}
.soft {
  background: var(--active);
  color: var(--accent);
}
.danger {
  background: rgba(239,68,68,.12);
  color: var(--danger);
}
.field {
  width: 100%;
  background: rgba(255,255,255,.55);
  border: 1px solid var(--border);
  border-radius: 1rem;
  outline: none;
  color: var(--text);
}
.dark .field {
  background: rgba(255,255,255,.06);
}
.mail {
  border-bottom: 1px solid var(--border);
}
.mail:hover,
.mail.selected {
  background: var(--active);
}
.badge {
  border-radius: 999px;
  background: #ef4444;
  color: white;
  font-size: .68rem;
  font-weight: 900;
  padding: 0 .42rem;
}
.no-scroll::-webkit-scrollbar {
  display: none;
}
.no-scroll {
  scrollbar-width: none;
}
@media(max-width:767px) {
  .desktop {
    display: none !important;
  }
  .workspace {
    position: fixed;
    inset: 0;
    z-index: 30;
  }
  .bottomnav {
    display: grid !important;
  }
  .list {
    padding-bottom: 72px;
  }
}
</style>
</head>

<body class="text-sm select-none">

<div id="toastBox" class="fixed top-5 left-1/2 -translate-x-1/2 z-50 space-y-2 pointer-events-none"></div>

<div id="loginView" class="h-screen flex items-center justify-center p-4">
  <div class="glass border rounded-3xl p-7 max-w-md w-full shadow-2xl">
    <div class="flex items-center gap-4 mb-7">
      <div class="w-14 h-14 rounded-2xl primary flex items-center justify-center text-white">
        <i class="ti ti-cloud text-3xl"></i>
      </div>
      <div>
        <h1 class="text-2xl font-black">Mail Pro</h1>
        <p class="text-xs" style="color:var(--muted)">Cloudflare Edge Mail</p>
      </div>
    </div>

    <input id="loginUser" class="field px-4 py-3 mb-3" placeholder="邮箱账号">
    <input id="loginPass" type="password" class="field px-4 py-3 mb-3" placeholder="密码">

    <button onclick="login()" class="btn primary w-full py-3">登录</button>
  </div>
</div>

<div id="app" class="hidden h-screen">
  <div class="h-full flex">

    <aside class="desktop w-72 glass border-r p-4 flex flex-col justify-between">
      <div>
        <div class="solid border rounded-3xl p-4 mb-4">
          <div class="font-black truncate" id="userLabel"></div>
          <div class="text-xs" style="color:var(--muted)">安全会话已连接</div>
        </div>

        <button onclick="compose()" class="btn primary w-full mb-5">
          <i class="ti ti-edit"></i>撰写新邮件
        </button>

        <nav class="space-y-1">
          <a id="nav-unread" onclick="loadFolder('unread')" class="nav active">
            <span><i class="ti ti-mail-opened"></i> 未读</span>
            <span id="count-unread" class="badge hidden">0</span>
          </a>
          <a id="nav-read" onclick="loadFolder('read')" class="nav">
            <span><i class="ti ti-inbox"></i> 已读</span>
            <span id="count-read">0</span>
          </a>
          <a id="nav-starred" onclick="loadFolder('starred')" class="nav">
            <span><i class="ti ti-star"></i> 星标</span>
            <span id="count-starred">0</span>
          </a>
          <a id="nav-sent" onclick="loadFolder('sent')" class="nav">
            <span><i class="ti ti-send"></i> 已发送</span>
            <span id="count-sent">0</span>
          </a>
          <a id="nav-draft" onclick="loadFolder('draft')" class="nav">
            <span><i class="ti ti-file-pencil"></i> 草稿</span>
            <span id="count-draft">0</span>
          </a>
          <a id="nav-trash" onclick="loadFolder('trash')" class="nav">
            <span><i class="ti ti-trash"></i> 废纸篓</span>
            <span id="count-trash">0</span>
          </a>
          <a id="nav-all" onclick="loadFolder('all')" class="nav">
            <span><i class="ti ti-folders"></i> 全部</span>
          </a>
          <a id="adminNav" onclick="showAdmin()" class="nav hidden">
            <span><i class="ti ti-shield-lock"></i> 用户管理</span>
          </a>
        </nav>
      </div>

      <div class="space-y-2">
        <select id="themeSelect" onchange="setTheme(this.value)" class="field px-3 py-2 text-xs">
          <option value="auto">跟随系统</option>
          <option value="light">浅色</option>
          <option value="dark">深色</option>
        </select>

        <a onclick="showSettings()" class="nav">
          <span><i class="ti ti-settings"></i> 设置</span>
        </a>

        <a onclick="logout()" class="nav" style="color:var(--danger)">
          <span><i class="ti ti-logout"></i> 退出</span>
        </a>
      </div>
    </aside>

    <main class="list w-full md:w-96 glass border-r flex flex-col">
      <div class="p-4 border-b" style="border-color:var(--border)">
        <div class="flex justify-between items-center mb-3">
          <div>
            <h2 id="listTitle" class="text-2xl font-black">未读</h2>
            <p id="listSub" class="text-xs" style="color:var(--muted)">同步中</p>
          </div>
          <div>
            <button onclick="compose()" class="btn soft md:hidden">
              <i class="ti ti-edit"></i>
            </button>
            <button onclick="reloadFolder()" class="btn soft">
              <i class="ti ti-refresh"></i>
            </button>
          </div>
        </div>

        <input id="searchBox" oninput="debouncedSearch()" class="field px-4 py-2.5" placeholder="搜索邮件...">

        <div id="trashBar" class="hidden mt-3">
          <button onclick="emptyTrash()" class="btn danger w-full">清空废纸篓</button>
        </div>
      </div>

      <div id="mailList" class="flex-1 overflow-y-auto no-scroll"></div>
      <div id="sentinel" class="h-10 text-center text-xs py-3" style="color:var(--muted)"></div>
    </main>

    <section id="workspace" class="workspace flex-1 hidden md:block">

      <div id="emptyPane" class="h-full flex items-center justify-center" style="color:var(--muted)">
        <div class="text-center">
          <i class="ti ti-mail text-6xl"></i>
          <div class="font-black mt-3">选择邮件查看</div>
        </div>
      </div>

      <div id="detailPane" class="hidden h-full flex flex-col">
        <div class="glass border-b p-3 flex gap-2 justify-end">
          <button id="starBtn" class="btn soft">星标</button>
          <button id="replyBtn" class="btn soft">回复</button>
          <button id="restoreBtn" class="btn soft hidden">恢复</button>
          <button id="trashBtn" class="btn danger">废纸篓</button>
          <button id="deleteBtn" class="btn danger">删除</button>
        </div>

        <div class="overflow-y-auto p-5 md:p-8 flex-1">
          <div class="glass border rounded-3xl p-6 max-w-4xl mx-auto">
            <h1 id="detailSubject" class="text-3xl font-black select-text"></h1>

            <div class="grid md:grid-cols-2 gap-3 my-5 text-xs">
              <div class="solid border rounded-2xl p-3">
                <div style="color:var(--muted)">发件人</div>
                <b id="detailFrom" class="select-all break-all"></b>
              </div>
              <div class="solid border rounded-2xl p-3">
                <div style="color:var(--muted)">时间</div>
                <b id="detailTime"></b>
              </div>
            </div>

            <div id="htmlBox" class="hidden solid border rounded-2xl p-4 mb-4 overflow-x-auto"></div>

            <pre id="detailBody" class="whitespace-pre-wrap font-sans text-base select-text"></pre>

            <div class="border-t mt-6 pt-5" style="border-color:var(--border)">
              <div class="flex justify-between mb-3">
                <b class="text-xs" style="color:var(--muted)">附件</b>
                <button id="zipBtn" onclick="downloadZip()" class="btn soft hidden">打包下载</button>
              </div>
              <div id="attachmentBox" class="grid md:grid-cols-2 gap-3"></div>
            </div>
          </div>
        </div>
      </div>

      <div id="composePane" class="hidden h-full flex flex-col">
        <div class="glass border-b p-3 flex justify-between">
          <b>撰写邮件</b>
          <div>
            <button onclick="discardCompose()" class="btn soft">丢弃</button>
            <button onclick="sendMail(event)" class="btn primary">发送</button>
          </div>
        </div>

        <form id="composeForm" class="overflow-y-auto p-5 md:p-8 flex-1">
          <input type="hidden" name="draft_id" id="draftId">

          <div class="glass border rounded-3xl p-6 max-w-4xl mx-auto space-y-4">
            <input name="to" class="field px-4 py-3" placeholder="收件人" oninput="draftChanged()">
            <input name="subject" class="field px-4 py-3 font-bold" placeholder="主题" oninput="draftChanged()">
            <textarea name="body" class="field px-4 py-3 h-80" placeholder="正文" oninput="draftChanged()"></textarea>

            <label class="btn soft cursor-pointer">
              <i class="ti ti-paperclip"></i>添加附件
              <input name="files" type="file" multiple class="hidden">
            </label>

            <span id="draftState" class="text-xs" style="color:var(--muted)"></span>
          </div>
        </form>
      </div>

      <div id="settingsPane" class="hidden p-8">
        <div class="glass border rounded-3xl p-6 max-w-xl">
          <h2 class="text-2xl font-black mb-4">设置</h2>
          <input id="settingsUser" class="field px-4 py-3 mb-3">
          <input id="settingsPass" type="password" class="field px-4 py-3 mb-3" placeholder="新密码，至少 8 位">
          <button onclick="saveSettings()" class="btn primary">保存</button>
        </div>
      </div>

      <div id="adminPane" class="hidden p-8 overflow-y-auto h-full">
        <div class="glass border rounded-3xl p-6 max-w-5xl">
          <h2 class="text-2xl font-black mb-4">用户管理</h2>

          <div class="grid md:grid-cols-5 gap-3 mb-5">
            <input id="newUser" class="field px-4 py-3 md:col-span-2" placeholder="alias@domain.com">
            <input id="newPass" class="field px-4 py-3" placeholder="密码至少8位">
            <label class="text-xs flex items-center gap-2">
              <input id="newAdmin" type="checkbox">管理员
            </label>
            <button onclick="createUser()" class="btn primary">创建</button>
          </div>

          <div id="usersBox" class="space-y-2"></div>
        </div>
      </div>

    </section>
  </div>

  <div class="bottomnav hidden fixed bottom-0 left-0 right-0 grid-cols-5 glass border-t z-40">
    <button onclick="loadFolder('unread')" class="p-3">
      <i class="ti ti-mail text-xl"></i>
      <div class="text-xs">未读</div>
    </button>
    <button onclick="loadFolder('starred')" class="p-3">
      <i class="ti ti-star text-xl"></i>
      <div class="text-xs">星标</div>
    </button>
    <button onclick="compose()" class="p-3">
      <i class="ti ti-edit text-xl"></i>
      <div class="text-xs">撰写</div>
    </button>
    <button onclick="loadFolder('draft')" class="p-3">
      <i class="ti ti-file-pencil text-xl"></i>
      <div class="text-xs">草稿</div>
    </button>
    <button onclick="loadFolder('trash')" class="p-3">
      <i class="ti ti-trash text-xl"></i>
      <div class="text-xs">废纸篓</div>
    </button>
  </div>
</div>

<script>
let token = localStorage.cf_mail_token || "";
let user = JSON.parse(localStorage.cf_mail_user || "{}");
let folder = "unread";
let page = 1;
let hasMore = true;
let loading = false;
let mails = [];
let selectedId = null;
let draftTimer = null;
let observer = null;

initTheme();

if (token) {
  showApp();
}

function initTheme() {
  const t = localStorage.mail_theme || "auto";
  document.getElementById("themeSelect").value = t;
  setTheme(t, false);
}

function setTheme(v, save = true) {
  if (save) {
    localStorage.mail_theme = v;
  }

  document.documentElement.classList.toggle(
    "dark",
    v === "dark" ||
      (v === "auto" && matchMedia("(prefers-color-scheme: dark)").matches)
  );
}

function showToast(message, type = "info") {
  const box = document.getElementById("toastBox");
  const d = document.createElement("div");

  d.className = "solid border rounded-full px-4 py-3 shadow-xl text-xs font-bold";

  d.innerHTML =
    (type === "error" ? "❌ " : type === "success" ? "✅ " : "ℹ️ ") +
    esc(message);

  box.appendChild(d);

  setTimeout(() => {
    d.style.opacity = 0;
    setTimeout(() => d.remove(), 250);
  }, 3000);
}

function api(p, o = {}) {
  o.headers = o.headers || {};
  o.headers.Authorization = "Bearer " + token;

  return fetch(p, o).then(async (r) => {
    const d = (r.headers.get("content-type") || "").includes("json")
      ? await r.json()
      : await r.text();

    if (!r.ok) {
      if (r.status === 401) {
        localStorage.removeItem("cf_mail_token");
        setTimeout(() => location.reload(), 800);
      }

      throw new Error(d.error || "请求失败");
    }

    return d;
  });
}

function login() {
  fetch("/api/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      username: document.getElementById("loginUser").value,
      password: document.getElementById("loginPass").value
    })
  })
    .then((r) =>
      r.json().then((d) => {
        if (!r.ok) throw new Error(d.error);
        return d;
      })
    )
    .then((d) => {
      token = d.token;
      user = d.user;

      localStorage.cf_mail_token = token;
      localStorage.cf_mail_user = JSON.stringify(user);

      showApp();
      showToast("登录成功", "success");
    })
    .catch((e) => showToast(e.message, "error"));
}

function logout() {
  api("/api/auth/logout", {
    method: "POST"
  }).catch(() => {});

  localStorage.clear();
  location.reload();
}

function showApp() {
  document.getElementById("loginView").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");

  document.getElementById("userLabel").textContent = user.username || "";
  document.getElementById("settingsUser").value = user.username || "";

  if (user.is_admin) {
    document.getElementById("adminNav").classList.remove("hidden");
  }

  loadFolder("unread");
  setupObserver();
}

function setupObserver() {
  if (observer) {
    observer.disconnect();
  }

  observer = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting && hasMore && !loading) {
      loadMore();
    }
  });

  observer.observe(document.getElementById("sentinel"));
}

function reloadFolder() {
  page = 1;
  hasMore = true;
  mails = [];
  document.getElementById("mailList").innerHTML = "";
  loadMore();
}

function loadFolder(f) {
  folder = f;

  const titleMap = {
    unread: "未读",
    read: "已读",
    sent: "已发送",
    trash: "废纸篓",
    starred: "星标",
    draft: "草稿",
    all: "全部"
  };

  document.getElementById("listTitle").textContent = titleMap[f] || f;

  document.querySelectorAll(".nav").forEach((n) => n.classList.remove("active"));

  const nav = document.getElementById("nav-" + f);

  if (nav) {
    nav.classList.add("active");
  }

  document.getElementById("trashBar").classList.toggle("hidden", f !== "trash");

  document.getElementById("workspace").classList.add("hidden");
  document.getElementById("workspace").classList.add("md:block");

  reloadFolder();
}

function loadMore() {
  if (loading || !hasMore) return;

  loading = true;

  const sentinel = document.getElementById("sentinel");
  sentinel.textContent = "加载中...";

  api(
    "/api/emails?status=" +
      encodeURIComponent(folder) +
      "&page=" +
      page +
      "&limit=30&q=" +
      encodeURIComponent(document.getElementById("searchBox").value.trim())
  )
    .then((d) => {
      mails = mails.concat(d.mails || []);
      hasMore = d.hasMore;
      page++;

      renderMails();
      updateCounts(d);

      document.getElementById("listSub").textContent = "共 " + d.total + " 封";
      sentinel.textContent = hasMore ? "继续下滑加载" : "没有更多了";
    })
    .catch((e) => showToast(e.message, "error"))
    .finally(() => {
      loading = false;
    });
}

function debouncedSearch() {
  clearTimeout(window.searchTimer);
  window.searchTimer = setTimeout(reloadFolder, 300);
}

function updateCounts(d) {
  const m = {};

  (d.counts || []).forEach((c) => {
    m[c.status] = c.count;
  });

  ["read", "sent", "trash", "draft"].forEach((k) => {
    const el = document.getElementById("count-" + k);
    if (el) el.textContent = m[k] || 0;
  });

  document.getElementById("count-starred").textContent = d.starredCount || 0;

  const unread = document.getElementById("count-unread");

  if (m.unread > 0) {
    unread.textContent = m.unread;
    unread.classList.remove("hidden");
  } else {
    unread.classList.add("hidden");
  }
}

function renderMails() {
  const box = document.getElementById("mailList");

  box.innerHTML = "";

  if (!mails.length) {
    box.innerHTML =
      '<div class="p-8 text-center" style="color:var(--muted)">暂无邮件</div>';
    return;
  }

  mails.forEach((x) => {
    const d = document.createElement("div");

    d.className =
      "mail p-4 cursor-pointer " + (selectedId == x.id ? "selected" : "");

    d.onclick = () => openMail(x.id);

    d.innerHTML =
      '<div class="flex justify-between gap-2">' +
      '<b class="truncate">' +
      (x.starred ? "⭐ " : "") +
      esc(person(x.direction === "outbound" ? x.recipient : x.sender)) +
      "</b>" +
      '<span class="text-xs" style="color:var(--muted)">' +
      date(x.created_at) +
      "</span>" +
      "</div>" +
      '<div class="truncate mt-1 ' +
      (x.status === "unread" ? "font-black" : "") +
      '">' +
      esc(x.subject || "(无主题)") +
      "</div>" +
      '<div class="text-xs mt-1" style="color:var(--muted)">' +
      esc(x.status) +
      "</div>";

    box.appendChild(d);
  });
}

function showPane(id) {
  ["emptyPane", "detailPane", "composePane", "settingsPane", "adminPane"].forEach(
    (x) => document.getElementById(x).classList.add("hidden")
  );

  document.getElementById(id).classList.remove("hidden");
  document.getElementById("workspace").classList.remove("hidden");
}

function openMail(id) {
  selectedId = id;

  api("/api/emails/" + id)
    .then((e) => {
      showPane("detailPane");

      document.getElementById("detailSubject").textContent =
        e.subject || "(无主题)";
      document.getElementById("detailFrom").textContent = e.sender || "";
      document.getElementById("detailTime").textContent = e.created_at || "";
      document.getElementById("detailBody").textContent = e.body_text || "";

      const htmlBox = document.getElementById("htmlBox");
      htmlBox.classList.toggle("hidden", !e.body_html);
      htmlBox.innerHTML = e.body_html || "";

      const starBtn = document.getElementById("starBtn");
      starBtn.textContent = e.starred ? "取消星标" : "星标";
      starBtn.onclick = () => action(id, "toggle-star");

      document.getElementById("replyBtn").onclick = () => {
        compose();

        const form = document.getElementById("composeForm");

        form.elements["to"].value = emailAddr(e.sender);
        form.elements["subject"].value = (e.subject || "").startsWith("Re:")
          ? e.subject
          : "Re: " + (e.subject || "");
        form.elements["body"].focus();
      };

      document.getElementById("restoreBtn").classList.toggle(
        "hidden",
        e.status !== "trash"
      );

      document.getElementById("trashBtn").classList.toggle(
        "hidden",
        e.status === "trash"
      );

      document.getElementById("restoreBtn").onclick = () => action(id, "restore");
      document.getElementById("trashBtn").onclick = () => action(id, "trash");
      document.getElementById("deleteBtn").onclick = () =>
        confirm("永久删除？") && action(id, "delete");

      renderAttachments(e.attachments || []);
      reloadFolder();
    })
    .catch((e) => showToast(e.message, "error"));
}

function renderAttachments(a) {
  const box = document.getElementById("attachmentBox");
  const zipBtn = document.getElementById("zipBtn");

  box.innerHTML = "";
  zipBtn.classList.toggle("hidden", a.length <= 1);

  if (!a.length) {
    box.innerHTML =
      '<span class="text-xs" style="color:var(--muted)">无附件</span>';
    return;
  }

  a.forEach((x) => {
    const l = document.createElement("a");

    l.href = "/api/attachments/" + x.id;
    l.className = "solid border rounded-2xl p-3 flex justify-between";
    l.innerHTML =
      '<b class="truncate">📎 ' +
      esc(x.filename) +
      "</b>" +
      '<span class="text-xs">' +
      size(x.size) +
      "</span>";

    box.appendChild(l);
  });
}

function downloadZip() {
  api("/api/emails/" + selectedId + "/attachments-all").then(async (a) => {
    const z = new JSZip();

    a.forEach((f) => {
      z.file(
        f.filename,
        Uint8Array.from(atob(f.base64Data), (c) => c.charCodeAt(0))
      );
    });

    const b = await z.generateAsync({ type: "blob" });
    const u = URL.createObjectURL(b);
    const el = document.createElement("a");

    el.href = u;
    el.download = "attachments-" + selectedId + ".zip";
    el.click();

    URL.revokeObjectURL(u);
  });
}

function action(id, a) {
  api("/api/emails/action/" + id, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      action: a
    })
  })
    .then(() => {
      showToast("操作完成", "success");
      showPane("emptyPane");
      reloadFolder();
    })
    .catch((e) => showToast(e.message, "error"));
}

function emptyTrash() {
  if (confirm("永久清空废纸篓？")) {
    action(0, "empty-trash");
  }
}

function compose() {
  showPane("composePane");

  const saved = JSON.parse(localStorage.local_draft || "{}");

  if (saved && !document.getElementById("draftId").value) {
    const form = document.getElementById("composeForm");

    form.elements["to"].value = saved.to || "";
    form.elements["subject"].value = saved.subject || "";
    form.elements["body"].value = saved.body || "";
  }
}

function discardCompose() {
  localStorage.removeItem("local_draft");

  document.getElementById("composeForm").reset();
  document.getElementById("draftId").value = "";
  document.getElementById("draftState").textContent = "";

  showPane("emptyPane");
}

function draftChanged() {
  const form = document.getElementById("composeForm");

  localStorage.local_draft = JSON.stringify({
    to: form.elements["to"].value,
    subject: form.elements["subject"].value,
    body: form.elements["body"].value
  });

  document.getElementById("draftState").textContent = "本地草稿已保存";

  clearTimeout(draftTimer);
  draftTimer = setTimeout(saveDraft, 900);
}

function saveDraft() {
  const form = document.getElementById("composeForm");

  api("/api/drafts", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      id: document.getElementById("draftId").value,
      to: form.elements["to"].value,
      subject: form.elements["subject"].value,
      body: form.elements["body"].value
    })
  })
    .then((d) => {
      document.getElementById("draftId").value = d.id;
      document.getElementById("draftState").textContent = "云端草稿已保存";
    })
    .catch(() => {
      document.getElementById("draftState").textContent = "云端草稿保存失败";
    });
}

function sendMail(e) {
  e.preventDefault();

  api("/api/emails/send", {
    method: "POST",
    body: new FormData(document.getElementById("composeForm"))
  })
    .then(() => {
      showToast("发送成功", "success");

      localStorage.removeItem("local_draft");

      document.getElementById("composeForm").reset();
      document.getElementById("draftId").value = "";

      loadFolder("sent");
    })
    .catch((e) => showToast(e.message, "error"));
}

function showSettings() {
  showPane("settingsPane");
}

function saveSettings() {
  api("/api/user/settings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      new_username: document.getElementById("settingsUser").value,
      new_password: document.getElementById("settingsPass").value
    })
  })
    .then(() => {
      showToast("已保存，请重新登录", "success");
      setTimeout(logout, 800);
    })
    .catch((e) => showToast(e.message, "error"));
}

function showAdmin() {
  showPane("adminPane");
  loadUsers();
}

function loadUsers() {
  api("/api/admin/users").then((users) => {
    const box = document.getElementById("usersBox");

    box.innerHTML = "";

    users.forEach((u) => {
      const d = document.createElement("div");

      d.className =
        "solid border rounded-2xl p-3 flex flex-wrap gap-2 items-center justify-between";

      d.innerHTML =
        "<b>" +
        esc(u.username) +
        "</b>" +
        '<span class="text-xs">' +
        (u.is_admin ? "管理员" : "用户") +
        " / " +
        (u.disabled ? "停用" : "启用") +
        "</span>" +
        '<div class="flex gap-2">' +
        '<button class="btn soft" onclick="resetUser(' +
        u.id +
        ')">重置密码</button>' +
        '<button class="btn soft" onclick="toggleUser(' +
        u.id +
        "," +
        !u.disabled +
        ')">' +
        (u.disabled ? "启用" : "停用") +
        "</button>" +
        '<button class="btn danger" onclick="deleteUser(' +
        u.id +
        ')">删除</button>' +
        "</div>";

      box.appendChild(d);
    });
  });
}

function createUser() {
  api("/api/admin/users", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      username: document.getElementById("newUser").value,
      password: document.getElementById("newPass").value,
      is_admin: document.getElementById("newAdmin").checked
    })
  })
    .then(() => {
      showToast("创建成功", "success");

      document.getElementById("newUser").value = "";
      document.getElementById("newPass").value = "";

      loadUsers();
    })
    .catch((e) => showToast(e.message, "error"));
}

function resetUser(id) {
  const p = prompt("输入新密码，至少8位");

  if (!p) return;

  api("/api/admin/users/" + id, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      action: "reset-password",
      password: p
    })
  })
    .then(loadUsers)
    .catch((e) => showToast(e.message, "error"));
}

function toggleUser(id, v) {
  api("/api/admin/users/" + id, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      action: "set-disabled",
      disabled: v
    })
  })
    .then(loadUsers)
    .catch((e) => showToast(e.message, "error"));
}

function deleteUser(id) {
  if (!confirm("删除用户？")) return;

  api("/api/admin/users/" + id, {
    method: "DELETE"
  })
    .then(loadUsers)
    .catch((e) => showToast(e.message, "error"));
}

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function person(s) {
  return String(s || "").split("<")[0].trim() || s || "unknown";
}

function emailAddr(s) {
  const m = String(s || "").match(/<([^>]+)>/);
  return m ? m[1] : String(s || "").trim();
}

function date(s) {
  try {
    return new Date(String(s).replace(" ", "T")).toLocaleString("zh-CN", {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit"
    });
  } catch {
    return s || "";
  }
}

function size(n) {
  n = Number(n || 0);

  return n > 1048576
    ? (n / 1048576).toFixed(2) + " MB"
    : n > 1024
      ? (n / 1024).toFixed(1) + " KB"
      : n + " B";
}
</script>
</body>
</html>`;
}