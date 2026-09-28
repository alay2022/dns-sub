import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { verifyPassword, signJwt, hashPassword } from "../utils/crypto";
import { userHasDomainPerm, now, insertAuditLog } from "../db";
import { notifyDomainOwners } from "../notify/domainOwners";
import { requireAuth, requireAdmin } from "../middleware/auth";

export const ciTokenRoutes = new Hono<{ Bindings: Env }>();
export const ciCallbackRoutes = new Hono<{ Bindings: Env }>();

/* =====================================================================
   API Key 管理（管理员，供 GitHub Actions 证书签发用）
   路由用 /ci-keys（不用 /keys）：applink.ts 已占用 /keys（老系统"开放API"
   端点，返回 {apiKey, apiSecret} 且无 id 字段），注册在前会抢走 /keys 请求。
   注意：每个路由都要 requireAuth 在 requireAdmin 之前——requireAdmin 依赖
   requireAuth 挂载的 user（单独用会 500: reading 'role' of undefined）。
   /ci-token 保持无登录鉴权（Actions 匿名调用，靠 API Key/Secret 自证）。
   ===================================================================== */

/** 签发 API Key：POST /api/open/ci-keys  body { remark? } → { ok, id, key, secret }（secret 仅此一次明文） */
ciTokenRoutes.post("/ci-keys", requireAuth, requireAdmin, async (c) => {
  const user = c.get("user") as JwtPayload;
  const { remark } = await c.req.json<{ remark?: string }>().catch(() => ({ remark: undefined }));
  const key = "dk_" + crypto.randomUUID().replace(/-/g, "");
  const secret = "ds_" + crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  const hash = await hashPassword(secret);
  const res = await c.env.DB.prepare(
    "INSERT INTO api_keys (user_id, key, secret_hash, remark, status, created_at) VALUES (?,?,?,?,?,?)"
  )
    .bind(user.uid, key, hash, remark || "GitHub Actions 证书签发", "active", now())
    .run();
  return c.json({ ok: true, id: res.meta.last_row_id, key, secret });
});

/** 列表：GET /api/open/ci-keys → [{ id, key, remark, status, created_at }]（不回 secret） */
ciTokenRoutes.get("/ci-keys", requireAuth, requireAdmin, async (c) => {
  const user = c.get("user") as JwtPayload;
  const { results } = await c.env.DB.prepare(
    "SELECT id, key, remark, status, created_at FROM api_keys WHERE user_id = ? ORDER BY id DESC"
  ).bind(user.uid).all();
  return c.json(results);
});

/** 吊销（保留记录）：PUT /api/open/ci-keys/:id/revoke */
ciTokenRoutes.put("/ci-keys/:id/revoke", requireAuth, requireAdmin, async (c) => {
  const id = Number(c.req.param("id"));
  if (!Number.isInteger(id)) return c.json({ error: "无效的ID" }, 400);
  await c.env.DB.prepare("UPDATE api_keys SET status = 'revoked' WHERE id = ?").bind(id).run();
  return c.json({ ok: true });
});

/** 物理删除：DELETE /api/open/ci-keys/:id */
ciTokenRoutes.delete("/ci-keys/:id", requireAuth, requireAdmin, async (c) => {
  const id = Number(c.req.param("id"));
  if (!Number.isInteger(id)) return c.json({ error: "无效的ID" }, 400);
  await c.env.DB.prepare("DELETE FROM api_keys WHERE id = ?").bind(id).run();
  return c.json({ ok: true });
});

/**
 * POST /api/open/ci-token
 * body: { apiKey, apiSecret, domainId }
 * 专供 GitHub Actions：用 API Key 换一个域名限定、有效期较长（默认30分钟）的 JWT，
 * 用于调用 /api/domains/:id/records 完成 DNS-01 的 TXT 记录增删。
 * 鉴权：api_keys 表（key 明文 + PBKDF2(secret) 哈希）；权限：admin 或该域名 readwrite。
 */
ciTokenRoutes.post("/ci-token", async (c) => {
  const { apiKey, apiSecret, domainId } = await c.req.json<{ apiKey: string; apiSecret: string; domainId: number }>();
  if (!apiKey || !apiSecret || !domainId) return c.json({ error: "参数不完整" }, 400);

  const keyRow = await c.env.DB.prepare("SELECT * FROM api_keys WHERE key = ? AND status = 'active'").bind(apiKey).first();
  if (!keyRow) return c.json({ error: "无效的API Key" }, 401);

  const ok = await verifyPassword(apiSecret, (keyRow as any).secret_hash);
  if (!ok) return c.json({ error: "API Secret 不正确" }, 401);

  const userId = (keyRow as any).user_id as number;
  const userRow = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId).first();
  if (!userRow || (userRow as any).status !== "active") return c.json({ error: "关联用户不可用" }, 403);

  if ((userRow as any).role !== "admin") {
    const hasPerm = await userHasDomainPerm(c.env, userId, domainId, true);
    if (!hasPerm) return c.json({ error: "该用户无该域名的读写权限" }, 403);
  }

  const expireSeconds = Number(c.env.CI_TOKEN_EXPIRE_SECONDS || 1800);
  const payload: JwtPayload = {
    uid: userId,
    username: (userRow as any).username,
    role: (userRow as any).role,
    scopeDomainId: domainId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expireSeconds,
  };
  const token = await signJwt(payload, c.env.JWT_SECRET);
  return c.json({ token, expiresIn: expireSeconds });
});

/** 回调鉴权：header X-CI-Secret 必须与 Worker secret CI_CALLBACK_SECRET 一致 */
function requireCiSecret(c: any): boolean {
  const secret = c.req.header("X-CI-Secret");
  return !!secret && !!c.env.CI_CALLBACK_SECRET && secret === c.env.CI_CALLBACK_SECRET;
}

/**
 * POST /api/ci/certs/:certId/complete
 * header: X-CI-Secret
 * body: { status: 'issued'|'failed', certPem?, keyPem?, expiresAt?, issuer?, error? }
 * GitHub Actions 签发完成后回调写回数据库，并触发通知（成功/失败都通知）。
 */
ciCallbackRoutes.post("/certs/:certId/complete", async (c) => {
  if (!requireCiSecret(c)) return c.json({ error: "无效的CI密钥" }, 401);

  const certId = Number(c.req.param("certId"));
  const body = await c.req.json<{
    status: "issued" | "failed";
    certPem?: string;
    keyPem?: string;
    expiresAt?: number;
    issuer?: string;
    error?: string;
  }>();

  const cert = await c.env.DB.prepare("SELECT * FROM ssl_certs WHERE id = ?").bind(certId).first<any>();
  if (!cert) return c.json({ error: "证书记录不存在" }, 404);

  const ts = now();
  if (body.status === "issued") {
    await c.env.DB.prepare(
      `UPDATE ssl_certs SET status='issued', cert_pem=?, key_pem=?, issuer=?, issued_at=?, expires_at=?, updated_at=? WHERE id=?`
    )
      .bind(body.certPem ?? null, body.keyPem ?? null, body.issuer ?? null, ts, body.expiresAt ?? null, ts, certId)
      .run();
    await insertAuditLog(c.env, null, "ci_issue_cert_success", `cert:${certId}`, cert.common_name);
    await notifyDomainOwners(c.env, cert.domain_id, {
      title: "证书签发成功",
      content: `域名 ${cert.common_name} 的证书已通过 GitHub Actions 签发成功。`,
    });
  } else {
    await c.env.DB.prepare("UPDATE ssl_certs SET status='failed', updated_at=? WHERE id=?").bind(ts, certId).run();
    await insertAuditLog(c.env, null, "ci_issue_cert_failed", `cert:${certId}`, body.error);
    await notifyDomainOwners(c.env, cert.domain_id, {
      title: "证书签发失败",
      content: `域名 ${cert.common_name} 的证书签发失败：${body.error || "未知错误"}，请登录系统查看详情。`,
    });
  }

  return c.json({ ok: true });
});

/**
 * GET /api/ci/due-for-renewal
 * header: X-CI-Secret
 * 返回20天内到期、且开启自动续签的证书列表，供 GitHub Actions 定时续签任务（renew-certs.ts）使用。
 */
ciCallbackRoutes.get("/due-for-renewal", async (c) => {
  if (!requireCiSecret(c)) return c.json({ error: "无效的CI密钥" }, 401);

  const RENEW_WINDOW_SECONDS = 20 * 24 * 3600;
  const ts = now();
  const { results } = await c.env.DB.prepare(
    `SELECT sc.id as cert_id, sc.common_name, sc.sans, sc.domain_id, d.domain_name as root_domain
     FROM ssl_certs sc JOIN domains d ON d.id = sc.domain_id
     WHERE sc.status = 'issued' AND sc.auto_renew = 1 AND sc.expires_at < ?`
  )
    .bind(ts + RENEW_WINDOW_SECONDS)
    .all();

  return c.json(results);
});