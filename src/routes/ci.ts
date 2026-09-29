import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { verifyPassword, signJwt, hashPassword } from "../utils/crypto";
import { userHasDomainPerm, now, insertAuditLog } from "../db";
import { notifyDomainOwners } from "../notify/domainOwners";
import { requireAuth, requireAdmin } from "../middleware/auth";

export const ciTokenRoutes = new Hono<{ Bindings: Env }>();
export const ciCallbackRoutes = new Hono<{ Bindings: Env }>();

/* =====================================================================
   API Key 管理（管理员，供 GitHub Actions 用）
   路由 /ci-keys（applink.ts 已占用 /keys）。签发为两段式：
   preview（仅前端预览，不落库）→ confirm（确认后写库）。
   ===================================================================== */

/** 预览生成（不落库）：POST /api/open/ci-keys/preview → { ok, key, secret } */
ciTokenRoutes.post("/ci-keys/preview", requireAuth, requireAdmin, async (c) => {
  const key = "dk_" + crypto.randomUUID().replace(/-/g, "");
  const secret = "ds_" + crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  return c.json({ ok: true, key, secret });
});

/** 确认写入：POST /api/open/ci-keys/confirm  body { key, secret, remark? } */
ciTokenRoutes.post("/ci-keys/confirm", requireAuth, requireAdmin, async (c) => {
  const user = c.get("user") as JwtPayload;
  const { key, secret, remark } = await c.req.json<{ key: string; secret: string; remark?: string }>();
  if (!key || !secret || !key.startsWith("dk_") || !secret.startsWith("ds_"))
    return c.json({ error: "参数无效" }, 400);

  const hash = await hashPassword(secret);
  const res = await c.env.DB.prepare(
    "INSERT INTO api_keys (user_id, key, secret_hash, remark, status, created_at) VALUES (?,?,?,?,?,?)"
  )
    .bind(user.uid, key, hash, remark || "GitHub Actions 证书签发", "active", now())
    .run();
  return c.json({ ok: true, id: res.meta.last_row_id });
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
 * 返回20天内到期、且开启自动续签的证书列表。
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