import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { requireAuth } from "../middleware/auth";
import { verifyPassword, hashPassword } from "../utils/crypto";
import { insertAuditLog } from "../db";

export const profileRoutes = new Hono<{ Bindings: Env }>();
profileRoutes.use("*", requireAuth);

/** GET /api/profile：当前用户资料 */
profileRoutes.get("/", async (c) => {
  const user = c.get("user") as JwtPayload;
  const row = await c.env.DB.prepare(
    "SELECT id, username, nickname, avatar_text, avatar_color, role, status, email, created_at FROM users WHERE id = ?"
  ).bind(user.uid).first<any>();
  if (!row) return c.json({ error: "用户不存在" }, 404);
  return c.json(row);
});

/**
 * PUT /api/profile
 * body: { nickname?, avatarText?, avatarColor?, email?, oldPassword?, newPassword? }
 */
profileRoutes.put("/", async (c) => {
  const user = c.get("user") as JwtPayload;
  const body = await c.req.json<{
    nickname?: string; avatarText?: string; avatarColor?: string; email?: string;
    oldPassword?: string; newPassword?: string;
  }>();

  const row = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(user.uid).first<any>();
  if (!row) return c.json({ error: "用户不存在" }, 404);

  const updates: string[] = [];
  const binds: any[] = [];

  if (body.nickname !== undefined) { updates.push("nickname = ?"); binds.push(body.nickname.trim() || null); }
  if (body.avatarText !== undefined) {
    const t = body.avatarText.trim().slice(0, 2) || "管";
    updates.push("avatar_text = ?"); binds.push(t);
  }
  if (body.avatarColor !== undefined) {
    if (!/^#[0-9a-fA-F]{3,8}$/.test(body.avatarColor)) return c.json({ error: "头像颜色格式不正确" }, 400);
    updates.push("avatar_color = ?"); binds.push(body.avatarColor);
  }
  if (body.email !== undefined) {
    if (body.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email)) return c.json({ error: "邮箱格式不正确" }, 400);
    updates.push("email = ?"); binds.push(body.email.trim() || null);
  }

  if (body.newPassword) {
    if (body.newPassword.length < 6) return c.json({ error: "新密码长度至少6位" }, 400);
    if (!body.oldPassword) return c.json({ error: "修改密码需要提供原密码" }, 400);
    const ok = await verifyPassword(body.oldPassword, row.password_hash);
    if (!ok) return c.json({ error: "原密码不正确" }, 401);
    updates.push("password_hash = ?"); binds.push(await hashPassword(body.newPassword));
  }

  if (!updates.length) return c.json({ error: "没有需要更新的内容" }, 400);
  updates.push("updated_at = ?"); binds.push(Math.floor(Date.now() / 1000));
  binds.push(user.uid);

  await c.env.DB.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`).bind(...binds).run();
  await insertAuditLog(c.env, user.uid, "update_profile", `user:${user.uid}`);
  return c.json({ ok: true });
});