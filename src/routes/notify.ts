import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { requireAuth } from "../middleware/auth";
import { now } from "../db";
import { sendNotify, type NotifyChannelType } from "../notify/channels";

export const notifyRoutes = new Hono<{ Bindings: Env }>();
notifyRoutes.use("*", requireAuth);

/** 当前用户的渠道列表（含 name；config 不返回，防止密钥泄漏） */
notifyRoutes.get("/", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { results } = await c.env.DB.prepare(
    "SELECT id, type, name, enabled, created_at FROM notify_channels WHERE user_id = ? ORDER BY id"
  )
    .bind(user.uid)
    .all();
  return c.json(results);
});

/** 新增渠道：{ type, name?, config } */
notifyRoutes.post("/", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { type, name, config } = await c.req.json<{ type: NotifyChannelType; name?: string; config: Record<string, any> }>();
  await c.env.DB.prepare(
    "INSERT INTO notify_channels (user_id, type, config, enabled, created_at, name) VALUES (?,?,?,?,?,?)"
  )
    .bind(user.uid, type, JSON.stringify(config), 1, now(), name || null)
    .run();
  return c.json({ ok: true });
});

/** 单个渠道详情（编辑时拉取，config 明文返回） */
notifyRoutes.get("/:id", async (c) => {
  const user = c.get("user") as JwtPayload;
  const row = await c.env.DB.prepare("SELECT * FROM notify_channels WHERE id = ? AND user_id = ?")
    .bind(Number(c.req.param("id")), user.uid)
    .first<any>();
  if (!row) return c.json({ error: "渠道不存在" }, 404);
  return c.json({ id: row.id, type: row.type, name: row.name, config: JSON.parse(row.config), enabled: row.enabled });
});

/** 修改渠道配置与名称：{ config, name? }（type 不可改；name 不传则保留原名） */
notifyRoutes.put("/:id", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { config, name } = await c.req.json<{ config: Record<string, any>; name?: string }>();
  await c.env.DB.prepare(
    "UPDATE notify_channels SET config = ?, name = COALESCE(?, name) WHERE id = ? AND user_id = ?"
  )
    .bind(JSON.stringify(config), name ?? null, Number(c.req.param("id")), user.uid)
    .run();
  return c.json({ ok: true });
});

/** 启用/停用渠道：{ enabled: boolean } */
notifyRoutes.put("/:id/enabled", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { enabled } = await c.req.json<{ enabled: boolean }>();
  await c.env.DB.prepare("UPDATE notify_channels SET enabled = ? WHERE id = ? AND user_id = ?")
    .bind(enabled ? 1 : 0, Number(c.req.param("id")), user.uid)
    .run();
  return c.json({ ok: true });
});

notifyRoutes.delete("/:id", async (c) => {
  const user = c.get("user") as JwtPayload;
  await c.env.DB.prepare("DELETE FROM notify_channels WHERE id = ? AND user_id = ?")
    .bind(Number(c.req.param("id")), user.uid)
    .run();
  return c.json({ ok: true });
});

notifyRoutes.post("/:id/test", async (c) => {
  const user = c.get("user") as JwtPayload;
  const row = await c.env.DB.prepare("SELECT * FROM notify_channels WHERE id = ? AND user_id = ?")
    .bind(Number(c.req.param("id")), user.uid)
    .first<any>();
  if (!row) return c.json({ error: "渠道不存在" }, 404);
  try {
    await sendNotify(row.type, JSON.parse(row.config), {
      title: "DNS-SUB 测试通知",
      content: "这是一条测试消息，如果你收到了，说明该通知渠道配置成功。",
    });
    return c.json({ ok: true });
  } catch (e: any) {
    return c.json({ ok: false, error: e.message }, 200);
  }
});