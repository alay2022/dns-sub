import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { requireAuth, requireAdmin } from "../middleware/auth";
import { now } from "../db";
import { sendNotify } from "../notify/channels";

export const noticeRoutes = new Hono<{ Bindings: Env }>();
noticeRoutes.use("*", requireAuth);

/** 公告列表（所有登录用户可读；置顶在前，时间倒序） */
noticeRoutes.get("/", async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT id, title, content, pinned, created_at, updated_at FROM notices ORDER BY pinned DESC, created_at DESC"
  ).all();
  return c.json(results);
});

/** 创建公告（管理员）：body { title, content?, pinned? }；创建后推送到所有启用的通知渠道 */
noticeRoutes.post("/", requireAdmin, async (c) => {
  const admin = c.get("user") as JwtPayload;
  const { title, content, pinned } = await c.req.json<{ title: string; content?: string; pinned?: boolean }>();
  if (!title || !title.trim()) return c.json({ error: "公告标题必填" }, 400);

  const ts = now();
  const res = await c.env.DB.prepare(
    "INSERT INTO notices (title, content, pinned, created_at, updated_at) VALUES (?,?,?,?,?)"
  )
    .bind(title.trim(), content || "", pinned ? 1 : 0, ts, ts)
    .run();

  /* 推送：遍历所有启用的渠道，逐个发送；失败不影响公告创建，收集错误返回 */
  const { results: channels } = await c.env.DB.prepare(
    "SELECT id, type, config FROM notify_channels WHERE enabled = 1"
  ).all<{ id: number; type: string; config: string }>();

  const errors: string[] = [];
  let sent = 0;
  const msgTitle = `📢 DNS-SUB通知：${title.trim()}`;
  const msgBody = (content || "").trim() || "(无正文)";

  for (const ch of channels) {
    try {
      await sendNotify(ch.type, JSON.parse(ch.config), { title: msgTitle, content: msgBody });
      sent++;
    } catch (e: any) {
      errors.push(`渠道#${ch.id}(${ch.type}): ${e.message}`);
    }
  }

  return c.json({ ok: true, id: res.meta.last_row_id, notified: sent, failed: errors.length, errors });
});

/** 更新公告（管理员）：{ title?, content?, pinned? }（不重推） */
noticeRoutes.put("/:id", requireAdmin, async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.json<{ title?: string; content?: string; pinned?: boolean }>();
  const row = await c.env.DB.prepare("SELECT * FROM notices WHERE id = ?").bind(id).first<any>();
  if (!row) return c.json({ error: "公告不存在" }, 404);

  await c.env.DB.prepare(
    "UPDATE notices SET title=?, content=?, pinned=?, updated_at=? WHERE id=?"
  )
    .bind(
      body.title !== undefined ? body.title.trim() : row.title,
      body.content !== undefined ? body.content : row.content,
      body.pinned !== undefined ? (body.pinned ? 1 : 0) : row.pinned,
      now(), id
    )
    .run();
  return c.json({ ok: true });
});

/** 删除公告（管理员） */
noticeRoutes.delete("/:id", requireAdmin, async (c) => {
  const id = Number(c.req.param("id"));
  await c.env.DB.prepare("DELETE FROM notices WHERE id = ?").bind(id).run();
  return c.json({ ok: true });
});