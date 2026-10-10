import { Hono } from "hono";
import type { Env } from "../types";
import { requireAuth, requireAdmin } from "../middleware/auth";
import { now } from "../db";
import { aesEncrypt, aesDecrypt } from "../utils/crypto";

export const mailSettingsRoutes = new Hono<{ Bindings: Env }>();
mailSettingsRoutes.use("*", requireAuth, requireAdmin);

/** GET /api/mail-settings：读取（Key 脱敏，只回 hasKey） */
mailSettingsRoutes.get("/", async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT key, value FROM system_settings WHERE key IN ('mail_api_key','mail_from')"
  ).all<{ key: string; value: string }>();
  const map = new Map(results.map(r => [r.key, r.value]));
  let hasKey = !!map.get('mail_api_key');
  let keyPreview = '';
  /* 尝试解密展示尾4位（未加密的旧值直接显示前4） */
  const enc = map.get('mail_api_key');
  if (enc) {
    try {
      const plain = c.env.ENCRYPT_KEY ? await aesDecrypt(enc, c.env.ENCRYPT_KEY) : enc;
      keyPreview = plain.slice(0, 4) + '****' + plain.slice(-4);
      hasKey = true;
    } catch { hasKey = false; }
  }
  return c.json({ hasKey, keyPreview, from: map.get('mail_from') || '' });
});

/** PUT /api/mail-settings：保存（Key 加密落库；留空不改） */
mailSettingsRoutes.put("/", async (c) => {
  const body = await c.req.json<{ apiKey?: string; from?: string }>();

  if (body.apiKey) {
    const enc = c.env.ENCRYPT_KEY ? await aesEncrypt(body.apiKey, c.env.ENCRYPT_KEY) : body.apiKey;
    await c.env.DB.prepare(
      "INSERT INTO system_settings (key, value, updated_at) VALUES ('mail_api_key', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
    ).bind(enc, now()).run();
  }
  if (body.from !== undefined) {
    await c.env.DB.prepare(
      "INSERT INTO system_settings (key, value, updated_at) VALUES ('mail_from', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
    ).bind(body.from.trim() || null, now()).run();
  }
  return c.json({ ok: true });
});