import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { requireAuth, requireAdmin } from "../middleware/auth";
import { now } from "../db";
import { randomShortId } from "../utils/crypto";
import { connect } from "cloudflare:sockets";

export const misubRoutes = new Hono<{ Bindings: Env }>();
misubRoutes.use("*", requireAuth);

/** 公开访问的订阅输出路由，不需要登录，挂载在 Worker 根路径（不是 /api 下面） */
export const misubPublicRoutes = new Hono<{ Bindings: Env }>();

function scopeClause(user: JwtPayload): { where: string; bind: any[] } {
  return user.role === "admin" ? { where: "1=1", bind: [] } : { where: "owner_user_id = ?", bind: [user.uid] };
}

// ==================== 全局设置（订阅链接用的自定义域名） ====================

misubRoutes.get("/settings", async (c) => {
  const row = await c.env.DB.prepare("SELECT domain FROM misub_settings WHERE id = 1").first<{ domain: string | null }>();
  return c.json({ domain: row?.domain || null });
});

misubRoutes.put("/settings", requireAdmin, async (c) => {
  const { domain } = await c.req.json<{ domain: string }>();
  await c.env.DB.prepare("UPDATE misub_settings SET domain = ?, updated_at = ? WHERE id = 1")
    .bind(domain ? domain.replace(/^https?:\/\//, "").replace(/\/$/, "") : null, now())
    .run();
  return c.json({ ok: true });
});

// ==================== 手动节点 ====================
// 注意：静态路径（/nodes/groups、/nodes/groups/reorder、/nodes/reorder、
// /nodes/batch-delete、/nodes/preview-subscription、/nodes/import-selected、/speedtest-url）
// 必须全部注册在动态参数路径（/nodes/:id）之前，否则会被 :id 吞掉。

misubRoutes.get("/nodes", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { where, bind } = scopeClause(user);
  const { results } = await c.env.DB.prepare(`SELECT * FROM misub_nodes WHERE ${where} ORDER BY sort_order, id`)
    .bind(...bind)
    .all();
  return c.json(results);
});

/** 分组列表：按 misub_group_order 的自定义顺序排；未记录的组排后面（按名称） */
misubRoutes.get("/nodes/groups", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { where, bind } = scopeClause(user);
  const { results } = await c.env.DB.prepare(
    `SELECT DISTINCT group_name FROM misub_nodes WHERE ${where} AND group_name IS NOT NULL AND group_name != '' ORDER BY group_name`
  )
    .bind(...bind)
    .all<{ group_name: string }>();

  const existing = results.map(r => r.group_name);
  const { results: orderRows } = await c.env.DB.prepare(
    "SELECT group_name, sort_order FROM misub_group_order ORDER BY sort_order"
  ).all<{ group_name: string; sort_order: number }>();
  const orderMap = new Map(orderRows.map(r => [r.group_name, r.sort_order]));

  const ordered = existing.sort((a, b) => {
    const oa = orderMap.has(a) ? orderMap.get(a)! : 100000 + a.localeCompare(b);
    const ob = orderMap.has(b) ? orderMap.get(b)! : 100000 + b.localeCompare(a);
    return oa - ob;
  });
  return c.json(ordered);
});

/** 分组chips拖动排序：body { orderedGroups: string[] } */
misubRoutes.put("/nodes/groups/reorder", async (c) => {
  const { orderedGroups } = await c.req.json<{ orderedGroups: string[] }>();
  if (!Array.isArray(orderedGroups)) return c.json({ error: "参数不能为空" }, 400);
  const clean = [...new Set(orderedGroups.filter((g): g is string => typeof g === 'string' && g.trim().length > 0))];
  await c.env.DB.prepare("DELETE FROM misub_group_order").run();
  if (clean.length) {
    await c.env.DB.batch(
      clean.map((g, i) => c.env.DB.prepare("INSERT INTO misub_group_order (group_name, sort_order) VALUES (?,?)").bind(g, i))
    );
  }
  return c.json({ ok: true });
});

/** 节点拖拽排序：body { orderedIds: number[] }（服务端过滤非法值） */
misubRoutes.put("/nodes/reorder", async (c) => {
  const { orderedIds } = await c.req.json<{ orderedIds: number[] }>();
  if (!Array.isArray(orderedIds)) return c.json({ error: "参数不能为空" }, 400);
  const cleanIds = [...new Set(orderedIds)].filter(id => Number.isInteger(id));
  if (!cleanIds.length) return c.json({ error: "没有有效的节点ID" }, 400);
  await c.env.DB.batch(
    cleanIds.map((id, i) => c.env.DB.prepare("UPDATE misub_nodes SET sort_order = ? WHERE id = ?").bind(i, id))
  );
  return c.json({ ok: true });
});

/** 批量删除节点 */
misubRoutes.post("/nodes/batch-delete", async (c) => {
  const { ids } = await c.req.json<{ ids: number[] }>();
  if (!Array.isArray(ids) || !ids.length) return c.json({ error: "参数不能为空" }, 400);
  const cleanIds = ids.filter(id => Number.isInteger(id));
  if (!cleanIds.length) return c.json({ error: "没有有效的节点ID" }, 400);
  await c.env.DB.batch(cleanIds.map((id) => c.env.DB.prepare("DELETE FROM misub_nodes WHERE id = ?").bind(id)));
  return c.json({ ok: true, deleted: cleanIds.length });
});

/** 新增节点：{ name?, group?, text }，text 支持单条或多行批量 */
misubRoutes.post("/nodes", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { name, group, text } = await c.req.json<{ name?: string; group?: string; text: string }>();
  const lines = (text || "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && /^[a-z0-9]+:\/\//i.test(l));
  if (!lines.length) return c.json({ error: "没有识别到有效的节点链接" }, 400);

  const ts = now();
  const maxRow = await c.env.DB.prepare("SELECT MAX(sort_order) as m FROM misub_nodes").first<{ m: number | null }>();
  let order = (maxRow?.m ?? 0) + 1;
  for (const url of lines) {
    const nodeName = lines.length === 1 && name ? name : extractNodeName(url);
    await c.env.DB.prepare(
      "INSERT INTO misub_nodes (owner_user_id, name, url, group_name, enabled, sort_order, created_at, updated_at) VALUES (?,?,?,?,1,?,?,?)"
    )
      .bind(user.uid, nodeName, url, group || null, order++, ts, ts)
      .run();
  }
  return c.json({ ok: true, imported: lines.length });
});

/** 第一步：拉取外部订阅，解析节点列表，只返回预览不落库 */
misubRoutes.post("/nodes/preview-subscription", async (c) => {
  const { url } = await c.req.json<{ url: string }>();
  if (!url) return c.json({ error: "请提供订阅地址" }, 400);

  try {
    const res = await fetch(url, {
      headers: { "User-Agent": "clash-verge/1.0", Accept: "*/*" },
      redirect: "follow",
    });
    if (!res.ok) return c.json({ error: `拉取订阅失败: HTTP ${res.status}` }, 200);
    const text = await res.text();
    const nodeUrls = decodeSubscriptionNodes(text);
    if (!nodeUrls.length) {
      const preview = text.slice(0, 150).replace(/\s+/g, " ");
      return c.json({ error: `没有解析出节点。响应内容开头：${preview || "(空)"}` }, 200);
    }
    return c.json({ items: nodeUrls.map((u) => ({ name: extractNodeName(u), url: u })) });
  } catch (e: any) {
    return c.json({ error: `拉取订阅失败: ${e.message}` }, 200);
  }
});

/** 第二步：把预览勾选的节点正式导入 */
misubRoutes.post("/nodes/import-selected", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { items, group } = await c.req.json<{ items: { name: string; url: string }[]; group?: string }>();
  if (!Array.isArray(items) || !items.length) return c.json({ error: "没有选中任何节点" }, 400);

  const ts = now();
  const maxRow = await c.env.DB.prepare("SELECT MAX(sort_order) as m FROM misub_nodes").first<{ m: number | null }>();
  let order = (maxRow?.m ?? 0) + 1;
  for (const item of items) {
    await c.env.DB.prepare(
      "INSERT INTO misub_nodes (owner_user_id, name, url, group_name, enabled, sort_order, created_at, updated_at) VALUES (?,?,?,?,1,?,?,?)"
    )
      .bind(user.uid, item.name, item.url, group || null, order++, ts, ts)
      .run();
  }
  return c.json({ ok: true, imported: items.length });
});

/** 未入库节点链接直接测速（预览页用） */
misubRoutes.post("/speedtest-url", async (c) => {
  const { url } = await c.req.json<{ url: string }>();
  const target = parseHostPort(url);
  if (!target) return c.json({ ok: false, error: "无法解析出服务器地址" }, 200);
  return c.json(await doSpeedTest(target));
});

/** 部分更新节点：只更新请求里带的字段，其余保留原值（根治 D1 undefined） */
misubRoutes.put("/nodes/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.json<{ name?: string; url?: string; group?: string; enabled?: boolean }>();
  const row = await c.env.DB.prepare("SELECT * FROM misub_nodes WHERE id = ?").bind(id).first<any>();
  if (!row) return c.json({ error: "节点不存在" }, 404);

  await c.env.DB.prepare(
    "UPDATE misub_nodes SET name=?, url=?, group_name=?, enabled=?, updated_at=? WHERE id=?"
  )
    .bind(
      body.name !== undefined ? body.name : row.name,
      body.url !== undefined ? body.url : row.url,
      body.group !== undefined ? (body.group || null) : row.group_name,
      body.enabled !== undefined ? (body.enabled ? 1 : 0) : row.enabled,
      now(),
      id
    )
    .run();
  return c.json({ ok: true });
});

/** 单节点测速（TCP握手；结果持久化） */
misubRoutes.post("/nodes/:id/speedtest", async (c) => {
  const id = Number(c.req.param("id"));
  const row = await c.env.DB.prepare("SELECT url FROM misub_nodes WHERE id = ?").bind(id).first<{ url: string }>();
  if (!row) return c.json({ error: "节点不存在" }, 404);

  const target = parseHostPort(row.url);
  if (!target) {
    await c.env.DB.prepare("UPDATE misub_nodes SET last_latency_ms=NULL, last_tested_at=? WHERE id=?").bind(now(), id).run();
    return c.json({ ok: false, error: "无法从该节点链接解析出服务器地址" }, 200);
  }

  const result = await doSpeedTest(target);
  await c.env.DB.prepare("UPDATE misub_nodes SET last_latency_ms=?, last_tested_at=? WHERE id=?")
    .bind(result.ok ? result.latency : null, now(), id)
    .run();
  return c.json(result);
});

async function doSpeedTest(target: { host: string; port: number }): Promise<{ ok: boolean; latency?: number; error?: string }> {
  let socket: any;
  try {
    const start = Date.now();
    socket = connect({ hostname: target.host, port: target.port });
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => setTimeout(() => reject(new Error("连接超时(5秒)")), 5000)),
    ]);
    return { ok: true, latency: Date.now() - start };
  } catch (e: any) {
    return { ok: false, error: e.message || "连接失败（也可能是机场屏蔽了Cloudflare出口IP，不代表节点真的不可用）" };
  } finally {
    if (socket) {
      try {
        await socket.close();
      } catch {
        /* 忽略关闭失败 */
      }
    }
  }
}

// ==================== 订阅组 (Profiles) ====================
// 路由顺序：/profiles/reorder 必须在 /profiles/:id 之前（静态优先）！

misubRoutes.get("/profiles", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { where, bind } = scopeClause(user);
  const { results } = await c.env.DB.prepare(`SELECT * FROM misub_profiles WHERE ${where} ORDER BY sort_order, id`)
    .bind(...bind)
    .all();
  return c.json(results);
});

/** 订阅组卡片拖动排序：body { orderedIds: number[] } */
misubRoutes.put("/profiles/reorder", async (c) => {
  const { orderedIds } = await c.req.json<{ orderedIds: number[] }>();
  if (!Array.isArray(orderedIds)) return c.json({ error: "参数不能为空" }, 400);
  const cleanIds = [...new Set(orderedIds)].filter(id => Number.isInteger(id));
  if (!cleanIds.length) return c.json({ error: "没有有效的订阅组ID" }, 400);
  await c.env.DB.batch(
    cleanIds.map((id, i) => c.env.DB.prepare("UPDATE misub_profiles SET sort_order = ? WHERE id = ?").bind(i, id))
  );
  return c.json({ ok: true });
});

async function validateCustomId(env: Env, customId: string | undefined, excludeProfileId?: number): Promise<string | null> {
  if (!customId) return null;
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(customId)) return "自定义ID只能包含字母、数字、下划线、短横线，长度3-32位";
  const existing = await env.DB.prepare("SELECT id FROM misub_profiles WHERE custom_id = ?").bind(customId).first<{ id: number }>();
  if (existing && existing.id !== excludeProfileId) return "该自定义ID已被占用，换一个试试";
  return null;
}

misubRoutes.post("/profiles", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { name, nodeIds, customId } = await c.req.json<{ name: string; nodeIds: number[]; customId?: string }>();
  if (!name) return c.json({ error: "分组名称必填" }, 400);

  const idError = await validateCustomId(c.env, customId);
  if (idError) return c.json({ error: idError }, 400);

  const ts = now();
  const maxRow = await c.env.DB.prepare("SELECT MAX(sort_order) as m FROM misub_profiles").first<{ m: number | null }>();

  let shareToken = "";
  for (let i = 0; i < 5; i++) {
    const candidate = randomShortId(6);
    const clash = await c.env.DB.prepare("SELECT id FROM misub_profiles WHERE share_token = ?").bind(candidate).first();
    if (!clash) {
      shareToken = candidate;
      break;
    }
  }
  if (!shareToken) return c.json({ error: "生成分享码失败，请重试一次" }, 500);

  const res = await c.env.DB.prepare(
    "INSERT INTO misub_profiles (owner_user_id, name, share_token, custom_id, node_ids, sort_order, enabled, is_public, created_at, updated_at) VALUES (?,?,?,?,?,?,1,1,?,?)"
  )
    .bind(user.uid, name, shareToken, customId || null, JSON.stringify(nodeIds || []), (maxRow?.m ?? 0) + 1, ts, ts)
    .run();
  return c.json({ ok: true, id: res.meta.last_row_id });
});

misubRoutes.put("/profiles/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.json<{ name?: string; nodeIds?: number[]; customId?: string; enabled?: boolean }>();
  const row = await c.env.DB.prepare("SELECT * FROM misub_profiles WHERE id = ?").bind(id).first<any>();
  if (!row) return c.json({ error: "分组不存在" }, 404);

  if (body.customId !== undefined) {
    const idError = await validateCustomId(c.env, body.customId || undefined, id);
    if (idError) return c.json({ error: idError }, 400);
  }

  await c.env.DB.prepare("UPDATE misub_profiles SET name=?, node_ids=?, custom_id=?, enabled=?, updated_at=? WHERE id=?")
    .bind(
      body.name ?? row.name,
      JSON.stringify(body.nodeIds ?? JSON.parse(row.node_ids)),
      body.customId !== undefined ? body.customId || null : row.custom_id,
      body.enabled === undefined ? row.enabled : body.enabled ? 1 : 0,
      now(),
      id
    )
    .run();
  return c.json({ ok: true });
});

misubRoutes.delete("/profiles/:id", async (c) => {
  const id = Number(c.req.param("id"));
  await c.env.DB.prepare("DELETE FROM misub_profiles WHERE id = ?").bind(id).run();
  await c.env.DB.prepare("DELETE FROM misub_access_log WHERE profile_id = ?").bind(id).run();
  return c.json({ ok: true });
});

misubRoutes.get("/profiles/:id/log", async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT ip, user_agent, created_at FROM misub_access_log WHERE profile_id = ? ORDER BY created_at DESC LIMIT 50"
  )
    .bind(Number(c.req.param("id")))
    .all();
  return c.json(results);
});

// ==================== 工具函数 ====================

function extractNodeName(url: string): string {
  const hashIdx = url.indexOf("#");
  if (hashIdx >= 0) {
    try {
      return decodeURIComponent(url.slice(hashIdx + 1));
    } catch {
      return url.slice(hashIdx + 1);
    }
  }
  return url.split("://")[0].toUpperCase();
}

export function decodeSubscriptionNodes(text: string): string[] {
  const trimmed = text.trim();
  if (/^[a-z0-9]+:\/\//i.test(trimmed)) {
    return trimmed.split("\n").map((l) => l.trim()).filter(Boolean);
  }
  try {
    let b64 = trimmed.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4;
    if (pad) b64 += "=".repeat(4 - pad);
    const decoded = atob(b64);
    return decoded.split("\n").map((l) => l.trim()).filter((l) => /^[a-z0-9]+:\/\//i.test(l));
  } catch {
    return [];
  }
}

function parseHostPort(nodeUrl: string): { host: string; port: number } | null {
  try {
    const scheme = nodeUrl.split("://")[0].toLowerCase();

    if (scheme === "vmess") {
      const b64 = nodeUrl.slice(8).split("#")[0].split("?")[0];
      const json = JSON.parse(atob(b64.replace(/-/g, "+").replace(/_/g, "/")));
      return { host: json.add, port: Number(json.port) };
    }

    if (scheme === "ss") {
      const rest = nodeUrl.slice(5).split("#")[0];
      const atIdx = rest.lastIndexOf("@");
      if (atIdx >= 0) {
        const hostPort = rest.slice(atIdx + 1).split("?")[0].split("/")[0];
        const [host, port] = hostPort.split(":");
        if (host && port && !isNaN(Number(port))) return { host, port: Number(port) };
      }
      try {
        const decoded = atob(rest.replace(/-/g, "+").replace(/_/g, "/"));
        const m = decoded.match(/@([^:@/]+):(\d+)/);
        if (m) return { host: m[1], port: Number(m[2]) };
      } catch {
        /* fallthrough */
      }
      return null;
    }

    const u = new URL(nodeUrl.replace(new RegExp(`^${scheme}:\\/\\/`), "https://"));
    if (u.hostname && u.port) return { host: u.hostname, port: Number(u.port) };
    return null;
  } catch {
    return null;
  }
}

// ==================== 公开订阅输出 ====================

misubPublicRoutes.get("/:idOrToken", async (c) => {
  const idOrToken = c.req.param("idOrToken");
  const profile = await c.env.DB.prepare("SELECT * FROM misub_profiles WHERE custom_id = ? OR share_token = ?")
    .bind(idOrToken, idOrToken)
    .first<any>();
  if (!profile) return c.text("订阅链接不存在或已失效", 404);
  if (!profile.enabled) return c.text("该订阅组已被停用", 403);

  c.executionCtx.waitUntil(
    (async () => {
      await c.env.DB.prepare("UPDATE misub_profiles SET access_count = access_count + 1 WHERE id = ?").bind(profile.id).run();
      await c.env.DB.prepare("INSERT INTO misub_access_log (profile_id, ip, user_agent, created_at) VALUES (?,?,?,?)")
        .bind(profile.id, c.req.header("cf-connecting-ip") || "", c.req.header("User-Agent") || "", Math.floor(Date.now() / 1000))
        .run();
      await c.env.DB.prepare(
        `DELETE FROM misub_access_log WHERE profile_id = ? AND id NOT IN (
           SELECT id FROM misub_access_log WHERE profile_id = ? ORDER BY created_at DESC LIMIT 200
         )`
      )
        .bind(profile.id, profile.id)
        .run();
    })()
  );

  const nodeIds: number[] = JSON.parse(profile.node_ids || "[]");
  let nodeUrls: string[] = [];
  if (nodeIds.length) {
    const { results: nodes } = await c.env.DB.prepare(
      `SELECT id, url FROM misub_nodes WHERE id IN (${nodeIds.map(() => "?").join(",")}) AND enabled = 1`
    )
      .bind(...nodeIds)
      .all<{ id: number; url: string }>();
    const urlById = new Map(nodes.map((n) => [n.id, n.url]));
    nodeUrls = nodeIds.map((id) => urlById.get(id)).filter(Boolean) as string[];
  }

  const combined = [...new Set(nodeUrls)].join("\n");

  const target = c.req.query("target") || "base64";
  if (target === "base64") {
    return c.text(btoa(combined), 200, { "Content-Type": "text/plain; charset=utf-8" });
  }

  if (!c.env.MISUB_SUBCONVERTER_URL) {
    return c.text(
      `未配置 MISUB_SUBCONVERTER_URL，无法转换为 ${target} 格式。请配置一个subconverter服务地址，或直接使用不带 target 参数的通用(base64)格式。`,
      501
    );
  }
  const subconverterUrl = `${c.env.MISUB_SUBCONVERTER_URL}?target=${target}&url=${encodeURIComponent(
    `data:text/plain;base64,${btoa(combined)}`
  )}`;
  return c.redirect(subconverterUrl, 302);
});