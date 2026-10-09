import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { requireAuth, requireAdmin } from "../middleware/auth";
import { now, insertAuditLog } from "../db";

export const backupRoutes = new Hono<{ Bindings: Env }>();
backupRoutes.use("*", requireAuth, requireAdmin);

/* =====================================================================
   数据备份 / 还原
   · 全量表（BACKUP_TABLES）：全量备份、还原时全表覆盖
   · 日志表（LOG_TABLES）：仅备份最新 50 条，还原时恢复这 50 条
   · 不包含：api_keys（例外——包含）、排除表：无（audit/access 已纳入限量）
   · 还原顺序：清场按依赖倒序（子表先删），插入按依赖正序（父表先插）
   ===================================================================== */

/** 全量备份表（依赖正序：父表在前） */
const BACKUP_TABLES = [
  "users",
  "dns_providers",
  "domains",
  "user_domain_perms",
  "ssl_certs",
  "record_remarks",
  "user_favorites",
  "notify_channels",
  "api_keys",
  "oauth_provider_configs",
  "oauth_accounts",
  "misub_nodes",
  "misub_profiles",
  "misub_settings",
  "notices",
];

/** 日志表：仅备份最新 50 条 */
const LOG_TABLES = [
  "audit_logs",
  "misub_access_log",
];

/** 还原涉及的全部表（全量 + 日志） */
const RESTORE_TABLES = [...BACKUP_TABLES, ...LOG_TABLES];

const APP_VERSION = "dns-sub-1.0";

/** SQL 值转义（供 SQL 文本备份） */
function sqlEscape(v: any): string {
  if (v === null || v === undefined) return "NULL";
  if (typeof v === "number") return String(v);
  return `'${String(v).replace(/'/g, "''")}'`;
}

/** 备份：全库 JSON（用于系统内还原；日志表限最新50条） */
backupRoutes.get("/export/json", async (c) => {
  const user = c.get("user") as JwtPayload;
  const data: Record<string, any[]> = {};

  for (const table of BACKUP_TABLES) {
    const { results } = await c.env.DB.prepare(`SELECT * FROM ${table}`).all();
    data[table] = results;
  }
  for (const table of LOG_TABLES) {
    const { results } = await c.env.DB.prepare(`SELECT * FROM ${table} ORDER BY id DESC LIMIT 50`).all();
    data[table] = results;
  }

  const payload = {
    meta: {
      app: APP_VERSION,
      version: 1,
      created_at: new Date().toISOString(),
      created_by: user.username,
      tables: BACKUP_TABLES,        /* 全量覆盖清单 */
      log_tables: LOG_TABLES,       /* 日志表清单（限量恢复） */
    },
    tables: data,
  };
  return new Response(JSON.stringify(payload, null, 2), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Disposition": `attachment; filename="dns-sub-backup-${new Date().toISOString().slice(0,10)}.json"`,
      "Access-Control-Allow-Origin": "*",
    },
  });
});

/** 备份：全库 SQL（人可读，供查看/手动重建参考；系统内还原请用 JSON） */
backupRoutes.get("/export/sql", async (c) => {
  const lines: string[] = [
    `-- DNS-SUB 全库备份`,
    `-- 生成时间: ${new Date().toISOString()}`,
    `-- 注意: 系统内还原请使用 JSON 备份；本文件供人工查看/重建参考`,
    `BEGIN TRANSACTION;`,
  ];

  for (const table of BACKUP_TABLES) {
    const { results } = await c.env.DB.prepare(`SELECT * FROM ${table}`).all();
    lines.push(`\n-- ===== ${table} (${results.length} rows) =====`);
    lines.push(`DELETE FROM ${table};`);
    for (const row of results as any[]) {
      const cols = Object.keys(row);
      const vals = cols.map(c => sqlEscape(row[c]));
      lines.push(`INSERT INTO ${table} (${cols.join(", ")}) VALUES (${vals.join(", ")});`);
    }
  }
  for (const table of LOG_TABLES) {
    const { results } = await c.env.DB.prepare(`SELECT * FROM ${table} ORDER BY id DESC LIMIT 50`).all();
    lines.push(`\n-- ===== ${table} (latest 50 rows) =====`);
    lines.push(`DELETE FROM ${table};`);
    for (const row of results as any[]) {
      const cols = Object.keys(row);
      const vals = cols.map(c => sqlEscape(row[c]));
      lines.push(`INSERT INTO ${table} (${cols.join(", ")}) VALUES (${vals.join(", ")});`);
    }
  }
  lines.push(`\nCOMMIT;`);

  return new Response(lines.join("\n"), {
    headers: {
      "Content-Type": "application/sql; charset=utf-8",
      "Content-Disposition": `attachment; filename="dns-sub-backup-${new Date().toISOString().slice(0,10)}.sql"`,
      "Access-Control-Allow-Origin": "*",
    },
  });
});

/** 通用单表插入（列过滤 + 逐条执行 + 坏行收集） */
async function insertTableRows(
  c: any,
  table: string,
  rows: any[]
): Promise<{ ok: number; fail: number; firstError: string }> {
  const cols = Object.keys(rows[0]);
  const colInfo = await c.env.DB.prepare(`PRAGMA table_info(${table})`).all();
  const validCols = colInfo.results.map((r: any) => r.name);
  const insertCols = cols.filter(c => validCols.includes(c));
  if (!insertCols.length) return { ok: 0, fail: rows.length, firstError: "无可插入列" };

  let ok = 0, fail = 0, firstError = "";
  for (let idx = 0; idx < rows.length; idx++) {
    try {
      await c.env.DB.prepare(
        `INSERT INTO ${table} (${insertCols.join(", ")}) VALUES (${insertCols.map(() => "?").join(", ")})`
      ).bind(...insertCols.map(col => rows[idx][col] ?? null)).run();
      ok++;
    } catch (e: any) {
      fail++;
      if (!firstError) firstError = `#${idx}: ${e.message}`;
    }
  }
  return { ok, fail, firstError };
}

/** 还原：POST /api/backup/restore  header X-Restore-Confirm: RESTORE  body = 备份 JSON
 *  全表覆盖：先倒序清场 → 全量表正序逐条插入 → 日志表恢复（限50条内） */
backupRoutes.post("/restore", async (c) => {
  const user = c.get("user") as JwtPayload;

  const confirm = c.req.header("X-Restore-Confirm");
  if (confirm !== "RESTORE") return c.json({ error: "缺少确认码" }, 400);

  let payload: any;
  try {
    payload = await c.req.json();
  } catch {
    return c.json({ error: "不是有效的 JSON 文件" }, 400);
  }

  if (!payload || payload.meta?.app !== APP_VERSION || !payload.tables) {
    return c.json({ error: "备份文件格式不正确（meta.app 不匹配或缺少 tables）" }, 400);
  }
  const backupTables = payload.meta.tables || [];
  if (!Array.isArray(backupTables) || !backupTables.length) {
    return c.json({ error: "备份文件缺少表清单" }, 400);
  }

  const ts = now();
  const summary: Record<string, number> = {};
  const errors: string[] = [];

  /* 延迟外键检查（兜底；主修复是依赖倒序清场） */
  try { await c.env.DB.prepare("PRAGMA defer_foreign_keys = ON").run(); } catch(_) {}

  /* ===== 第一步：清场（RESTORE_TABLES 全部，依赖倒序：子表先删） ===== */
  const DELETE_ORDER = [...RESTORE_TABLES].reverse();
  for (const table of DELETE_ORDER) {
    try { await c.env.DB.prepare(`DELETE FROM ${table}`).run(); }
    catch (e: any) { errors.push(`清场 ${table}: ${e.message}`); }
  }

  /* ===== 第二步：全量表按依赖正序逐条插入 ===== */
  for (const table of BACKUP_TABLES) {
    const rows = payload.tables[table];
    if (!Array.isArray(rows)) { summary[table] = 0; continue; }
    if (!rows.length) { summary[table] = 0; continue; }

    try {
      const r = await insertTableRows(c, table, rows);
      summary[table] = r.ok;
      if (r.fail) errors.push(`${table}: ${r.fail} 行失败（首条：${r.firstError}）`);
    } catch (e: any) {
      errors.push(`${table}: ${e.message}`);
      summary[table] = -1;
    }
  }

  /* ===== 第三步：日志表恢复（只取备份内最新50条） ===== */
  for (const table of LOG_TABLES) {
    const rows = payload.tables[table];
    if (!Array.isArray(rows)) { summary[table] = 0; continue; }
    if (!rows.length) { summary[table] = 0; continue; }

    try {
      const latest = rows.slice(0, 50);
      const r = await insertTableRows(c, table, latest);
      summary[table] = r.ok;
      if (r.fail) errors.push(`${table}: ${r.fail} 行失败（首条：${r.firstError}）`);
    } catch (e: any) {
      errors.push(`${table}: ${e.message}`);
      summary[table] = -1;
    }
  }

  await insertAuditLog(c.env, user.uid, "restore_backup", JSON.stringify(summary));
  return c.json({ ok: errors.length === 0, summary, errors, restored_at: ts });
});