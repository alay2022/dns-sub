import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { requireAuth, requireDomainPerm } from "../middleware/auth";
import { getDomainById, now, insertAuditLog } from "../db";
import { triggerGithubWorkflow } from "../github";

export const sslRoutes = new Hono<{ Bindings: Env }>();
sslRoutes.use("*", requireAuth);

/** 最小 zip 打包（store 模式）——已核对字段偏移 */
function makeZip(files: { name: string; data: Uint8Array }[]): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;

  const u16 = (v: number) => new Uint8Array([v & 0xff, (v >> 8) & 0xff]);
  const u32 = (v: number) => new Uint8Array([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]);
  const crc32 = (buf: Uint8Array) => {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      c ^= buf[i];
      for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1));
    }
    return (c ^ 0xffffffff) >>> 0;
  };

  for (const f of files) {
    const name = enc.encode(f.name);
    const crc = crc32(f.data);

    // Local File Header (30 + nameLen)
    const lh = new Uint8Array(30 + name.length);
    lh.set(u32(0x04034b50), 0);      // signature
    lh.set(u16(20), 4);              // version needed
    lh.set(u16(0x0800), 6);          // flags: UTF-8
    lh.set(u16(0), 8);               // method: store
    lh.set(u16(0), 10);              // time
    lh.set(u16(0x21), 12);           // date (1980-01-01)
    lh.set(u32(crc), 14);
    lh.set(u32(f.data.length), 18);  // compressed size
    lh.set(u32(f.data.length), 22);  // uncompressed size
    lh.set(u16(name.length), 26);
    lh.set(u16(0), 28);
    lh.set(name, 30);
    parts.push(lh, f.data);

    // Central Directory Entry (46 + nameLen)
    const ch = new Uint8Array(46 + name.length);
    ch.set(u32(0x02014b50), 0);
    ch.set(u16(20), 4);              // version made by
    ch.set(u16(20), 6);              // version needed
    ch.set(u16(0x0800), 8);          // flags: UTF-8（与 local 一致）
    ch.set(u16(0), 10);              // method: store
    ch.set(u16(0), 12);              // time
    ch.set(u16(0x21), 14);           // date
    ch.set(u32(crc), 16);
    ch.set(u32(f.data.length), 20);
    ch.set(u32(f.data.length), 24);
    ch.set(u16(name.length), 28);
    ch.set(u16(0), 30); ch.set(u16(0), 32); ch.set(u16(0), 34);
    ch.set(u16(0), 36);              // disk number
    ch.set(u16(0), 38);              // internal attrs
    ch.set(u32(0), 40);              // external attrs
    ch.set(u32(offset), 42);         // local header offset
    ch.set(name, 46);
    central.push(ch);

    offset += lh.length + f.data.length;
  }

  const centralSize = central.reduce((s, c) => s + c.length, 0);
  const cdStart = offset;
  const eocd = new Uint8Array(22);
  eocd.set(u32(0x06054b50), 0);
  eocd.set(u16(0), 4); eocd.set(u16(0), 6);
  eocd.set(u16(files.length), 8); eocd.set(u16(files.length), 10);
  eocd.set(u32(centralSize), 12);
  eocd.set(u32(cdStart), 16);      // central directory 起始 = 所有 local+data 之后
  eocd.set(u16(0), 20);

  const total = [...parts, ...central, eocd];
  const out = new Uint8Array(total.reduce((s, p) => s + p.length, 0));
  let pos = 0;
  for (const p of total) { out.set(p, pos); pos += p.length; }
  return out;
}

/**
 * 证书总览：GET /api/domains/certs 是全部域名的证书（管理员看全部，
 * 普通用户只看自己有权限的域名），供证书列表页默认展示全部、也支持上方下拉框按域名筛选。
 */
sslRoutes.get("/certs", async (c) => {
  const user = c.get("user") as JwtPayload;
  const scope =
    user.role === "admin"
      ? "1=1"
      : `sc.domain_id IN (SELECT domain_id FROM user_domain_perms WHERE user_id = ${user.uid})`;
  const { results } = await c.env.DB.prepare(
    `SELECT sc.*, d.domain_name FROM ssl_certs sc
     JOIN domains d ON d.id = sc.domain_id
     WHERE ${scope}
     ORDER BY sc.id DESC`
  ).all();
  return c.json(results);
});

/** 批量删除证书记录：body: { certIds: number[] }（只删本地数据库记录，不会去CA吊销证书） */
sslRoutes.post("/certs/batch-delete", async (c) => {
  const user = c.get("user") as JwtPayload;
  const { certIds } = await c.req.json<{ certIds: number[] }>();
  if (!Array.isArray(certIds) || !certIds.length) return c.json({ error: "参数不能为空" }, 400);
  const cleanIds = [...new Set(certIds)].filter(id => Number.isInteger(id));
  if (!cleanIds.length) return c.json({ error: "没有有效的证书ID" }, 400);

  if (user.role !== "admin") {
    const { results } = await c.env.DB.prepare(
      `SELECT sc.id FROM ssl_certs sc
       WHERE sc.id IN (${cleanIds.map(() => "?").join(",")})
       AND sc.domain_id NOT IN (SELECT domain_id FROM user_domain_perms WHERE user_id = ? AND perm = 'readwrite')`
    )
      .bind(...cleanIds, user.uid)
      .all();
    if (results.length) return c.json({ error: "存在无权限删除的证书" }, 403);
  }

  await c.env.DB.batch(cleanIds.map((id) => c.env.DB.prepare("DELETE FROM ssl_certs WHERE id = ?").bind(id)));
  await insertAuditLog(c.env, user.uid, "batch_delete_certs", cleanIds.join(","));
  return c.json({ ok: true, deleted: cleanIds.length });
});

sslRoutes.get("/:domainId/certs", requireDomainPerm(false), async (c) => {
  const domainId = Number(c.req.param("domainId"));
  const { results } = await c.env.DB.prepare("SELECT * FROM ssl_certs WHERE domain_id = ? ORDER BY id DESC")
    .bind(domainId)
    .all();
  return c.json(results);
});

/**
 * 申请证书：body: { commonName?, sans?: string[], autoRenew?: boolean }
 * commonName 留空或传 "@" 时默认为域名本身（根域名）。
 * 实际签发搬到 GitHub Actions，这里只插入 pending 记录并触发 issue-cert.yml。
 * 前端轮询 GET /:domainId/certs 获取最终状态（Actions 完成后回调 /api/ci/certs/:id/complete）。
 */
sslRoutes.post("/:domainId/certs", requireDomainPerm(true), async (c) => {
  const user = c.get("user") as JwtPayload;
  const domainId = Number(c.req.param("domainId"));
  const body = await c.req.json<{ commonName?: string; sans?: string[]; autoRenew?: boolean }>();

  const domain = (await getDomainById(c.env, domainId)) as any;
  if (!domain) return c.json({ error: "域名不存在" }, 404);

  const commonName = !body.commonName || body.commonName.trim() === "@" ? domain.domain_name : body.commonName.trim();
  const sans = body.sans || [];

  const ts = now();
  const insertRes = await c.env.DB.prepare(
    `INSERT INTO ssl_certs (domain_id, common_name, sans, ca, status, auto_renew, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?)`
  )
    .bind(domainId, commonName, JSON.stringify(sans), "letsencrypt", "pending", body.autoRenew === false ? 0 : 1, ts, ts)
    .run();
  const certId = insertRes.meta.last_row_id;

  try {
    await triggerGithubWorkflow(c.env, "issue-cert.yml", {
      domain_id: String(domainId),
      cert_id: String(certId),
      common_name: commonName,
      sans: sans.join(","),
      root_domain: domain.domain_name,
    });
    await insertAuditLog(c.env, user.uid, "trigger_issue_cert", `${domain.domain_name}(${commonName})`);
  } catch (e: any) {
    await c.env.DB.prepare("UPDATE ssl_certs SET status='failed', updated_at=? WHERE id=?").bind(now(), certId).run();
    return c.json({ ok: false, error: e.message }, 500);
  }

  return c.json({ ok: true, certId, status: "pending" });
});

/** 查看证书内容（JSON）：GET /:domainId/certs/:certId/view（供前端「查看」弹窗显示 PEM/KEY） */
sslRoutes.get("/:domainId/certs/:certId/view", requireDomainPerm(false), async (c) => {
  const certId = Number(c.req.param("certId"));
  const row = await c.env.DB.prepare("SELECT * FROM ssl_certs WHERE id = ?").bind(certId).first<any>();
  if (!row || row.status !== "issued") return c.json({ error: "证书不存在或尚未签发成功" }, 404);
  return c.json({ certPem: row.cert_pem, keyPem: row.key_pem, expiresAt: row.expires_at, issuer: row.issuer, issuedAt: row.issued_at });
});

/** 下载证书 zip（cert.pem + key.pem）：GET /:domainId/certs/:certId/download → application/zip */
sslRoutes.get("/:domainId/certs/:certId/download", requireDomainPerm(false), async (c) => {
  const certId = Number(c.req.param("certId"));
  const row = await c.env.DB.prepare("SELECT * FROM ssl_certs WHERE id = ?").bind(certId).first<any>();
  if (!row || row.status !== "issued" || !row.cert_pem || !row.key_pem)
    return c.json({ error: "证书不存在或尚未签发成功" }, 404);

  const enc = new TextEncoder();
  const zip = makeZip([
    { name: "cert.pem", data: enc.encode(row.cert_pem) },
    { name: "key.pem", data: enc.encode(row.key_pem) },
  ]);
  return new Response(zip, {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="cert-${row.common_name.replace(/\*/g, "_")}.zip"`,
      "Access-Control-Allow-Origin": "*",                    // ← 加这行
    },
  });
});

/** 续签：状态置回 pending 并触发 workflow，实际工作交给 GitHub Actions */
sslRoutes.post("/:domainId/certs/:certId/renew", requireDomainPerm(true), async (c) => {
  const user = c.get("user") as JwtPayload;
  const domainId = Number(c.req.param("domainId"));
  const certId = Number(c.req.param("certId"));
  const domain = (await getDomainById(c.env, domainId)) as any;
  const cert = await c.env.DB.prepare("SELECT * FROM ssl_certs WHERE id = ?").bind(certId).first<any>();
  if (!domain || !cert) return c.json({ error: "记录不存在" }, 404);

  await c.env.DB.prepare("UPDATE ssl_certs SET status='pending', updated_at=? WHERE id=?").bind(now(), certId).run();

  try {
    await triggerGithubWorkflow(c.env, "issue-cert.yml", {
      domain_id: String(domainId),
      cert_id: String(certId),
      common_name: cert.common_name,
      sans: JSON.parse(cert.sans || "[]").join(","),
      root_domain: domain.domain_name,
    });
    await insertAuditLog(c.env, user.uid, "trigger_renew_cert", `${domain.domain_name}(${cert.common_name})`);
  } catch (e: any) {
    await c.env.DB.prepare("UPDATE ssl_certs SET status='failed', updated_at=? WHERE id=?").bind(now(), certId).run();
    return c.json({ ok: false, error: e.message }, 500);
  }

  return c.json({ ok: true, status: "pending" });
});