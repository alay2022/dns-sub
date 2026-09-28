import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { requireAuth, requireDomainPerm } from "../middleware/auth";
import { getDomainById, now, insertAuditLog } from "../db";
import { triggerGithubWorkflow } from "../github";

export const sslRoutes = new Hono<{ Bindings: Env }>();
sslRoutes.use("*", requireAuth);

/** 最小 zip 打包（store 模式，无压缩）：files = [{name, data(Uint8Array)}]，标准工具均可解压 */
function makeZip(files: { name: string; data: Uint8Array }[]): Uint8Array {
  const enc = new TextEncoder();
  const chunks: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const u32 = (v: number) => new Uint8Array([v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >>> 24) & 255]);
  const u16 = (v: number) => new Uint8Array([v & 255, (v >> 8) & 255]);
  const crc32 = (buf: Uint8Array) => {
    let c = ~0;
    for (let i = 0; i < buf.length; i++) {
      c ^= buf[i];
      for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (0xEDB88320 & -(c & 1));
    }
    return ~c >>> 0;
  };

  for (const f of files) {
    const nameB = enc.encode(f.name);
    const crc = crc32(f.data);
    const local = new Uint8Array(30 + nameB.length);
    local.set(u32(0x04034b50), 0); local.set(u16(20), 4); local.set(u16(0x0800), 6);
    local.set(u16(0), 8); local.set(u16(0), 10); local.set(u16(0), 12);
    local.set(u32(crc), 14); local.set(u32(f.data.length), 18); local.set(u32(f.data.length), 22);
    local.set(u16(nameB.length), 26); local.set(u16(0), 28);
    local.set(nameB, 30);
    chunks.push(local, f.data);

    const cen = new Uint8Array(46 + nameB.length);
    cen.set(u32(0x02014b50), 0); cen.set(u16(20), 4); cen.set(u16(20), 6);
    cen.set(u16(0x0800), 8); cen.set(u16(0), 10); cen.set(u16(0), 12); cen.set(u16(0), 14);
    cen.set(u32(crc), 16); cen.set(u32(f.data.length), 20); cen.set(u32(f.data.length), 24);
    cen.set(u16(nameB.length), 28); cen.set(u16(0), 30); cen.set(u16(0), 32);
    cen.set(u16(0), 34); cen.set(u16(0), 36); cen.set(u32(0), 38);
    cen.set(u32(offset), 42); cen.set(nameB, 46);
    central.push(cen);
    offset += local.length + f.data.length;
  }
  const cenSize = central.reduce((s, c) => s + c.length, 0);
  const end = new Uint8Array(22);
  end.set(u32(0x06054b50), 0); end.set(u16(0), 4); end.set(u16(0), 6);
  end.set(u16(files.length), 8); end.set(u16(files.length), 10);
  end.set(u32(cenSize), 12); end.set(u32(offset), 16); end.set(u16(0), 20);
  return new Uint8Array([...chunks.flat(), ...central.flat(), ...end]);
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