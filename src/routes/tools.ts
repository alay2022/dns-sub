import { Hono } from "hono";
import type { Env } from "../types";
import { requireAuth } from "../middleware/auth";
import { lookupWhois } from "../utils/whois";

export const toolsRoutes = new Hono<{ Bindings: Env }>();
toolsRoutes.use("*", requireAuth);

/**
 * DNS 查询：GET /api/tools/dns-lookup?domain=example.com&type=A
 * Cloudflare DoH（免费无需Key），服务端发起避免浏览器 CORS。
 */
toolsRoutes.get("/dns-lookup", async (c) => {
  const domain = (c.req.query("domain") || "").trim();
  const type = (c.req.query("type") || "A").toUpperCase();
  if (!domain) return c.json({ error: "缺少 domain 参数" }, 400);
  const allowed = ["A", "AAAA", "CNAME", "TXT", "MX", "NS"];
  if (!allowed.includes(type)) return c.json({ error: "不支持的记录类型" }, 400);

  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
      { headers: { accept: "application/dns-json" } }
    );
    if (!res.ok) return c.json({ error: `DoH 查询失败 (HTTP ${res.status})` }, 502);
    const data = await res.json() as any;
    return c.json({
      domain, type,
      status: data.Status ?? -1,
      answers: (data.Answer || []).map((a: any) => ({ name: a.name, type: a.type, ttl: a.TTL, data: a.data })),
    });
  } catch (e: any) {
    return c.json({ error: e.message || "查询失败" }, 502);
  }
});

/** Whois 查询：GET /api/tools/whois?domain=xxx（复用 RDAP 实现） */
toolsRoutes.get("/whois", async (c) => {
  const domain = (c.req.query("domain") || "").trim();
  if (!domain) return c.json({ error: "缺少 domain 参数" }, 400);
  try {
    return c.json((await lookupWhois(domain)) ?? {});
  } catch (e: any) {
    return c.json({ error: e.message || "Whois 查询失败" }, 502);
  }
});

/** 证书透明度：GET /api/tools/cert-check?domain=xxx（crt.sh，最近20条去重） */
toolsRoutes.get("/cert-check", async (c) => {
  const domain = (c.req.query("domain") || "").trim();
  if (!domain) return c.json({ error: "缺少 domain 参数" }, 400);
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      { headers: { "User-Agent": "dns-sub-worker" } });
    if (!res.ok) return c.json({ error: `crt.sh 查询失败 (HTTP ${res.status})` }, 502);
    const text = await res.text();
    let data: any[];
    try { data = JSON.parse(text); }
    catch { return c.json({ error: "crt.sh 返回非JSON（可能被限流），请稍后重试" }, 502); }
    if (!Array.isArray(data)) return c.json({ certs: [] });

    const seen = new Set<string>();
    const certs = data
      .sort((a, b) => new Date(b.entry_timestamp).getTime() - new Date(a.entry_timestamp).getTime())
      .filter((r) => {
        const k = `${r.common_name}|${r.not_before}`;
        if (seen.has(k)) return false;
        seen.add(k); return true;
      })
      .slice(0, 20)
      .map((r) => ({
        commonName: r.common_name,
        issuer: r.issuer_name,
        notBefore: r.not_before,
        notAfter: r.not_after,
      }));
    return c.json({ certs });
  } catch (e: any) {
    return c.json({ error: e.message || "查询失败" }, 502);
  }
});

/** base64url（供 subconverter 的 url 参数） */
function toBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * 订阅转换：POST /api/tools/sub-convert  body { target, nodesText }
 * 服务端调用公共 subconverter（dler.io 免费公益实例，无需任何配置），
 * 规避浏览器 CORS。target：clash / surge / v2ray / mixed。
 */
toolsRoutes.post("/sub-convert", async (c) => {
  const { target, nodesText } = await c.req.json<{ target: string; nodesText: string }>();
  if (!nodesText || !nodesText.trim()) return c.json({ error: "请粘贴节点或分享链接" }, 400);
  const allowedTargets = ["clash", "surge", "v2ray", "mixed"];
  const t = allowedTargets.includes(target) ? target : "clash";

  const url = `https://api.dler.io/sub?target=${t}&url=${encodeURIComponent(toBase64Url(nodesText.trim()))}&insert=false`;
  try {
    const res = await fetch(url, { headers: { "User-Agent": "dns-sub-worker" } });
    if (!res.ok) return c.json({ error: `转换服务返回 HTTP ${res.status}` }, 502);
    const text = await res.text();
    if (!text.trim()) return c.json({ error: "转换服务返回了空结果，请检查节点链接格式" }, 502);
    return c.json({ ok: true, target: t, text: text.slice(0, 500000) });
  } catch (e: any) {
    return c.json({ error: e.message || "转换失败" }, 502);
  }
});