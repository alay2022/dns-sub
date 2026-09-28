import type { DnsDomain, DnsRecord } from "../types";
import type { DnsProvider, ProviderCredentials } from "./interface";
import { safeJson } from "../utils/http";

const API = "https://api.cloudflare.com/client/v4";

/**
 * Cloudflare 凭据支持两种鉴权方式，二选一：
 * 1) 新版 API Token（推荐）: { apiToken: string }
 * 2) 老版 Global API Key（在 Cloudflare 后台"我的个人资料 > API令牌 > 全局API密钥"里查看，
 *    必须搭配注册邮箱一起使用）: { email: string, apiKey: string }
 */
export class CloudflareProvider implements DnsProvider {
  readonly type = "cloudflare";
  private authHeaders: Record<string, string>;

  constructor(creds: ProviderCredentials) {
    if (creds.apiToken) {
      this.authHeaders = { Authorization: `Bearer ${creds.apiToken}` };
    } else if (creds.email && creds.apiKey) {
      this.authHeaders = { "X-Auth-Email": creds.email, "X-Auth-Key": creds.apiKey };
    } else {
      throw new Error("Cloudflare凭据不完整：请提供 apiToken，或同时提供 email + apiKey（Global API Key）");
    }
  }

  private async req(path: string, init: RequestInit = {}) {
    const res = await fetch(`${API}${path}`, {
      ...init,
      headers: {
        ...this.authHeaders,
        "Content-Type": "application/json",
        ...(init.headers || {}),
      },
    });
    const data = await safeJson(res, "Cloudflare");
    if (!data.success) {
      throw new Error(`Cloudflare API错误(HTTP ${res.status}): ${JSON.stringify(data.errors)}`);
    }
    return data;
  }

  private async getZoneId(domain: string): Promise<string> {
    const data = await this.req(`/zones?name=${encodeURIComponent(domain)}`);
    if (!data.result?.length) throw new Error(`未找到域名 ${domain} 对应的 Zone`);
    return data.result[0].id;
  }

  async listDomains(): Promise<DnsDomain[]> {
    const data = await this.req(`/zones?per_page=50`);
    return (data.result as any[]).map((z) => ({ domainName: z.name, status: z.status }));
  }

  async listRecords(domain: string): Promise<DnsRecord[]> {
    const zoneId = await this.getZoneId(domain);
    const data = await this.req(`/zones/${zoneId}/dns_records?per_page=100`);
    return (data.result as any[]).map((r) => ({
      id: r.id,
      rr: r.name === domain ? "@" : r.name.replace(`.${domain}`, ""),
      type: r.type,
      value: r.content,
      ttl: r.ttl,
      priority: r.priority,
      proxied: !!r.proxied,
    }));
  }

  async createRecord(domain: string, record: Omit<DnsRecord, "id">): Promise<string> {
    const zoneId = await this.getZoneId(domain);
    const name = record.rr === "@" ? domain : `${record.rr}.${domain}`;
    const data = await this.req(`/zones/${zoneId}/dns_records`, {
      method: "POST",
      body: JSON.stringify({
        type: record.type,
        name,
        content: record.value,
        ttl: record.proxied ? 1 : record.ttl || 1, // 开启代理时TTL必须为Automatic(1)
        priority: record.priority,
        proxied: !!record.proxied,
	comment: record.remark || undefined,   // ← 加这行
      }),
    });
    return data.result.id;
  }

  async updateRecord(domain: string, recordId: string, record: Omit<DnsRecord, "id">): Promise<void> {
    const zoneId = await this.getZoneId(domain);
    const name = record.rr === "@" ? domain : `${record.rr}.${domain}`;
    await this.req(`/zones/${zoneId}/dns_records/${recordId}`, {
      method: "PUT",
      body: JSON.stringify({
        type: record.type,
        name,
        content: record.value,
        ttl: record.proxied ? 1 : record.ttl || 1,
        priority: record.priority,
        proxied: !!record.proxied,
	comment: record.remark || undefined,   // ← 加这行
      }),
    });
  }

  async deleteRecord(domain: string, recordId: string): Promise<void> {
    const zoneId = await this.getZoneId(domain);
    await this.req(`/zones/${zoneId}/dns_records/${recordId}`, { method: "DELETE" });
  }
}
