import type { DnsProvider } from "../providers/interface";
import { generateAcmeAccountKey, importAccountKeyFromPkcs8B64, exportAccountKeyPkcs8B64, jwkThumbprint, signAcmeJws, signEabJws } from "./jws";
import { generateKeyPairAndCsr } from "./csr";
import { safeJson } from "../utils/http";

const LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory";
// 备选：Buypass Go SSL，免费、兼容ACMEv2、无需EAB，且不在Cloudflare网络上，
// 如果 Let's Encrypt 因 Cloudflare Workers 平台已知的525问题无法访问，可切换到这个：
// const LETSENCRYPT_DIRECTORY = "https://api.buypass.com/acme/directory";
// 测试环境（不消耗生产速率限制，调试时建议先用这个）：
// const LETSENCRYPT_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory";

interface AcmeDirectory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  revokeCert: string;
  keyChange: string;
}

export interface IssueCertResult {
  certPem: string;
  keyPem: string;
  expiresAt: number;
}

export class AcmeClient {
  private directory!: AcmeDirectory;
  private nonce: string | null = null;
  private accountKey!: CryptoKey;
  private accountJwk!: { kty: "EC"; crv: "P-256"; x: string; y: string };
  private kid: string | null = null;

  private constructor(private email: string) {}

  static async create(email: string, existingAccountKeyPkcs8B64?: string, directoryUrl: string = LETSENCRYPT_DIRECTORY): Promise<AcmeClient> {
    const client = new AcmeClient(email);
    const dirRes = await fetch(directoryUrl);
    client.directory = await safeJson(dirRes, "ACME目录");

    if (existingAccountKeyPkcs8B64) {
      client.accountKey = await importAccountKeyFromPkcs8B64(existingAccountKeyPkcs8B64);
      // 注意：已有账户密钥时，publicJwk 无法从私钥反推导出（WebCrypto不支持从PKCS8导出公钥），
      // 因此复用账户时必须同时保存 kid（账户URL），由调用方通过 setKid() 传入。
    } else {
      const { privateKey, publicJwk } = await generateAcmeAccountKey();
      client.accountKey = privateKey;
      client.accountJwk = publicJwk;
    }
    return client;
  }

  setKid(kid: string) {
    this.kid = kid;
  }

  async exportAccountKey(): Promise<string> {
    return exportAccountKeyPkcs8B64(this.accountKey);
  }

  private async fetchNonce(): Promise<string> {
    if (this.nonce) {
      const n = this.nonce;
      this.nonce = null;
      return n;
    }
    const res = await fetch(this.directory.newNonce, { method: "HEAD" });
    return res.headers.get("Replay-Nonce")!;
  }

  private async post(url: string, payload: Record<string, unknown> | "") {
    const nonce = await this.fetchNonce();
    const jws = await signAcmeJws({
      privateKey: this.accountKey,
      payload,
      url,
      nonce,
      jwk: this.kid ? undefined : this.accountJwk,
      kid: this.kid ?? undefined,
    });
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/jose+json" },
      body: JSON.stringify(jws),
    });
    this.nonce = res.headers.get("Replay-Nonce");
    return res;
  }

  /**
   * 注册或获取已有账户，返回账户URL（kid）。
   * eab: ZeroSSL / Google Trust Services 等要求 External Account Binding 的CA需要传入
   *      { kid, hmacKey }（从对应CA的开发者后台获取，一次生成永久可复用）。
   */
  async ensureAccount(eab?: { kid: string; hmacKey: string }): Promise<string> {
    const payload: Record<string, unknown> = {
      termsOfServiceAgreed: true,
      contact: [`mailto:${this.email}`],
    };
    if (eab) {
      payload.externalAccountBinding = await signEabJws({
        accountJwk: this.accountJwk,
        eabKid: eab.kid,
        eabHmacKeyB64Url: eab.hmacKey,
        url: this.directory.newAccount,
      });
    }
    const res = await this.post(this.directory.newAccount, payload);
    if (!res.ok && res.status !== 200) {
      throw new Error(`ACME账户注册失败: ${res.status} ${await res.text()}`);
    }
    const kid = res.headers.get("Location")!;
    this.kid = kid;
    return kid;
  }

  /**
   * 申请证书完整流程：newOrder -> DNS-01验证(调用传入的dnsProvider写TXT) -> finalize -> 下载证书
   */
  async issueCertificate(opts: {
    commonName: string;
    sans: string[];
    dnsProvider: DnsProvider;
    /** 从FQDN反推出该 provider 下的根域名，用于创建 _acme-challenge TXT 记录 */
    rootDomain: string;
    onLog?: (msg: string) => void;
  }): Promise<IssueCertResult> {
    const log = opts.onLog ?? (() => {});
    const allDomains = [...new Set([opts.commonName, ...opts.sans])];

    // 1. 创建订单
    const orderRes = await this.post(this.directory.newOrder, {
      identifiers: allDomains.map((d) => ({ type: "dns", value: d })),
    });
    if (!orderRes.ok) throw new Error(`创建ACME订单失败: ${await orderRes.text()}`);
    const order = await safeJson(orderRes, "ACME newOrder");
    const orderUrl = orderRes.headers.get("Location")!;

    // 2. 完成 DNS-01 挑战（两阶段：先写完所有 TXT → 统一等待传播 → 统一通知验证 → 统一轮询结果）
    //    不能"写一个验一个"：CN 和通配符共用 _acme-challenge.<根域> 同名TXT，
    //    串行验证时第一条产生的 DNS 缓存（TTL 内）会让 Let's Encrypt 的 secondary validation
    //    部分视角看不到新写入的第二条 TXT，误判 unauthorized（536677.xyz 失败的根因）
    const createdTxtRecordIds: string[] = [];
    try {
      const tasks: { authzUrl: string; challengeUrl: string; fqdn: string; sub: string; txtValue: string }[] = [];

      // 阶段一：为每个授权写入 TXT 记录（同名多条共存，Cloudflare 等主流平台均支持）
      for (const authzUrl of order.authorizations as string[]) {
        const authzRes = await this.post(authzUrl, "");
        const authz = await safeJson(authzRes, `ACME authorization ${authzUrl}`);
        const dnsChallenge = authz.challenges.find((c: any) => c.type === "dns-01");
        if (!dnsChallenge) throw new Error(`域名 ${authz.identifier.value} 不支持 DNS-01 验证`);

        const keyAuthorization = `${dnsChallenge.token}.${await jwkThumbprint(this.accountJwk)}`;
        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(keyAuthorization));
        const txtValue = b64urlDigest(digest);

        // RFC 8555：通配符授权的 identifier.value 不带 *.，TXT 统一放 _acme-challenge.<根域>；
        // 先去掉可能的星号前缀，防御个别 CA 返回带 *. 的 value
        const fqdn = String(authz.identifier.value).replace(/^\*\./, "");
        const sub = fqdn === opts.rootDomain ? "_acme-challenge" : `_acme-challenge.${fqdn.replace(`.${opts.rootDomain}`, "")}`;
        log(`写入 TXT 记录 ${sub}.${opts.rootDomain} = ${txtValue}`);
        const recordId = await opts.dnsProvider.createRecord(opts.rootDomain, {
          rr: sub,
          type: "TXT",
          value: `"${txtValue}"`,
          ttl: 600, // 部分平台（如阿里云）要求TTL最小值600秒，这里统一用600确保兼容
        });
        createdTxtRecordIds.push(recordId);
        tasks.push({ authzUrl, challengeUrl: dnsChallenge.url, fqdn, sub, txtValue });
      }

      // 阶段二：等待全部 TXT 在公共 DoH 可见——之后任何视角首次查询都能看到完整记录
      for (const t of tasks) {
        await pollDnsPropagation(t.sub, opts.rootDomain, t.txtValue);
      }
      // 再固定缓冲 30 秒，覆盖权威多节点同步与递归缓存差异（本脚本只在 GitHub Actions 运行，无 CPU 压力）
      await sleep(30000);

      // 阶段三：统一通知 ACME 验证
      for (const t of tasks) {
        log(`通知 ACME 服务器验证 ${t.fqdn}`);
        await this.post(t.challengeUrl, {});
      }

      // 阶段四：统一轮询验证结果
      for (const t of tasks) {
        await this.pollUntil(t.authzUrl, (a) => a.status === "valid" || a.status === "invalid", 20, 3000);
        const finalAuthz = await safeJson(await this.post(t.authzUrl, ""), `ACME authorization ${t.authzUrl}`);
        if ((finalAuthz as any).status !== "valid") {
          throw new Error(`域名 ${t.fqdn} DNS-01 验证失败: ${JSON.stringify(finalAuthz)}`);
        }
      }

      // 3. 生成CSR并finalize订单
      const { csrDerB64Url, certKeyPkcs8Pem } = await generateKeyPairAndCsr(opts.commonName, opts.sans);
      const finalizeRes = await this.post(order.finalize, { csr: csrDerB64Url });
      if (!finalizeRes.ok) throw new Error(`finalize订单失败: ${await finalizeRes.text()}`);

      // 4. 轮询订单直到签发完成
      const finalOrder = await this.pollUntil(orderUrl, (o) => o.status === "valid" || o.status === "invalid", 20, 3000);
      if (finalOrder.status !== "valid") throw new Error(`证书签发失败: ${JSON.stringify(finalOrder)}`);

      const certRes = await this.post(finalOrder.certificate, "");
      const certPem = await certRes.text();

      const expiresAt = parseCertExpiry(certPem);

      return { certPem, keyPem: certKeyPkcs8Pem, expiresAt };
    } finally {
      // 5. 清理 DNS-01 验证用的临时 TXT 记录
      for (const id of createdTxtRecordIds) {
        try {
          await opts.dnsProvider.deleteRecord(opts.rootDomain, id);
        } catch {
          /* 清理失败不影响主流程，留给下次续签覆盖 */
        }
      }
    }
  }

  private async pollUntil(url: string, done: (obj: any) => boolean, maxTries: number, intervalMs: number): Promise<any> {
    for (let i = 0; i < maxTries; i++) {
      const res = await this.post(url, "");
      const obj = await safeJson(res, `ACME poll ${url}`);
      if (done(obj)) return obj;
      await sleep(intervalMs);
    }
    throw new Error(`轮询 ${url} 超时`);
  }
}

function b64urlDigest(digest: ArrayBuffer): string {
  const bytes = new Uint8Array(digest);
  let str = "";
  bytes.forEach((b) => (str += String.fromCharCode(b)));
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** 通过公共DoH查询等待TXT记录在权威侧可见后再通知ACME（简化实现，避免过早验证失败） */
async function pollDnsPropagation(sub: string, rootDomain: string, expectedValue: string, maxTries = 10) {
  const fqdn = `${sub}.${rootDomain}`;
  for (let i = 0; i < maxTries; i++) {
    try {
      const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${fqdn}&type=TXT`, {
        headers: { accept: "application/dns-json" },
      });
      const data = (await res.json()) as any;
      const found = (data.Answer || []).some((a: any) => a.data?.replace(/"/g, "") === expectedValue);
      if (found) return;
    } catch {
      /* 忽略单次查询失败，继续重试 */
    }
    await sleep(3000);
  }
  // 查询不到也继续走验证流程，交给 ACME 服务器自行重试机制兜底
}

/** 从证书PEM中粗略解析出失效时间：优先信任Let's Encrypt返回顺序，取第一张证书的 notAfter。
 *  这里用最简单的方式：交由部署环境用 openssl/结构化库二次核实；此实现返回90天后的估算值作为兜底。
 */
function parseCertExpiry(_certPem: string): number {
  // Let's Encrypt 证书有效期固定为90天，此处按签发时间+90天估算；
  // 生产环境建议在 routes/ssl.ts 中用 X.509 解析库精确读取 notAfter 字段。
  return Math.floor(Date.now() / 1000) + 90 * 24 * 3600;
}