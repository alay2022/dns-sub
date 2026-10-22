import type { Env } from "../types";
import { now } from "../db";
import { notifyDomainOwners } from "../notify/domainOwners";

/** 提前几天提醒（精确匹配剩余天数，避免同一个阈值重复发送） */
const REMINDER_DAYS = [20, 10, 5, 4, 3, 2, 1];

/** 数据新鲜度阈值：到期数据超过 3 天未刷新就视为陈旧，提醒前先实时复查 */
const STALE_SECONDS = 3 * 86400;
/** 单次 cron 最多实时复查的域名数（按数据最旧优先，余下的下个周期继续，防止打爆 RDAP） */
const MAX_RDAP_RECHECK = 8;

/**
 * 通过 rdap.org 引导服务查询域名在注册局的真实到期时间（返回 unix 秒）。
 * 查询失败或该后缀不支持 RDAP 时返回 null —— 调用方保持旧数据照常提醒（安全降级，宁勿漏报）。
 */
async function rdapExpiresAt(domain: string): Promise<number | null> {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { Accept: "application/rdap+json" },
    });
    if (!res.ok) return null;
    const data: any = await res.json();
    const exp = (data.events || []).find((e: any) => e.eventAction === "expiration");
    if (!exp?.eventDate) return null;
    const t = Math.floor(new Date(exp.eventDate).getTime() / 1000);
    return Number.isFinite(t) ? t : null;
  } catch {
    return null;
  }
}

/**
 * 提醒前的数据新鲜度防护：
 * 20 天提醒窗口内、且 whois_checked_at 超过 3 天（或从未查询过）的域名，
 * 先实时复查注册局 RDAP。若到期时间已变化（典型场景：用户已续费，
 * 但上游 whois/引导缓存仍旧值），先更新数据库再进入下方提醒判断，
 * 避免"已续费还收到到期通知"的误报（即 ztvps.net 这次的案例）。
 */
async function refreshStaleExpiries(env: Env, ts: number) {
  const { results: stale } = await env.DB.prepare(
    `SELECT id, domain_name, whois_expires_at, whois_checked_at FROM domains
     WHERE whois_expires_at IS NOT NULL
       AND whois_expires_at >= ?1 AND whois_expires_at < ?2
       AND (whois_checked_at IS NULL OR whois_checked_at < ?3)
     ORDER BY whois_checked_at IS NULL DESC, whois_checked_at ASC
     LIMIT ?4`
  )
    .bind(ts, ts + 20 * 86400, ts - STALE_SECONDS, MAX_RDAP_RECHECK)
    .all<{ id: number; domain_name: string; whois_expires_at: number; whois_checked_at: number | null }>();

  for (const d of stale) {
    const fresh = await rdapExpiresAt(d.domain_name);
    if (fresh === null) continue; // RDAP 不可用：保持旧数据，提醒照发

    if (fresh !== d.whois_expires_at) {
      await env.DB.prepare(`UPDATE domains SET whois_expires_at = ?1, whois_checked_at = ?2 WHERE id = ?3`)
        .bind(fresh, ts, d.id)
        .run();
    } else {
      // 数据没变也顺手刷新 checked_at，避免同一个域名天天被复查
      await env.DB.prepare(`UPDATE domains SET whois_checked_at = ?1 WHERE id = ?2`)
        .bind(ts, d.id)
        .run();
    }
  }
}

export async function handleExpiryReminders(env: Env) {
  const ts = now();

  // 【防误报】进入提醒判断前，先刷新窗口内的陈旧到期数据
  await refreshStaleExpiries(env, ts);

  const daysToRange = (days: number) => ({ start: ts + (days - 1) * 86400, end: ts + days * 86400 });

  for (const days of REMINDER_DAYS) {
    const { start, end } = daysToRange(days);

    // 域名注册到期提醒
    const { results: domains } = await env.DB.prepare(
      `SELECT id, domain_name, whois_expires_at, whois_checked_at FROM domains WHERE whois_expires_at >= ? AND whois_expires_at < ?`
    )
      .bind(start, end)
      .all<{ id: number; domain_name: string; whois_expires_at: number; whois_checked_at: number | null }>();

    for (const d of domains) {
      const checked = d.whois_checked_at ? new Date(d.whois_checked_at * 1000).toLocaleDateString() : "未知";
      await notifyDomainOwners(env, d.id, {
        title: `域名到期提醒：还剩${days}天`,
        content: `域名 ${d.domain_name} 将在 ${days} 天后（${new Date(d.whois_expires_at * 1000).toLocaleDateString()}）到期，请及时续费，避免域名被释放。（到期数据查询于 ${checked}，如已续费请在域名列表点击「查询到期」刷新）`,
      });
    }

    // SSL证书到期提醒（正常情况下20天内会被GitHub Actions自动续签，这里作为兜底提醒，
    // 万一自动续签失败或关闭了自动续签，也能及时知道）
    const { results: certs } = await env.DB.prepare(
      `SELECT sc.id, sc.common_name, sc.expires_at, sc.domain_id, sc.auto_renew FROM ssl_certs sc
       WHERE sc.status = 'issued' AND sc.expires_at >= ? AND sc.expires_at < ?`
    )
      .bind(start, end)
      .all<{ id: number; common_name: string; expires_at: number; domain_id: number; auto_renew: number }>();

    for (const cert of certs) {
      await notifyDomainOwners(env, cert.domain_id, {
        title: `SSL证书到期提醒：还剩${days}天`,
        content: `证书 ${cert.common_name} 将在 ${days} 天后（${new Date(cert.expires_at * 1000).toLocaleDateString()}）到期。${
          cert.auto_renew ? "已开启自动续签，正常情况下会在到期前自动处理，这条提醒是兜底通知。" : "该证书未开启自动续签，请手动续签。"
        }`,
      });
    }
  }
}