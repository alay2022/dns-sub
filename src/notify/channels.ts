import { aesDecrypt } from "../utils/crypto";

export interface NotifyMessage {
  title: string;
  content: string; // 支持简单文本，部分渠道支持markdown
}

export type NotifyChannelType =
  | "email"
  | "wechat_mp"
  | "telegram"
  | "dingtalk"
  | "feishu"
  | "wecom"
  | "serverchan";

/**
 * 各渠道 config 字段约定：
 * - email:      { to: string }
 *               （Resend API Key / 发件人 已升级为系统级配置，
 *                 管理员在「系统设置 → 邮件通知」维护，存于 system_settings 表
 *                 —— Key 为 AES-GCM 加密存储，读取时解密，
 *                 渠道内只保留收件邮箱）
 * - wechat_mp:  { appId, appSecret, templateId, toOpenId }
 * - telegram:   { botToken, chatId }
 * - dingtalk:   { webhookUrl, secret? }
 * - feishu:     { webhookUrl }
 * - wecom:      { webhookUrl }
 * - serverchan: { sendKey }
 */

/** 读取系统级邮件配置（Resend Key / 发件人）；Key 是加密存储的，读取时解密 */
async function getSystemMailConfig(env: any): Promise<{ apiKey: string; from: string }> {
  const { results } = await env.DB.prepare(
    "SELECT key, value FROM system_settings WHERE key IN ('mail_api_key','mail_from')"
  ).all<{ key: string; value: string }>();
  const map = new Map(results.map((r: any) => [r.key, r.value]));

  let apiKey = map.get('mail_api_key') || '';
  if (apiKey) {
    try {
      apiKey = env?.ENCRYPT_KEY ? await aesDecrypt(apiKey, env.ENCRYPT_KEY) : apiKey;
    } catch {
      /* 解密失败时保留原值（可能是未加密的旧数据）——Resend 会报 invalid，可据此发现 */
    }
  }
  return { apiKey, from: map.get('mail_from') || '' };
}

export async function sendNotify(
  type: NotifyChannelType,
  config: Record<string, any>,
  msg: NotifyMessage,
  env?: any
): Promise<void> {
  switch (type) {
    case "email":
      return sendEmail(config, msg, env);
    case "wechat_mp":
      return sendWechatMp(config, msg);
    case "telegram":
      return sendTelegram(config, msg);
    case "dingtalk":
      return sendDingtalk(config, msg);
    case "feishu":
      return sendFeishu(config, msg);
    case "wecom":
      return sendWecom(config, msg);
    case "serverchan":
      return sendServerChan(config, msg);
    default:
      throw new Error(`不支持的通知渠道: ${type}`);
  }
}

/** 邮件：Key/发件人取自系统级配置（解密后），渠道 config 只需要 { to } */
async function sendEmail(config: any, msg: NotifyMessage, env?: any) {
  const sys = await getSystemMailConfig(env);
  if (!sys.apiKey) throw new Error("管理员尚未配置系统邮件服务（Resend API Key），邮件通知不可用");
  if (!config.to) throw new Error("邮件渠道缺少收件邮箱（to）");

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${sys.apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: sys.from || "DNS-SUB <noreply@resend.dev>",
      to: [config.to],
      subject: msg.title,
      text: msg.content,
    }),
  });
  if (!res.ok) throw new Error(`邮件发送失败: ${await res.text()}`);
}

async function sendWechatMp(config: any, msg: NotifyMessage) {
  const tokenRes = await fetch(
    `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${config.appId}&secret=${config.appSecret}`
  );
  const tokenData = (await tokenRes.json()) as any;
  if (!tokenData.access_token) throw new Error(`获取微信access_token失败: ${JSON.stringify(tokenData)}`);

  const res = await fetch(
    `https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=${tokenData.access_token}`,
    {
      method: "POST",
      body: JSON.stringify({
        touser: config.toOpenId,
        template_id: config.templateId,
        data: {
          title: { value: msg.title },
          content: { value: msg.content },
        },
      }),
    }
  );
  const data = (await res.json()) as any;
  if (data.errcode !== 0) throw new Error(`微信公众号推送失败: ${JSON.stringify(data)}`);
}

async function sendTelegram(config: any, msg: NotifyMessage) {
  const res = await fetch(`https://api.telegram.org/bot${config.botToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: config.chatId,
      text: `*${msg.title}*\n${msg.content}`,
      parse_mode: "Markdown",
    }),
  });
  const data = (await res.json()) as any;
  if (!data.ok) throw new Error(`Telegram推送失败: ${JSON.stringify(data)}`);
}

async function sendDingtalk(config: any, msg: NotifyMessage) {
  let url = config.webhookUrl;
  if (config.secret) {
    const timestamp = Date.now();
    const stringToSign = `${timestamp}\n${config.secret}`;
    const { hmacSignBase64 } = await import("../utils/crypto");
    const sign = encodeURIComponent(await hmacSignBase64(stringToSign, config.secret, "SHA-256"));
    url = `${config.webhookUrl}&timestamp=${timestamp}&sign=${sign}`;
  }
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      msgtype: "markdown",
      markdown: { title: msg.title, text: `### ${msg.title}\n${msg.content}` },
    }),
  });
  const data = (await res.json()) as any;
  if (data.errcode !== 0) throw new Error(`钉钉推送失败: ${JSON.stringify(data)}`);
}

async function sendFeishu(config: any, msg: NotifyMessage) {
  const res = await fetch(config.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      msg_type: "text",
      content: { text: `${msg.title}\n${msg.content}` },
    }),
  });
  const data = (await res.json()) as any;
  if (data.code !== 0) throw new Error(`飞书推送失败: ${JSON.stringify(data)}`);
}

async function sendWecom(config: any, msg: NotifyMessage) {
  const res = await fetch(config.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      msgtype: "markdown",
      markdown: { content: `**${msg.title}**\n${msg.content}` },
    }),
  });
  const data = (await res.json()) as any;
  if (data.errcode !== 0) throw new Error(`企业微信推送失败: ${JSON.stringify(data)}`);
}

async function sendServerChan(config: any, msg: NotifyMessage) {
  const res = await fetch(`https://sctapi.ftqq.com/${config.sendKey}.send`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ title: msg.title, desp: msg.content }).toString(),
  });
  const data = (await res.json()) as any;
  if (data.code !== 0) throw new Error(`Server酱推送失败: ${JSON.stringify(data)}`);
}