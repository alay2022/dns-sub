import { Hono } from "hono";
import type { Env, JwtPayload } from "../types";
import { requireAuth, requireAdmin } from "../middleware/auth";
import { signJwt, verifyJwt, aesEncrypt, aesDecrypt } from "../utils/crypto";
import { now, insertAuditLog } from "../db";

export const oauthRoutes = new Hono<{ Bindings: Env }>();

interface ProviderRow {
  provider: string;
  label: string;
  enabled: number;
  sort_order: number;
  client_id: string | null;
  client_secret: string | null; // 加密存储
  authorize_url: string | null;
  token_url: string | null;
  userinfo_url: string | null;
  scope: string | null;
}

async function getEnabledProvider(env: Env, provider: string): Promise<ProviderRow | null> {
  const row = await env.DB.prepare("SELECT * FROM oauth_provider_configs WHERE provider = ? AND enabled = 1")
    .bind(provider)
    .first<ProviderRow>();
  if (!row || !row.client_id || !row.client_secret || !row.authorize_url || !row.token_url || !row.userinfo_url) return null;
  return row;
}

async function decryptSecret(env: Env, encrypted: string): Promise<string> {
  return env.ENCRYPT_KEY ? aesDecrypt(encrypted, env.ENCRYPT_KEY) : encrypted;
}

function redirectUri(env: Env, provider: string): string {
  return `${(env.OAUTH_REDIRECT_BASE || "").replace(/\/$/, "")}/api/oauth/${provider}/callback`;
}

/** 前端登录页用这个接口拿到「已启用、按排序」的登录方式列表 */
oauthRoutes.get("/providers", async (c) => {
  const { results } = await c.env.DB.prepare(
    "SELECT provider, label FROM oauth_provider_configs WHERE enabled = 1 ORDER BY sort_order"
  ).all<{ provider: string; label: string }>();
  return c.json({ available: results.map((r) => r.provider), labels: Object.fromEntries(results.map((r) => [r.provider, r.label])) });
});

/** 拖拽排序：决定登录页上"使用XX登录"按钮的先后顺序 */
// 注意：静态路径 /admin/providers/reorder 必须注册在 /admin/providers/:provider 之前，
// 否则 reorder 会被 :provider 吞掉（provider="reorder" → 查不到 → 404）。
oauthRoutes.put("/admin/providers/reorder", requireAuth, requireAdmin, async (c) => {
  const { orderedProviders } = await c.req.json<{ orderedProviders: string[] }>();
  await c.env.DB.batch(
    orderedProviders.map((p, i) =>
      c.env.DB.prepare("UPDATE oauth_provider_configs SET sort_order = ? WHERE provider = ?").bind(i, p)
    )
  );
  return c.json({ ok: true });
});

oauthRoutes.get("/:provider/start", async (c) => {
  const provider = c.req.param("provider");
  const config = await getEnabledProvider(c.env, provider);
  if (!config) return c.text("该登录方式未配置或未启用，请联系管理员", 400);

  const mode = c.req.query("mode") === "link" ? "link" : "login";
  let uid: number | undefined;
  if (mode === "link") {
    const token = c.req.query("token");
    if (!token) return c.text("缺少登录态", 400);
    const payload = await verifyJwt<JwtPayload>(token, c.env.JWT_SECRET);
    if (!payload) return c.text("登录已过期", 401);
    uid = payload.uid;
  }

  const state = await signJwt(
    { mode, uid, nonce: crypto.randomUUID(), iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 600 },
    c.env.JWT_SECRET
  );

  const qs = new URLSearchParams({
    client_id: config.client_id!,
    redirect_uri: redirectUri(c.env, provider),
    scope: config.scope || "",
    state,
    response_type: "code",
  });
  return c.redirect(`${config.authorize_url}?${qs.toString()}`);
});

oauthRoutes.get("/:provider/callback", async (c) => {
  const provider = c.req.param("provider");
  const config = await getEnabledProvider(c.env, provider);
  const frontendBase = c.env.FRONTEND_BASE || "";
  if (!config) return c.text("该登录方式未配置或未启用", 400);

  const code = c.req.query("code");
  const state = c.req.query("state");
  if (!code || !state) return c.redirect(`${frontendBase}/?oauth_error=missing_code`);

  const statePayload = await verifyJwt<{ mode: "login" | "link"; uid?: number }>(state, c.env.JWT_SECRET);
  if (!statePayload) return c.redirect(`${frontendBase}/?oauth_error=invalid_state`);

  try {
    const clientSecret = await decryptSecret(c.env, config.client_secret!);
    const tokenRes = await fetch(config.token_url!, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({
        client_id: config.client_id!,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri(c.env, provider),
        grant_type: "authorization_code",
      }),
    });
    const tokenData = (await tokenRes.json()) as any;
    const accessToken = tokenData.access_token;
    if (!accessToken) throw new Error(`未能获取access_token: ${JSON.stringify(tokenData)}`);

    const userRes = await fetch(config.userinfo_url!, {
      headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "dns-sub-worker" },
    });
    const profile = (await userRes.json()) as any;

    const providerUserId = String(profile.id ?? profile.sub ?? profile.user_id ?? "");
    const providerUsername = profile.username ?? profile.login ?? profile.name ?? profile.email ?? providerUserId;
    if (!providerUserId) throw new Error("无法从第三方平台获取用户ID");

    if (statePayload.mode === "link") {
      await c.env.DB.prepare(
        `INSERT INTO oauth_accounts (user_id, provider, provider_user_id, provider_username, created_at)
         VALUES (?,?,?,?,?)
         ON CONFLICT(provider, provider_user_id) DO UPDATE SET user_id = excluded.user_id, provider_username = excluded.provider_username`
      )
        .bind(statePayload.uid, provider, providerUserId, providerUsername, now())
        .run();
      await insertAuditLog(c.env, statePayload.uid!, "oauth_link", provider, providerUsername);
      return c.redirect(`${frontendBase}/?oauth_linked=${provider}`);
    }

    const link = await c.env.DB.prepare("SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?")
      .bind(provider, providerUserId)
      .first<{ user_id: number }>();
    if (!link) return c.redirect(`${frontendBase}/?oauth_error=not_linked&provider=${provider}`);

    const user = await c.env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(link.user_id).first<any>();
    if (!user || user.status !== "active") return c.redirect(`${frontendBase}/?oauth_error=user_disabled`);

    const expireSeconds = Number(c.env.JWT_EXPIRE_SECONDS || 86400);
    const jwtToken = await signJwt(
      {
        uid: user.id,
        username: user.username,
        role: user.role,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + expireSeconds,
      },
      c.env.JWT_SECRET
    );
    await insertAuditLog(c.env, user.id, "oauth_login", provider);
    return c.redirect(`${frontendBase}/?direct-login=1&token=${jwtToken}`);
  } catch (e: any) {
    console.error(e);
    return c.redirect(`${frontendBase}/?oauth_error=${encodeURIComponent(e.message)}`);
  }
});

oauthRoutes.get("/links", requireAuth, async (c) => {
  const user = c.get("user") as JwtPayload;
  const { results } = await c.env.DB.prepare(
    "SELECT provider, provider_username, created_at FROM oauth_accounts WHERE user_id = ?"
  )
    .bind(user.uid)
    .all();
  return c.json(results);
});

oauthRoutes.delete("/links/:provider", requireAuth, async (c) => {
  const user = c.get("user") as JwtPayload;
  await c.env.DB.prepare("DELETE FROM oauth_accounts WHERE user_id = ? AND provider = ?")
    .bind(user.uid, c.req.param("provider"))
    .run();
  return c.json({ ok: true });
});

// ==================== 管理员：第三方登录方式配置（替代原来写在wrangler.toml里的方式） ====================

oauthRoutes.get("/admin/providers", requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.DB.prepare("SELECT * FROM oauth_provider_configs ORDER BY sort_order").all<any>();
  // client_secret 不明文返回，只告诉前端"是否已配置"
  return c.json(
    results.map((r) => ({
      provider: r.provider,
      label: r.label,
      enabled: !!r.enabled,
      sortOrder: r.sort_order,
      clientId: r.client_id || "",
      hasSecret: !!r.client_secret,
      authorizeUrl: r.authorize_url || "",
      tokenUrl: r.token_url || "",
      userinfoUrl: r.userinfo_url || "",
      scope: r.scope || "",
    }))
  );
});

oauthRoutes.put("/admin/providers/:provider", requireAuth, requireAdmin, async (c) => {
  const provider = c.req.param("provider");
  const body = await c.req.json<{
    enabled?: boolean;
    clientId?: string;
    clientSecret?: string; // 留空表示不修改
    authorizeUrl?: string;
    tokenUrl?: string;
    userinfoUrl?: string;
    scope?: string;
  }>();

  const row = await c.env.DB.prepare("SELECT * FROM oauth_provider_configs WHERE provider = ?").bind(provider).first<any>();
  if (!row) return c.json({ error: "不支持的登录方式" }, 404);

  const encryptedSecret = body.clientSecret
    ? c.env.ENCRYPT_KEY
      ? await aesEncrypt(body.clientSecret, c.env.ENCRYPT_KEY)
      : body.clientSecret
    : row.client_secret;

  await c.env.DB.prepare(
    `UPDATE oauth_provider_configs SET
       enabled=?, client_id=?, client_secret=?, authorize_url=?, token_url=?, userinfo_url=?, scope=?, updated_at=?
     WHERE provider=?`
  )
    .bind(
      body.enabled === undefined ? row.enabled : body.enabled ? 1 : 0,
      body.clientId ?? row.client_id,
      encryptedSecret,
      body.authorizeUrl ?? row.authorize_url,
      body.tokenUrl ?? row.token_url,
      body.userinfoUrl ?? row.userinfo_url,
      body.scope ?? row.scope,
      now(),
      provider
    )
    .run();
  return c.json({ ok: true });
});