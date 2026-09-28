import { Hono } from "hono";
import type { Env } from "./types";
import { authRoutes } from "./routes/auth";
import { userRoutes } from "./routes/users";
import { providerRoutes } from "./routes/providers";
import { domainRoutes } from "./routes/domains";
import { recordRoutes } from "./routes/records";
import { applinkRoutes } from "./routes/applink";
import { sslRoutes } from "./routes/ssl";
import { notifyRoutes } from "./routes/notify";
import { ciTokenRoutes, ciCallbackRoutes } from "./routes/ci";
import { overviewRoutes } from "./routes/overview";
import { toolsRoutes } from "./routes/tools";
import { handleExpiryReminders } from "./cron/reminders";
import { oauthRoutes } from "./routes/oauth";
import { misubRoutes, misubPublicRoutes } from "./routes/misub";
import { noticeRoutes } from "./routes/notices";

const app = new Hono<{ Bindings: Env }>();

// 简单CORS，便于Pages前端跨源调用（生产环境建议把 origin 收紧为你的Pages域名）
app.use("*", async (c, next) => {
  c.header("Access-Control-Allow-Origin", "*");
  c.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CI-Secret");
  c.header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  if (c.req.method === "OPTIONS") return c.body(null, 204);
  await next();
});

app.get("/api/health", (c) => c.json({ ok: true, name: c.env.APP_NAME }));

app.route("/api/auth", authRoutes);
app.route("/api/users", userRoutes);
app.route("/api/providers", providerRoutes);
app.route("/api/domains", domainRoutes);
app.route("/api/domains", recordRoutes); // /api/domains/:domainId/records...
app.route("/api/domains", sslRoutes); // /api/domains/:domainId/certs...
app.route("/api/notify", notifyRoutes);
app.route("/api/open", applinkRoutes); // /api/open/applink, /api/open/keys
app.route("/api/open", ciTokenRoutes); // /api/open/ci-token
app.route("/api/ci", ciCallbackRoutes); // /api/ci/certs/:id/complete, /api/ci/due-for-renewal
app.route("/api/overview", overviewRoutes);
app.route("/api/tools", toolsRoutes);
app.route("/api/oauth", oauthRoutes);
app.route("/api/misub", misubRoutes);
app.route("/", misubPublicRoutes); // 公开订阅输出：GET /:idOrToken，不需要登录
app.route("/api/notices", noticeRoutes);

app.notFound((c) => c.json({ error: "Not Found" }, 404));
app.onError((err, c) => {
  console.error(err);
  return c.json({ error: err.message || "服务器内部错误" }, 500);
});

// 证书签发/续签已经搬到 GitHub Actions 里跑（见 .github/workflows/）。
// 但「到期提醒通知」这个任务很轻量（只查数据库+发通知，没有ACME签名运算），
// 留在 Workers 自己的 Cron Trigger 里跑就够了，不需要搬去 GitHub Actions。
export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, env: Env, ctx: ExecutionContext) => {
    ctx.waitUntil(handleExpiryReminders(env));
  },
};
