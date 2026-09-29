<br>

# DNS-SUB

基于 Cloudflare Workers + D1 实现的**多平台域名解析统一管理系统**，前端为纯 HTML+JS 单页应用，通过 `API_BASE` 配置与 Worker 对接。

![Tech](https://img.shields.io/badge/runtime-Cloudflare%20Workers-F6821F) ![DB](https://img.shields.io/badge/db-Cloudflare%20D1-0051C3) ![Frontend](https://img.shields.io/badge/frontend-vanilla%20JS-f7df1e) ![Cert](https://img.shields.io/badge/ssl-GitHub%20Actions-2088FF)

## ✨ 功能

### 🌐 域名管理
- 多解析平台统一接入：Cloudflare / 阿里云 / DNSPod ）
- 域名列表：平台筛选、收藏、拖动排序、Whois 到期查询、批量删除
- 解析记录：统一增删改查、Cloudflare 小云朵代理、本地备注、批量操作
- 平台账号：凭据 AES-GCM 加密存储、提取域名、一键导入

### 👥 用户体系
- 多用户 + 域名级权限（readonly / readwrite）
- 个人资料：昵称 / 头像（文字+底色）/ 邮箱 / 改密
- 第三方登录绑定（GitHub / Google / NodeLoc，管理员后台配置）
- 单浏览器多账号管理：添加 / 免密切换 / 删除 / 拖动排序

### 🔒 SSL 证书
- ACME DNS-01 签发（Let's Encrypt），实际签发由 **GitHub Actions** 执行（绕开 Workers 10ms CPU 限制）
- 证书列表：状态轮询、详情、PEM/KEY 查看、zip 下载、批量删除
- 自动续签：每日定时检查，20 天内到期证书自动续签并回调写库
- 签发结果自动推送到通知渠道

### 📡 MiSub 订阅
- 手动节点：多行批量粘贴 / 订阅导入、分组管理（分组可拖动排序）、TCP 测速
- 订阅组：勾选节点、拖动排序决定输出顺序、启停开关、公开订阅链接
- 订阅输出：base64 + subconverter 转换（Clash / Surge / sing-box / V2Ray）

### 📢 通知
- 渠道：邮件（Resend）/ Server酱 / Telegram，可独立启停
- 每日定时：域名 / 证书到期提醒（Workers Cron）
- 事件推送：证书签发成功 / 失败

### 🛠 工具箱
- DNS 查询（Cloudflare DoH）
- Whois 查询（RDAP）
- 证书透明度查询（crt.sh）
- 订阅转换（subconverter 公共实例，Worker 服务端代理）

### 📊 其他
- 概览：统计卡片、20 天内到期提醒、公告、最近操作日志
- 通知公告：管理员发布并自动推送到全部启用渠道
- 审计日志（audit_logs）

## 🚀 部署

### 1️⃣ Cloudflare 侧

创建 D1 数据库并导入表结构：

```bash
npx wrangler d1 create dns-sub
npx wrangler d1 execute dns-sub --remote --file=./migrations/0001_init.sql
npx wrangler d1 execute dns-sub --remote --file=./migrations/0002_features.sql
```

编辑 `wrangler.toml`：

```toml
name = "dns-sub"
main = "src/index.ts"
compatibility_date = "2024-11-01"
compatibility_flags = ["nodejs_compat"]

[[d1_databases]]
binding = "DB"
database_name = "dns-sub"
database_id = "<创建时输出的 UUID>"

[triggers]
crons = ["0 0 * * *"]

[vars]
APP_NAME = "DNS-SUB"
GITHUB_OWNER = "<你的GitHub用户名>"
GITHUB_REPO   = "dns-sub"
GITHUB_REF    = "main"
OAUTH_REDIRECT_BASE = "https://api.example.com"
FRONTEND_BASE       = "https://www.example.com"
```

配置 Secrets（逐条执行）：

```bash
npx wrangler secret put JWT_SECRET
npx wrangler secret put ENCRYPT_KEY
npx wrangler secret put CI_CALLBACK_SECRET
npx wrangler secret put ACME_ACCOUNT_EMAIL
npx wrangler secret put GITHUB_TOKEN

npx wrangler deploy
```

### 2️⃣ GitHub 仓库 Secrets（Actions 使用）

仓库 → Settings → Secrets and variables → Actions：

| Secret | 说明 |
|---|---|
| WORKER_BASE_URL | Worker 地址，如 https://api.example.com |
| DNSMGR_API_KEY | 后台「API Key 管理」生成 |
| DNSMGR_API_SECRET | 同上（仅生成时显示一次） |
| CI_CALLBACK_SECRET | 与 Worker 的同名 Secret 相同值 |
| ACME_ACCOUNT_EMAIL | Let's Encrypt 账户邮箱 |
| ACME_DIRECTORY_URL | 可选，默认 Let's Encrypt |
| ACME_EAB_KID / ACME_EAB_HMAC_KEY | 可选，ZeroSSL 才需要 |

### 3️⃣ 前端

`public/` 部署到 Cloudflare Pages（或任意静态托管），前端 `API_BASE` 指向 Worker 地址即可。

### 4️⃣ 初始账号

admin / admin

> 首次登录后请立即修改密码。

## 🏗 架构

```
┌────────────────┐        ┌─────────────────────────┐
│  Pages（前端）  │ ─────▶│ Workers（API + 订阅分发）│
└────────────────┘        └───────────┬─────────────┘
                                      │
                          ┌───────────▼─────────────┐
                          │        D1 (SQLite)      │
                          └───────────▲─────────────┘
                                      │ 回调（X-CI-Secret）
┌────────────────┐        ┌───────────┴─────────────┐
│ 订阅客户端轮询   │ ─────▶│  GitHub Actions         │
└────────────────┘        │  · ACME DNS-01 签发      │
                          │  · 定时续签              │
                          └─────────────────────────┘
```

- Workers 只做「记录 + 触发」，ACME 重活交给 Actions（绕开 10ms CPU 限制）
- Actions 通过 Worker 的 REST API 写 DNS TXT 记录（复用全部平台适配器）
- Workers Cron 只跑轻量任务（到期提醒）

## 📁 目录结构

```
├── wrangler.toml
├── migrations/
├── src/
│   ├── index.ts              # Hono 入口，路由汇总
│   ├── db.ts                 # D1 访问封装
│   ├── types.ts              # 公共类型
│   ├── github.ts             # 触发 GitHub Actions
│   ├── middleware/auth.ts    # JWT 校验 + 权限
│   ├── utils/crypto.ts       # JWT / PBKDF2 / AES-GCM（WebCrypto）
│   ├── providers/            # 解析平台适配层
│   ├── notify/               # 通知渠道 + 域名归属推送
│   ├── acme/client.ts        # ACME v2 DNS-01 客户端
│   ├── cron/                 # 到期提醒
│   └── routes/               # auth users providers domains records ssl ci
│                             # notify notices oauth misub tools profile
├── scripts/                  # GitHub Actions 内运行的签发脚本（tsx 直跑）
├── .github/workflows/        # issue-cert / renew-certs / keepalive
└── public/                   # 前端单页应用
```

## 🔌 API 说明

所有接口以 `/api` 为前缀，鉴权：`Authorization: Bearer <JWT>`。

| 模块 | 前缀 |
|---|---|
| 认证 / 资料 | `/api/auth` · `/api/profile` |
| 用户管理 | `/api/users` |
| 解析平台 | `/api/providers` |
| 域名 + 解析记录 + 证书 | `/api/domains` |
| 通知渠道 / 公告 | `/api/notify` · `/api/notices` |
| OAuth | `/api/oauth` |
| MiSub | `/api/misub` |
| 工具箱 | `/api/tools` |
| 概览 | `/api/overview` |
| 开放接口（CI / 直达链接） | `/api/open` |

各端点的请求/响应格式见 `src/routes/*.ts` 内注释（每个端点均有说明）。

## 🔐 安全说明

- 平台凭据、OAuth Client Secret：**AES-GCM 加密落库**（ENCRYPT_KEY）
- CI 回调：共享密钥头 `X-CI-Secret` 校验
- 管理端点 `requireAdmin`；域名操作校验 `user_domain_perms`
- API Key 的 Secret 仅签发时明文返回一次，库中只存 PBKDF2 哈希
- **请勿**将任何 Secret / 私钥提交到仓库

