PRAGMA defer_foreign_keys=TRUE;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,     -- PBKDF2 派生后的哈希，格式 iter$salt$hash（均为hex）
  role TEXT NOT NULL DEFAULT 'user', -- 'admin' | 'user'
  status TEXT NOT NULL DEFAULT 'active', -- 'active' | 'disabled'
  email TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE dns_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,               -- 用户自定义备注名
  type TEXT NOT NULL,               -- aliyun|tencent|huaweicloud|baiducloud|west|volcengine|dnsla|cloudflare|namesilo|powerdns
  credentials TEXT NOT NULL,        -- JSON字符串，AES-GCM加密后的密文（见 utils/crypto.ts）
  owner_user_id INTEGER NOT NULL,   -- 归属的用户（一般是admin录入）
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (owner_user_id) REFERENCES users(id)
);
CREATE TABLE domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id INTEGER NOT NULL,
  domain_name TEXT NOT NULL,
  remark TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  synced_at INTEGER,
  created_at INTEGER NOT NULL, sort_order INTEGER DEFAULT 0, whois_expires_at INTEGER, whois_checked_at INTEGER,
  FOREIGN KEY (provider_id) REFERENCES dns_providers(id),
  UNIQUE(provider_id, domain_name)
);
CREATE TABLE user_domain_perms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  domain_id INTEGER NOT NULL,
  perm TEXT NOT NULL DEFAULT 'readwrite', -- 'readonly' | 'readwrite'
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (domain_id) REFERENCES domains(id),
  UNIQUE(user_id, domain_id)
);
CREATE TABLE ssl_certs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  common_name TEXT NOT NULL,
  sans TEXT,                        -- JSON数组，多域名SAN
  ca TEXT NOT NULL DEFAULT 'letsencrypt',
  cert_pem TEXT,
  key_pem TEXT,                     -- 建议客户端下载后自行妥善保管；如需更高安全性可只存证书链不存私钥明文
  status TEXT NOT NULL DEFAULT 'pending', -- pending|issued|failed|expired
  issued_at INTEGER,
  expires_at INTEGER,
  auto_renew INTEGER NOT NULL DEFAULT 1,
  deploy_targets TEXT,               -- JSON: 自动部署目标（如上传到某CDN/服务器的webhook）
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL, issuer TEXT,
  FOREIGN KEY (domain_id) REFERENCES domains(id)
);
CREATE TABLE notify_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,   -- email|wechat_mp|telegram|dingtalk|feishu|wecom|serverchan
  config TEXT NOT NULL, -- JSON字符串（含密文）
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  key TEXT NOT NULL UNIQUE,
  secret_hash TEXT NOT NULL,
  remark TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  ip TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE record_remarks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  record_id TEXT NOT NULL,
  remark TEXT,
  updated_at INTEGER NOT NULL,
  UNIQUE(domain_id, record_id)
);
CREATE TABLE user_favorites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  domain_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, domain_id)
);
CREATE TABLE oauth_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  provider TEXT NOT NULL,           -- github | google | nodeloc
  provider_user_id TEXT NOT NULL,   -- 第三方平台侧的用户ID
  provider_username TEXT,           -- 第三方平台的用户名/昵称，仅用于展示
  created_at INTEGER NOT NULL,
  UNIQUE(provider, provider_user_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE misub_nodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL,
  name TEXT,
  url TEXT NOT NULL,              -- 节点链接，如 vmess://... vless://... trojan://... ss://... hysteria2://...
  enabled INTEGER NOT NULL DEFAULT 1,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
, group_name TEXT, last_latency_ms INTEGER, last_tested_at INTEGER);
CREATE TABLE misub_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  share_token TEXT NOT NULL UNIQUE,     -- 公开订阅链接用的随机token，客户端直接拿这个链接订阅，不需要登录
  node_ids TEXT NOT NULL DEFAULT '[]',           -- JSON数组，包含哪些手动节点
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
, sort_order INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, is_public INTEGER NOT NULL DEFAULT 1, access_count INTEGER NOT NULL DEFAULT 0, custom_id TEXT);
CREATE TABLE misub_access_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id INTEGER NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE misub_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  domain TEXT,
  updated_at INTEGER
);
CREATE TABLE oauth_provider_configs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL UNIQUE,     -- github | google | nodeloc
  label TEXT NOT NULL,               -- 登录按钮显示文字
  enabled INTEGER NOT NULL DEFAULT 0,
  sort_order INTEGER NOT NULL DEFAULT 0,
  client_id TEXT,
  client_secret TEXT,                -- AES-GCM加密存储（跟解析平台AK/SK用同一套加密逻辑）
  authorize_url TEXT,
  token_url TEXT,
  userinfo_url TEXT,
  scope TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
DELETE FROM sqlite_sequence;
CREATE INDEX idx_misub_access_log_profile ON misub_access_log(profile_id, created_at DESC);
CREATE UNIQUE INDEX idx_misub_profiles_custom_id ON misub_profiles(custom_id);
