const API = window.API_BASE || "";
// CloudSSH 服务器管理（跨域读取，需在 CloudSSH fork 部署 CORS 补丁并配置 CORS_ALLOWED_ORIGINS）
const CLOUDSSH = window.CLOUDSSH_BASE || "https://ssh.ztvps.com";

/** 格式化域名到期时间，20天内标记为快到期(红色) */
function formatDomainExpiry(whoisExpiresAt) {
  if (!whoisExpiresAt) return { text: "未查询", soon: false };
  const daysLeft = Math.ceil((whoisExpiresAt * 1000 - Date.now()) / 86400000);
  const dateStr = new Date(whoisExpiresAt * 1000).toLocaleDateString();
  if (daysLeft < 0) return { text: `${dateStr}（已过期）`, soon: true };
  return { text: `${dateStr}（${daysLeft}天后）`, soon: daysLeft <= 20 };
}

/** 生成一个可点击切换的云朵图标开关（用于Cloudflare代理开关），data-checked记录状态 */
function cloudToggleHtml(id, checked, label) {
  return `<span class="cloud-toggle ${checked ? "on" : ""}" id="${id}" data-checked="${checked}" title="点击切换：${label}">
    <svg viewBox="0 0 24 24" width="22" height="22" fill="currentColor" stroke="none">
      <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
    </svg>
    <span style="font-size:14px">${label}</span>
  </span>`;
}
/** 绑定 cloudToggleHtml 生成的开关的点击事件，需在插入DOM后调用 */
function bindCloudToggle(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.onclick = () => {
    const nowChecked = el.dataset.checked !== "true";
    el.dataset.checked = String(nowChecked);
    el.classList.toggle("on", nowChecked);
  };
}
let state = {
  token: localStorage.getItem("dnsmgr_token") || "",
  user: JSON.parse(localStorage.getItem("dnsmgr_user") || "null"),
  page: "overview",
  domains: [],
  currentDomainId: null,
  favorites: [],
  jumpToDomainId: null,
  navCollapsed: {},
};

function toast(msg, type = "") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

async function api(path, opts = {}) {
  const res = await fetch(`${API}/api${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
      ...(opts.headers || {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `请求失败(${res.status})`);
  return data;
}

function saveSession(token, user) {
  state.token = token;
  state.user = user;
  localStorage.setItem("dnsmgr_token", token);
  localStorage.setItem("dnsmgr_user", JSON.stringify(user));
  // 普通用户更关心自己的域名，登录后直接落地到「域名解析记录」页；管理员保留概览页
  state.page = user.role === "admin" ? "overview" : "domains";
}
function logout() {
  state.token = "";
  state.user = null;
  localStorage.removeItem("dnsmgr_token");
  localStorage.removeItem("dnsmgr_user");
  render();
}

// ---------------- 处理「登录直达链接」跳转 & OAuth回调提示 ----------------
(function handleDirectLogin() {
  const params = new URLSearchParams(location.search);
  const token = params.get("token");
  if (location.pathname.includes("direct-login") && token) {
    localStorage.setItem("dnsmgr_token", token);
    state.token = token;
    history.replaceState({}, "", "/");
  }
  const oauthError = params.get("oauth_error");
  const oauthLinked = params.get("oauth_linked");
  if (oauthError === "not_linked") {
    setTimeout(() => toast(`该${OAUTH_LABELS[params.get("provider")] || "第三方"}账号还没绑定过，请先用密码登录，再去个人设置里绑定`, "error"), 300);
    history.replaceState({}, "", "/");
  } else if (oauthError) {
    setTimeout(() => toast(`第三方登录失败：${oauthError}`, "error"), 300);
    history.replaceState({}, "", "/");
  } else if (oauthLinked) {
    setTimeout(() => toast(`${OAUTH_LABELS[oauthLinked] || oauthLinked} 绑定成功`, "success"), 300);
    history.replaceState({}, "", "/");
  }
})();

const OAUTH_LABELS = { github: "GitHub", google: "Google", nodeloc: "NodeLoc" };

// ---------------- 登录页 ----------------
async function renderLogin() {
  const app = document.getElementById("app");
  app.innerHTML = `
    <div class="login-wrap">
      <div class="login-box">
        <h2>DNSMGR-CF 登录</h2>
        <input id="username" placeholder="用户名" value="admin" />
        <input id="password" type="password" placeholder="密码" value="admin" />
        <button id="loginBtn">登录</button>
        <div id="oauthButtons" style="margin-top:12px"></div>
      </div>
    </div>`;
  document.getElementById("loginBtn").onclick = async () => {
    try {
      const username = document.getElementById("username").value;
      const password = document.getElementById("password").value;
      const data = await api("/auth/login", { method: "POST", body: { username, password } });
      saveSession(data.token, data.user);
      if (data.forcePasswordChange) toast("检测到你仍在使用默认密码 admin，请尽快修改", "error");
      render();
    } catch (e) {
      toast(e.message, "error");
    }
  };

  try {
    const { available } = await api("/oauth/providers");
    if (available.length) {
      document.getElementById("oauthButtons").innerHTML =
        `<div style="text-align:center;color:var(--muted);font-size:13px;margin:10px 0">或使用以下方式登录</div>` +
        available
          .map((p) => `<button class="secondary" style="width:100%;margin-top:6px" onclick="location.href='${API}/api/oauth/${p}/start?mode=login'">使用 ${OAUTH_LABELS[p]} 登录</button>`)
          .join("");
    }
  } catch {
    /* 拿不到就不显示第三方登录按钮，不影响正常密码登录 */
  }
}

// ---------------- 主框架 ----------------
const NAV = [
  { key: "overview", label: "概览" },
  {
    label: "域名管理",
    children: [
      { key: "domainList", label: "域名列表" },
      { key: "domains", label: "域名解析" },
      { key: "favorites", label: "收藏" },
      { key: "providers", label: "域名平台账户" },
    ],
  },
  {
    label: "SSL 证书",
    children: [
      { key: "ssl", label: "SSL 证书" },
      { key: "cloudssh", label: "CloudSSH 管理" },
    ],
  },
  { key: "misub", label: "MiSub订阅" },
  {
    label: "用户设置",
    children: [
      { key: "changePassword", label: "修改密码" },
      { key: "oauthLinks", label: "第三方登录绑定" },
      { key: "notify", label: "通知渠道" },
    ],
  },
  {
    label: "系统设置",
    adminOnly: true,
    children: [
      { key: "users", label: "用户管理" },
      { key: "misubDomain", label: "订阅域名设置" },
      { key: "applink", label: "开放API" },
      { key: "oauthAdmin", label: "第三方登录管理" },
    ],
  },
  { key: "tools", label: "工具箱" },
];

function renderNavItem(item) {
  if (item.adminOnly && state.user.role !== "admin") return "";
  if (item.children) {
    const collapsed = !!state.navCollapsed[item.label];
    return `<div class="nav-group">
      <div class="nav-group-title" data-group="${item.label}">
        <span>${item.label}</span>
        <span class="nav-group-arrow ${collapsed ? "" : "open"}">▸</span>
      </div>
      <div class="nav-group-children ${collapsed ? "collapsed" : ""}">
        ${item.children
          .map((c) => `<a data-page="${c.key}" class="nav-child ${state.page === c.key ? "active" : ""}">${c.label}</a>`)
          .join("")}
      </div>
    </div>`;
  }
  return `<a data-page="${item.key}" class="${state.page === item.key ? "active" : ""}">${item.label}</a>`;
}

async function renderShell() {
  const app = document.getElementById("app");
  const navHtml = NAV.map(renderNavItem).join("");

  app.innerHTML = `
    <div class="mobile-topbar">
      <button class="mobile-menu-btn" id="mobileMenuBtn">☰</button>
      <h1>DNSMGR-CF</h1>
    </div>
    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    <div class="sidebar" id="sidebar">
      <h1>DNSMGR-CF</h1>
      <nav>${navHtml}<a id="logoutLink">退出登录 (${state.user.username})</a></nav>
    </div>
    <div class="main" id="main"></div>`;

  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");
  const closeMobileSidebar = () => {
    sidebar.classList.remove("mobile-open");
    overlay.classList.remove("show");
  };
  document.getElementById("mobileMenuBtn").onclick = () => {
    sidebar.classList.toggle("mobile-open");
    overlay.classList.toggle("show");
  };
  overlay.onclick = closeMobileSidebar;

  app.querySelectorAll("[data-page]").forEach((a) => (a.onclick = () => { state.page = a.dataset.page; closeMobileSidebar(); render(); }));
  app.querySelectorAll("[data-group]").forEach(
    (el) => (el.onclick = () => {
      const g = el.dataset.group;
      state.navCollapsed[g] = !state.navCollapsed[g];
      renderShell();
    })
  );
  document.getElementById("logoutLink").onclick = logout;
  renderPage();
}

// ---------------- 收藏（页面） ----------------
async function renderFavorites(main) {
  main.innerHTML = `<div class="card"><h3>收藏的域名</h3><div id="favList">加载中...</div></div>`;
  try {
    const favorites = await api("/domains/favorites");
    state.favorites = favorites;
    const el = document.getElementById("favList");
    el.innerHTML = favorites.length
      ? `<table><tr><th>域名</th><th>操作</th></tr>${favorites
          .map(
            (f) => `<tr><td>${f.domain_name}</td>
              <td><button class="jumpToRecords" data-id="${f.id}">查看解析记录</button>
                  <button class="secondary unfavBtn" data-id="${f.id}">取消收藏</button></td></tr>`
          )
          .join("")}</table>`
      : `<p style="color:var(--muted)">还没有收藏任何域名，去「域名列表」页点星标图标收藏</p>`;

    el.querySelectorAll(".jumpToRecords").forEach(
      (btn) => (btn.onclick = () => {
        state.page = "domains";
        state.jumpToDomainId = Number(btn.dataset.id);
        render();
      })
    );
    el.querySelectorAll(".unfavBtn").forEach(
      (btn) => (btn.onclick = async () => {
        await api(`/domains/${btn.dataset.id}/favorite`, { method: "PUT", body: { favorite: false } });
        renderFavorites(main);
      })
    );
  } catch (e) {
    document.getElementById("favList").innerHTML = `<p style="color:red">${e.message}</p>`;
  }
}

// ---------------- 第三方登录管理（系统设置，管理员） ----------------
const OAUTH_ADMIN_FIELDS = {
  github: ["clientId", "clientSecret"],
  google: ["clientId", "clientSecret"],
  nodeloc: ["clientId", "clientSecret", "authorizeUrl", "tokenUrl", "userinfoUrl", "scope"],
};
const OAUTH_FIELD_LABELS = {
  clientId: "Client ID",
  clientSecret: "Client Secret（留空表示不修改）",
  authorizeUrl: "授权地址 (authorize)",
  tokenUrl: "Token地址",
  userinfoUrl: "用户信息地址 (userinfo)",
  scope: "Scope",
};

async function renderOauthAdmin(main) {
  main.innerHTML = `<div class="card">
    <h3>第三方登录管理</h3>
    <p style="color:var(--muted);font-size:14px">
      开关决定登录页是否显示这个"使用XX登录"按钮；卡片可以拖动排序，决定按钮在登录页上的先后顺序。
      GitHub/Google 需要先去对应平台申请 OAuth 应用；NodeLoc 端点不是标准化的，按你申请到的应用信息填。
      回调地址统一是 <code id="oauthCallbackHint">加载中...</code>，去对应平台的应用设置里把这个填成"回调/重定向URI"。
    </p>
    <div id="oauthProviderList">加载中...</div>
  </div>`;

  const providers = await api("/oauth/admin/providers");
  document.getElementById("oauthCallbackHint").textContent = `${API || location.origin}/api/oauth/<provider>/callback`;

  renderOauthProviderList(providers);
}

function renderOauthProviderList(providers) {
  const listEl = document.getElementById("oauthProviderList");
  listEl.innerHTML = providers
    .map(
      (p) => `<div class="misub-card" draggable="true" data-id="${p.provider}" style="margin-bottom:10px;cursor:grab">
        <div class="misub-card-head">
          <div class="misub-card-title">⠿ ${p.label}</div>
          <label class="switch"><input type="checkbox" class="toggleOauthProvider" data-provider="${p.provider}" ${p.enabled ? "checked" : ""} /><span class="slider"></span></label>
        </div>
        <div class="misub-card-sub">${p.clientId ? `Client ID: ${p.clientId}` : "还没配置"} ${p.hasSecret ? "· 已设置Secret" : "· 未设置Secret"}</div>
        <button class="secondary editOauthProvider" data-provider="${p.provider}">编辑配置</button>
      </div>`
    )
    .join("");

  listEl.querySelectorAll(".toggleOauthProvider").forEach(
    (cb) => (cb.onchange = async () => {
      try {
        await api(`/oauth/admin/providers/${cb.dataset.provider}`, { method: "PUT", body: { enabled: cb.checked } });
        toast("已更新", "success");
      } catch (e) {
        toast(e.message, "error");
        cb.checked = !cb.checked;
      }
    })
  );
  listEl.querySelectorAll(".editOauthProvider").forEach(
    (btn) => (btn.onclick = () => showEditOauthProviderModal(providers.find((p) => p.provider === btn.dataset.provider)))
  );

  enableDragReorder(listEl, ".misub-card", async (orderedIds) => {
    await api("/oauth/admin/providers/reorder", { method: "PUT", body: { orderedProviders: orderedIds } });
  });
}

function showEditOauthProviderModal(provider) {
  const fields = OAUTH_ADMIN_FIELDS[provider.provider] || [];
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:480px">
      <h3>编辑 ${provider.label} 登录配置</h3>
      ${fields
        .map((f) => {
          const currentValue = f === "clientSecret" ? "" : provider[f] || "";
          return `<label style="font-size:14px;color:var(--muted);display:block;margin:10px 0 4px">${OAUTH_FIELD_LABELS[f]}</label>
            <input class="oauthField" data-f="${f}" value="${String(currentValue).replace(/"/g, "&quot;")}" style="width:100%" />`;
        })
        .join("")}
      <div class="modal-actions">
        <button class="secondary" id="cancelOauthEditBtn">取消</button>
        <button id="saveOauthEditBtn">保存</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("cancelOauthEditBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  document.getElementById("saveOauthEditBtn").onclick = async () => {
    const body = {};
    overlay.querySelectorAll(".oauthField").forEach((input) => {
      if (input.value) body[input.dataset.f] = input.value;
    });
    try {
      await api(`/oauth/admin/providers/${provider.provider}`, { method: "PUT", body });
      toast("保存成功", "success");
      overlay.remove();
      renderOauthAdmin(document.getElementById("main"));
    } catch (e) {
      toast(e.message, "error");
    }
  };
}
async function renderChangePassword(main) {
  main.innerHTML = `<div class="card" style="max-width:420px">
    <h3>修改密码</h3>
    <label style="font-size:14px;color:var(--muted);display:block;margin-bottom:4px">原密码</label>
    <input id="oldPwd" type="password" placeholder="原密码" style="width:100%;margin-bottom:10px" />
    <label style="font-size:14px;color:var(--muted);display:block;margin-bottom:4px">新密码（至少6位）</label>
    <input id="newSelfPwd" type="password" placeholder="新密码" style="width:100%" />
    <button id="changeSelfPwdBtn" style="margin-top:14px">修改密码</button>
  </div>`;
  document.getElementById("changeSelfPwdBtn").onclick = async () => {
    try {
      await api("/auth/change-password", {
        method: "POST",
        body: { oldPassword: document.getElementById("oldPwd").value, newPassword: document.getElementById("newSelfPwd").value },
      });
      toast("密码修改成功", "success");
      document.getElementById("oldPwd").value = "";
      document.getElementById("newSelfPwd").value = "";
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

// ---------------- 第三方登录绑定（页面） ----------------
async function renderOauthLinks(main) {
  main.innerHTML = `<div class="card" style="max-width:480px">
    <h3>第三方登录绑定</h3>
    <div id="oauthLinksList">加载中...</div>
  </div>`;

  try {
    const [{ available, labels }, links] = await Promise.all([api("/oauth/providers"), api("/oauth/links")]);
    const linkedProviders = new Set(links.map((l) => l.provider));
    document.getElementById("oauthLinksList").innerHTML = available.length
      ? available
          .map((p) => {
            const linked = linkedProviders.has(p);
            return `<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
              <span>${labels[p] || p}${linked ? ` <span style="color:var(--success);font-size:13px">已绑定</span>` : ""}</span>
              ${
                linked
                  ? `<button class="danger unlinkOauth" data-provider="${p}" style="padding:4px 10px;font-size:13px">解绑</button>`
                  : `<button class="secondary linkOauth" data-provider="${p}" style="padding:4px 10px;font-size:13px">绑定</button>`
              }
            </div>`;
          })
          .join("")
      : `<p style="color:var(--muted);font-size:14px">管理员还没有在「系统设置 → 第三方登录管理」里启用任何登录方式</p>`;

    document.querySelectorAll(".linkOauth").forEach(
      (btn) => (btn.onclick = () => { location.href = `${API}/api/oauth/${btn.dataset.provider}/start?mode=link&token=${state.token}`; })
    );
    document.querySelectorAll(".unlinkOauth").forEach(
      (btn) => (btn.onclick = async () => {
        try {
          await api(`/oauth/links/${btn.dataset.provider}`, { method: "DELETE" });
          toast("已解绑", "success");
          renderOauthLinks(main);
        } catch (e) {
          toast(e.message, "error");
        }
      })
    );
  } catch (e) {
    document.getElementById("oauthLinksList").innerHTML = `<p style="color:red">${e.message}</p>`;
  }
}

function renderPage() {
  const main = document.getElementById("main");
  main.innerHTML = "";
  const renderers = {
    overview: renderOverview,
    domainList: renderDomainList,
    domains: renderDomains,
    favorites: renderFavorites,
    providers: renderProviders,
    ssl: renderSsl,
    cloudssh: renderCloudSSH,
    users: renderUsers,
    notify: renderNotify,
    applink: renderApplink,
    tools: renderTools,
    misub: renderMisub,
    misubDomain: renderMisubDomainSettings,
    changePassword: renderChangePassword,
    oauthLinks: renderOauthLinks,
    oauthAdmin: renderOauthAdmin,
  };
  (renderers[state.page] || renderOverview)(main);
}

// ---------------- 概览页 ----------------
async function renderOverview(main) {
  main.innerHTML = `<div id="overviewContent">加载中...</div>`;
  try {
    const data = await api("/overview");
    const el = document.getElementById("overviewContent");
    el.innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px">
        <div class="card" style="margin-bottom:0"><div style="color:var(--muted);font-size:14px">域名总数</div><div style="font-size:28px;font-weight:600">${data.domainCount}</div></div>
        ${data.providerCount !== null ? `<div class="card" style="margin-bottom:0"><div style="color:var(--muted);font-size:14px">解析平台账号</div><div style="font-size:28px;font-weight:600">${data.providerCount}</div></div>` : ""}
        <div class="card" style="margin-bottom:0"><div style="color:var(--muted);font-size:14px">已签发证书</div><div style="font-size:28px;font-weight:600;color:var(--success)">${data.certStats.issued || 0}</div></div>
        ${data.userCount !== null ? `<div class="card" style="margin-bottom:0"><div style="color:var(--muted);font-size:14px">用户数</div><div style="font-size:28px;font-weight:600">${data.userCount}</div></div>` : ""}
      </div>
      <div class="card">
        <h3>20天内到期的域名</h3>
        ${
          data.domainsExpiringSoon.length
            ? `<table><tr><th>域名</th><th>到期时间</th></tr>${data.domainsExpiringSoon
                .map((d) => `<tr><td>${d.domain_name}</td><td style="color:var(--danger)">${new Date(d.whois_expires_at * 1000).toLocaleDateString()}</td></tr>`)
                .join("")}</table>`
            : `<p style="color:var(--muted)">暂无即将到期的域名（需要先在「域名列表」页查询过到期时间才会显示在这里）</p>`
        }
      </div>
      <div class="card">
        <h3>20天内到期的证书</h3>
        ${
          data.expiringSoon.length
            ? `<table><tr><th>域名</th><th>CN</th><th>到期时间</th></tr>${data.expiringSoon
                .map((c) => `<tr><td>${c.domain_name}</td><td>${c.common_name}</td><td>${new Date(c.expires_at * 1000).toLocaleDateString()}</td></tr>`)
                .join("")}</table>`
            : `<p style="color:var(--muted)">暂无即将到期的证书</p>`
        }
      </div>
      ${
        data.recentActivity.length
          ? `<div class="card"><h3>最近操作日志</h3><table><tr><th>时间</th><th>用户</th><th>操作</th><th>对象</th></tr>${data.recentActivity
              .map(
                (a) => `<tr><td>${new Date(a.created_at * 1000).toLocaleString()}</td><td>${a.username || "-"}</td><td>${a.action}</td><td>${a.target || ""}</td></tr>`
              )
              .join("")}</table></div>`
          : ""
      }
    `;
  } catch (e) {
    document.getElementById("overviewContent").innerHTML = `<p style="color:red">${e.message}</p>`;
  }
}


let dragSrcId = null;

async function renderDomainList(main) {
  main.innerHTML = `<div class="card">
    <h3>域名列表 <span style="font-weight:400;font-size:13px;color:var(--muted)">拖动左侧 ⠿ 图标调整顺序，会同步到「域名解析记录」页面上方下拉框的排列顺序</span></h3>
    <div style="margin-bottom:10px">按解析平台筛选：<select id="domainListProviderFilter"><option value="">全部平台账号</option></select></div>
    <div id="domainListTable">加载中...</div>
    <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
      <label><input type="checkbox" id="selectAllDomains" /> 全选</label>
      <button class="danger" id="batchDeleteDomainsBtn">批量删除</button>
    </div>
  </div>`;

  const providers = await api("/providers");
  const providerFilter = document.getElementById("domainListProviderFilter");
  providerFilter.innerHTML +=
    providers.map((p) => `<option value="${p.id}">${p.name}（${p.type}）</option>`).join("");

  try {
    state.favorites = await api("/domains/favorites");
  } catch {
    state.favorites = [];
  }

  const load = async () => {
    const providerId = providerFilter.value;
    const domains = await api(providerId ? `/domains?providerId=${providerId}` : "/domains");
    state.domains = domains;
    renderDomainListTable(domains);
  };
  providerFilter.onchange = load;
  await load();

  document.getElementById("selectAllDomains").onchange = (e) => {
    document.querySelectorAll(".domainRowCheck").forEach((cb) => (cb.checked = e.target.checked));
  };

  document.getElementById("batchDeleteDomainsBtn").onclick = async () => {
    const ids = [...document.querySelectorAll(".domainRowCheck:checked")].map((cb) => Number(cb.dataset.id));
    if (!ids.length) return toast("请先勾选要删除的域名", "error");
    if (!confirm(`确认批量删除这 ${ids.length} 个域名？会同时清除相关的权限、证书、备注记录，且不可恢复。`)) return;
    try {
      await api("/domains/batch-delete", { method: "POST", body: { domainIds: ids } });
      toast("删除成功", "success");
      renderDomainList(main);
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

function renderDomainListTable(domains) {
  const container = document.getElementById("domainListTable");
  const favIds = new Set(state.favorites.map((f) => f.id));
  const starSvg = (filled) => `
    <svg class="fav-icon ${filled ? "active" : ""}" viewBox="0 0 24 24" width="22" height="22"
         fill="${filled ? "currentColor" : "none"}" stroke="currentColor" stroke-width="1.8"
         stroke-linecap="round" stroke-linejoin="round">
      <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
    </svg>`;

  container.innerHTML = domains.length
    ? `<table id="domainSortTable">
        <tr><th></th><th></th><th></th><th>域名</th><th>平台</th><th>状态</th><th>注册到期时间</th><th>操作</th></tr>
        ${domains
          .map((d) => {
            const expiresText = formatDomainExpiry(d.whois_expires_at);
            return `<tr draggable="true" data-id="${d.id}" class="domainDragRow">
              <td style="cursor:grab;width:24px">⠿</td>
              <td style="width:24px"><input type="checkbox" class="domainRowCheck" data-id="${d.id}" /></td>
              <td style="width:32px"><span class="favStar" data-id="${d.id}" title="收藏/取消收藏" style="cursor:pointer;display:inline-flex">${starSvg(favIds.has(d.id))}</span></td>
              <td>${d.domain_name}</td>
              <td>${d.provider_type}</td>
              <td>${d.status}</td>
              <td class="${expiresText.soon ? "text-danger" : ""}">${expiresText.text}</td>
              <td style="white-space:nowrap">
                <button class="secondary refreshWhois" data-id="${d.id}">查询到期</button>
                <button class="danger delDomain" data-id="${d.id}" data-name="${d.domain_name}">删除</button>
              </td>
            </tr>`;
          })
          .join("")}
      </table>`
    : `<p>暂无域名，请先在「解析平台账号」中添加账号并导入域名。</p>`;

  container.querySelectorAll(".refreshWhois").forEach(
    (btn) => (btn.onclick = async () => {
      btn.textContent = "查询中...";
      btn.disabled = true;
      try {
        const r = await api(`/domains/${btn.dataset.id}/refresh-whois`, { method: "POST" });
        if (r.ok) {
          toast("到期时间已更新", "success");
          renderDomainListTable(domains.map((d) => (d.id === Number(btn.dataset.id) ? { ...d, whois_expires_at: r.whoisExpiresAt } : d)));
        } else {
          toast(r.error || "查询失败", "error");
          btn.textContent = "查询到期";
          btn.disabled = false;
        }
      } catch (e) {
        toast(e.message, "error");
        btn.textContent = "查询到期";
        btn.disabled = false;
      }
    })
  );

  container.querySelectorAll(".delDomain").forEach(
    (btn) => (btn.onclick = async () => {
      if (!confirm(`确认删除域名「${btn.dataset.name}」？会同时清除相关的权限、证书、备注记录，且不可恢复。\n\n注意：这只是把域名移出本系统管理，不会影响该域名在解析平台上的实际解析记录。`)) return;
      try {
        await api("/domains/batch-delete", { method: "POST", body: { domainIds: [Number(btn.dataset.id)] } });
        toast("已删除", "success");
        renderDomainList(document.getElementById("main"));
      } catch (e) {
        toast(e.message, "error");
      }
    })
  );

  container.querySelectorAll(".favStar").forEach(
    (star) => (star.onclick = async () => {
      const domainId = Number(star.dataset.id);
      const icon = star.querySelector(".fav-icon");
      const isFav = icon.classList.contains("active");
      try {
        await api(`/domains/${domainId}/favorite`, { method: "PUT", body: { favorite: !isFav } });
        star.innerHTML = starSvg(!isFav);
        if (isFav) state.favorites = state.favorites.filter((f) => f.id !== domainId);
        else state.favorites.push({ id: domainId, domain_name: domains.find((d) => d.id === domainId)?.domain_name });
        renderShell();
      } catch (e) {
        toast(e.message, "error");
      }
    })
  );

  // 原生 HTML5 拖拽排序，不依赖任何第三方库
  const rows = container.querySelectorAll(".domainDragRow");
  rows.forEach((row) => {
    row.addEventListener("dragstart", () => {
      dragSrcId = row.dataset.id;
      row.style.opacity = "0.4";
    });
    row.addEventListener("dragend", () => {
      row.style.opacity = "1";
    });
    row.addEventListener("dragover", (e) => e.preventDefault());
    row.addEventListener("drop", async (e) => {
      e.preventDefault();
      if (!dragSrcId || dragSrcId === row.dataset.id) return;
      const table = document.getElementById("domainSortTable");
      const srcRow = table.querySelector(`[data-id="${dragSrcId}"]`);
      const rect = row.getBoundingClientRect();
      const insertAfter = e.clientY - rect.top > rect.height / 2;
      row.parentNode.insertBefore(srcRow, insertAfter ? row.nextSibling : row);

      const orderedIds = [...table.querySelectorAll(".domainDragRow")].map((r) => Number(r.dataset.id));
      try {
        await api("/domains/reorder", { method: "PUT", body: { orderedIds } });
        toast("排序已保存", "success");
      } catch (err) {
        toast(err.message, "error");
      }
    });
  });
}
// ---------------- 域名解析记录（下拉框选择域名） ----------------
async function renderDomains(main) {
  main.innerHTML = `<div class="card">
      <h3>域名解析记录</h3>
      <select id="domainSelect"></select>
    </div>
    <div class="card" id="recordsCard" style="display:none">
      <h3>解析记录</h3>
      <div id="recordForm"></div>
      <div id="recordList"></div>
    </div>`;
  try {
    const domains = await api("/domains");
    state.domains = domains;
    const select = document.getElementById("domainSelect");
    if (!domains.length) {
      select.outerHTML = `<p>暂无域名，请先在「解析平台账号」中添加账号并同步域名。</p>`;
      return;
    }
    select.innerHTML = domains
      .map((d) => `<option value="${d.id}">${d.domain_name}（${d.provider_type} · ${d.status}）</option>`)
      .join("");
    if (state.jumpToDomainId && domains.some((d) => d.id === state.jumpToDomainId)) {
      select.value = state.jumpToDomainId;
      state.jumpToDomainId = null;
    }
    select.onchange = () => loadRecords(Number(select.value));
    loadRecords(Number(select.value));
  } catch (e) {
    document.getElementById("domainSelect").outerHTML = `<p style="color:red">${e.message}</p>`;
  }
}

async function loadRecords(domainId) {
  state.currentDomainId = domainId;
  document.getElementById("recordsCard").style.display = "block";

  const domain = state.domains.find((d) => d.id === domainId);
  const isCloudflare = domain && domain.provider_type === "cloudflare";

  document.getElementById("recordForm").innerHTML = `
    <input id="rr" placeholder="主机记录 如 www / @" />
    <select id="type">
      <option>A</option><option>AAAA</option><option>CNAME</option><option>TXT</option><option>MX</option><option>NS</option>
    </select>
    <input id="value" placeholder="记录值" />
    <input id="ttl" placeholder="TTL" value="600" style="width:80px" />
    <input id="remark" placeholder="备注（可选）" style="width:140px" />
    ${isCloudflare ? cloudToggleHtml("proxied", false, "启用代理") : ""}
    <button id="addRecordBtn">添加记录</button>`;
  if (isCloudflare) bindCloudToggle("proxied");
  document.getElementById("addRecordBtn").onclick = async () => {
    try {
      await api(`/domains/${domainId}/records`, {
        method: "POST",
        body: {
          rr: document.getElementById("rr").value,
          type: document.getElementById("type").value,
          value: document.getElementById("value").value,
          ttl: Number(document.getElementById("ttl").value) || 600,
          remark: document.getElementById("remark").value || undefined,
          proxied: isCloudflare ? document.getElementById("proxied").dataset.checked === "true" : undefined,
        },
      });
      toast("添加成功", "success");
      loadRecords(domainId);
    } catch (e) {
      toast(e.message, "error");
    }
  };

  const listEl = document.getElementById("recordList");
  listEl.innerHTML = "加载中...";
  try {
    const records = await api(`/domains/${domainId}/records`);
    const cloudIcon = (proxied) => `
      <svg viewBox="0 0 24 24" width="20" height="20" title="${proxied ? "已代理" : "仅DNS"}"
           fill="${proxied ? "#f6821f" : "none"}" stroke="${proxied ? "#f6821f" : "#94a3b8"}" stroke-width="1.8"
           stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle">
        <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
      </svg>`;

    listEl.innerHTML = records.length
      ? `<table class="record-table">
          <tr><th></th><th>主机记录</th><th>类型</th><th>值</th><th>TTL</th>${isCloudflare ? "<th>代理</th>" : ""}<th>备注</th><th>操作</th></tr>
          ${records
            .map(
              (r) => `<tr>
                <td style="width:24px"><input type="checkbox" class="recordRowCheck" data-id="${r.id}" /></td>
                <td>${r.rr}</td><td>${r.type}</td>
                <td class="value-cell" title="${String(r.value).replace(/"/g, "&quot;")}">${r.value}</td>
                <td>${r.ttl}</td>
                ${isCloudflare ? `<td style="width:72px;text-align:center"><span class="cloud-toggle-cell" data-id="${r.id}" data-checked="${r.proxied ? "true" : "false"}" style="cursor:pointer;display:inline-flex">${cloudIcon(r.proxied)}</span></td>` : ""}
                <td><input class="remarkInput" data-id="${r.id}" value="${(r.remark || "").replace(/"/g, "&quot;")}" placeholder="备注" style="width:150px;font-size:13px" /></td>
                <td style="white-space:nowrap"><button class="secondary editRecord" data-record='${JSON.stringify(r).replace(/'/g, "&apos;")}'>修改</button>
                    <button class="danger delRecord" data-id="${r.id}">删除</button></td>
              </tr>`
            )
            .join("")}
        </table>
        <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
          <label><input type="checkbox" id="selectAllRecords" /> 全选</label>
          <button class="danger" id="batchDeleteRecordsBtn">批量删除</button>
        </div>`
      : `<p>暂无解析记录</p>`;

    if (!records.length) return;

    document.getElementById("selectAllRecords").onchange = (e) => {
      listEl.querySelectorAll(".recordRowCheck").forEach((cb) => (cb.checked = e.target.checked));
    };
    document.getElementById("batchDeleteRecordsBtn").onclick = async () => {
      const ids = [...listEl.querySelectorAll(".recordRowCheck:checked")].map((cb) => cb.dataset.id);
      if (!ids.length) return toast("请先勾选要删除的记录", "error");
      if (!confirm(`确认批量删除这 ${ids.length} 条解析记录？`)) return;
      try {
        const r = await api(`/domains/${domainId}/records/batch-delete`, { method: "POST", body: { recordIds: ids } });
        toast(`已删除 ${r.deleted} 条`, "success");
        loadRecords(domainId);
      } catch (e) {
        toast(e.message, "error");
      }
    };

    listEl.querySelectorAll(".remarkInput").forEach(
      (input) =>
        (input.onblur = async () => {
          try {
            await api(`/domains/${domainId}/records/${input.dataset.id}/remark`, {
              method: "PUT",
              body: { remark: input.value },
            });
          } catch (e) {
            toast(e.message, "error");
          }
        })
    );

    listEl.querySelectorAll(".cloud-toggle-cell").forEach(
      (cell) =>
        (cell.onclick = async () => {
          const record = records.find((r) => String(r.id) === cell.dataset.id);
          if (!record) return;
          const newProxied = cell.dataset.checked !== "true";
          try {
            await api(`/domains/${domainId}/records/${cell.dataset.id}`, {
              method: "PUT",
              body: { rr: record.rr, type: record.type, value: record.value, ttl: record.ttl, line: record.line, priority: record.priority, proxied: newProxied },
            });
            cell.dataset.checked = String(newProxied);
            cell.innerHTML = cloudIcon(newProxied);
            toast(newProxied ? "已开启代理" : "已关闭代理", "success");
          } catch (e) {
            toast(e.message, "error");
          }
        })
    );

    listEl.querySelectorAll(".editRecord").forEach(
      (btn) =>
        (btn.onclick = () => {
          const record = JSON.parse(btn.dataset.record.replace(/&apos;/g, "'"));
          showEditRecordModal(domainId, record, isCloudflare);
        })
    );

    listEl.querySelectorAll(".delRecord").forEach(
      (btn) =>
        (btn.onclick = async () => {
          if (!confirm("确认删除该记录？")) return;
          try {
            await api(`/domains/${domainId}/records/${btn.dataset.id}`, { method: "DELETE" });
            toast("已删除", "success");
            loadRecords(domainId);
          } catch (e) {
            toast(e.message, "error");
          }
        })
    );
  } catch (e) {
    listEl.innerHTML = `<p style="color:red">${e.message}</p>`;
  }
}

/** 修改解析记录弹窗，预填当前值 */
function showEditRecordModal(domainId, record, isCloudflare) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:420px">
      <h3>修改解析记录</h3>
      <label>主机记录</label>
      <input id="editRr" value="${record.rr}" style="width:100%" />
      <label>类型</label>
      <select id="editType" style="width:100%">
        ${["A", "AAAA", "CNAME", "TXT", "MX", "NS"]
          .map((t) => `<option ${t === record.type ? "selected" : ""}>${t}</option>`)
          .join("")}
      </select>
      <label>记录值</label>
      <input id="editValue" value="${record.value}" style="width:100%" />
      <label>TTL</label>
      <input id="editTtl" value="${record.ttl}" style="width:100%" />
      ${isCloudflare ? cloudToggleHtml("editProxied", !!record.proxied, "启用代理") : ""}
      <div class="modal-actions">
        <button class="secondary" id="cancelEditBtn">取消</button>
        <button id="saveEditBtn">保存</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  if (isCloudflare) bindCloudToggle("editProxied");
  document.getElementById("cancelEditBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  document.getElementById("saveEditBtn").onclick = async () => {
    try {
      await api(`/domains/${domainId}/records/${record.id}`, {
        method: "PUT",
        body: {
          rr: document.getElementById("editRr").value,
          type: document.getElementById("editType").value,
          value: document.getElementById("editValue").value,
          ttl: Number(document.getElementById("editTtl").value) || 600,
          proxied: isCloudflare ? document.getElementById("editProxied").dataset.checked === "true" : undefined,
        },
      });
      toast("修改成功", "success");
      overlay.remove();
      loadRecords(domainId);
    } catch (e) {
      toast(e.message, "error");
    }
  };
}


// ---------------- 解析平台账号 ----------------
const PROVIDER_TYPES = [
  ["cloudflare", "CloudFlare"],
  ["tencent", "腾讯云 DNSPod"],
  ["aliyun", "阿里云"],
  ["huaweicloud", "华为云"],
  ["baiducloud", "百度智能云"],
  ["west", "西部数码"],
  ["volcengine", "火山引擎"],
  ["dnsla", "DNSLA"],
  ["namesilo", "Namesilo"],
  ["powerdns", "PowerDNS"],
];
const PROVIDER_CRED_FIELDS = {
  cloudflare: [
    ["apiToken", "API Token（推荐，填了这个下面两项可留空）"],
    ["email", "邮箱（仅用 Global API Key 时需要）"],
    ["apiKey", "Global API Key（仅老版鉴权需要）"],
  ],
  tencent: [["secretId", "secretId"], ["secretKey", "secretKey"]],
  aliyun: [["accessKeyId", "accessKeyId"], ["accessKeySecret", "accessKeySecret"]],
  huaweicloud: [["accessKeyId", "accessKeyId"], ["secretAccessKey", "secretAccessKey"]],
  baiducloud: [["accessKeyId", "accessKeyId"], ["secretAccessKey", "secretAccessKey"]],
  west: [["username", "username"], ["apiPassword", "apiPassword"]],
  volcengine: [["accessKeyId", "accessKeyId"], ["secretAccessKey", "secretAccessKey"], ["region", "region(可选,默认cn-north-1)"]],
  dnsla: [["apiKey", "apiKey"], ["apiSecret", "apiSecret"]],
  namesilo: [["apiKey", "apiKey"]],
  powerdns: [["apiUrl", "apiUrl,如 https://ns.example.com:8081"], ["apiKey", "apiKey"], ["serverId", "serverId(可选,默认localhost)"]],
};

async function renderProviders(main) {
  main.innerHTML = `<div class="card"><h3>新增解析平台账号</h3>
      <select id="pType"></select>
      <input id="pName" placeholder="备注名称" />
      <div id="credFields"></div>
      <button id="addProviderBtn">保存</button>
    </div>
    <div class="card"><h3>已添加账号</h3><div id="providerList">加载中...</div></div>`;

  const typeSelect = document.getElementById("pType");
  typeSelect.innerHTML = PROVIDER_TYPES.map(([v, l]) => `<option value="${v}">${l}</option>`).join("");
  const renderCredFields = () => {
    const fields = PROVIDER_CRED_FIELDS[typeSelect.value] || [];
    document.getElementById("credFields").innerHTML = fields
      .map(([key, label]) => `<input data-f="${key}" placeholder="${label}" /><br/><br/>`)
      .join("");
  };
  typeSelect.onchange = renderCredFields;
  renderCredFields();

  document.getElementById("addProviderBtn").onclick = async () => {
    const credentials = {};
    document.querySelectorAll("#credFields input").forEach((i) => {
      if (i.value) credentials[i.dataset.f] = i.value; // 空字段不提交，避免覆盖为空字符串
    });
    try {
      await api("/providers", {
        method: "POST",
        body: { type: typeSelect.value, name: document.getElementById("pName").value || typeSelect.value, credentials },
      });
      toast("添加成功", "success");
      renderProviders(main);
    } catch (e) {
      toast(e.message, "error");
    }
  };

  const list = await api("/providers");
  document.getElementById("providerList").innerHTML = list.length
    ? `<table><tr><th>名称</th><th>类型</th><th>操作</th></tr>${list
        .map(
          (p) => `<tr><td>${p.name}</td><td>${p.type}</td>
          <td><button class="testP" data-id="${p.id}">测试</button>
              <button class="secondary editP" data-id="${p.id}" data-name="${p.name}" data-type="${p.type}">修改</button>
              <button class="discoverP" data-id="${p.id}">发现域名</button>
              <button class="danger delP" data-id="${p.id}">删除</button></td></tr>`
        )
        .join("")}</table>`
    : `<p>暂未添加任何解析平台账号</p>`;

  document.querySelectorAll(".testP").forEach(
    (btn) => (btn.onclick = async () => {
      try {
        const r = await api(`/providers/${btn.dataset.id}/test`, { method: "POST" });
        toast(r.ok ? `连接成功，检测到 ${r.domainCount} 个域名` : r.error, r.ok ? "success" : "error");
      } catch (e) {
        toast(e.message, "error");
      }
    })
  );
  document.querySelectorAll(".editP").forEach(
    (btn) => (btn.onclick = () => showEditProviderModal(btn.dataset.id, btn.dataset.name, btn.dataset.type, main))
  );
  document.querySelectorAll(".discoverP").forEach(
    (btn) => (btn.onclick = () => showDiscoverDomainsModal(btn.dataset.id))
  );
  document.querySelectorAll(".delP").forEach(
    (btn) => (btn.onclick = async () => {
      if (!confirm("确认删除该账号？")) return;
      await api(`/providers/${btn.dataset.id}`, { method: "DELETE" });
      renderProviders(main);
    })
  );
}

/** 修改解析平台账号弹窗：备注名可直接改；凭据字段留空表示不修改，只有填了才会覆盖原有凭据 */
function showEditProviderModal(providerId, currentName, type, main) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  const fields = PROVIDER_CRED_FIELDS[type] || [];
  overlay.innerHTML = `
    <div class="modal-box" style="width:420px">
      <h3>修改解析平台账号</h3>
      <label>备注名称</label>
      <input id="editPName" value="${currentName}" style="width:100%" />
      <label style="margin-top:8px">凭据（留空表示不修改，只有要更换密钥时才填）</label>
      <div id="editCredFields">${fields.map(([key, label]) => `<input data-f="${key}" placeholder="${label}（留空不改）" style="width:100%;margin:4px 0" />`).join("")}</div>
      <div class="modal-actions">
        <button class="secondary" id="cancelEditPBtn">取消</button>
        <button id="saveEditPBtn">保存</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("cancelEditPBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  document.getElementById("saveEditPBtn").onclick = async () => {
    const credentials = {};
    overlay.querySelectorAll("#editCredFields input").forEach((i) => {
      if (i.value) credentials[i.dataset.f] = i.value;
    });
    try {
      await api(`/providers/${providerId}`, {
        method: "PUT",
        body: { name: document.getElementById("editPName").value, credentials: Object.keys(credentials).length ? credentials : undefined },
      });
      toast("修改成功", "success");
      overlay.remove();
      renderProviders(main);
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

/** 发现域名弹窗：从平台拉取域名列表供勾选，已导入过的默认勾选并标注 */
async function showDiscoverDomainsModal(providerId) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box">
      <h3>发现域名</h3>
      <div id="discoverList">正在从平台拉取域名列表...</div>
      <div class="modal-actions">
        <button class="secondary" id="cancelDiscoverBtn">取消</button>
        <button id="importDomainsBtn">导入选中域名</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("cancelDiscoverBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  try {
    const domains = await api(`/providers/${providerId}/discover-domains`, { method: "POST" });
    const listEl = document.getElementById("discoverList");
    listEl.innerHTML = domains.length
      ? `<div style="max-height:50vh;overflow:auto"><table><tr><th></th><th>域名</th><th>状态</th></tr>${domains
          .map(
            (d) => `<tr>
              <td><input type="checkbox" class="discoverCheck" value="${d.domainName}" data-imported="${d.imported ? "1" : "0"}" ${d.imported ? "checked" : ""} /></td>
              <td>${d.domainName}</td>
              <td>${d.imported ? "已导入" : "未导入"}</td>
            </tr>`
          )
          .join("")}</table></div>`
      : `<p>该账号下没有找到任何域名。</p>`;
  } catch (e) {
    document.getElementById("discoverList").innerHTML = `<p style="color:red">${e.message}</p>`;
  }

  document.getElementById("importDomainsBtn").onclick = async () => {
    const allChecks = [...overlay.querySelectorAll(".discoverCheck")];
    const domainNames = allChecks.filter((cb) => cb.checked).map((cb) => cb.value);
    const allDomainNames = allChecks.map((cb) => cb.value);

    // 原本已导入、这次被取消勾选的，会从系统里移除，先明确告知
    const willRemove = allChecks
      .filter((cb) => !cb.checked && cb.dataset.imported === "1")
      .map((cb) => cb.value);
    if (willRemove.length) {
      const ok = confirm(
        `以下 ${willRemove.length} 个域名已取消勾选，保存后会从本系统中移除（同时清除它们的权限、证书、备注、收藏记录）：\n\n${willRemove.join("\n")}\n\n注意：移除只是不再由本系统管理，不会影响这些域名在解析平台上的实际解析记录。\n\n确认继续吗？`
      );
      if (!ok) return;
    }

    try {
      const r = await api(`/providers/${providerId}/import-domains`, {
        method: "POST",
        body: { domainNames, allDomainNames },
      });
      const parts = [];
      if (r.imported) parts.push(`导入/更新 ${r.imported} 个`);
      if (r.removed) parts.push(`移除 ${r.removed} 个`);
      toast(parts.length ? `已${parts.join("，")}域名` : "没有变化", "success");
      overlay.remove();
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

// ---------------- SSL 证书 ----------------
async function renderSsl(main) {
  main.innerHTML = `<div class="card"><h3>申请证书</h3>
    <select id="sslDomain"></select>
    <input id="cn" placeholder="主域名，留空默认为域名本身" />
    <label style="display:block;font-size:14px;color:var(--muted);margin:8px 0 4px">附加域名（SAN，可选，一行一个，不用逗号分隔）</label>
    <textarea id="sans" placeholder="例如：&#10;www.example.com&#10;api.example.com" style="width:100%;min-height:70px;font-family:inherit;font-size:14px;padding:8px;border:1px solid var(--border);border-radius:6px;box-sizing:border-box"></textarea>
    <div style="margin-top:8px"><button id="issueBtn">申请</button></div>
    <p style="color:var(--muted);font-size:13px">申请过程会自动通过该域名绑定的解析平台写入/清理 _acme-challenge TXT 记录完成 DNS-01 验证，可能需要1~3分钟。</p>
    </div>
    <div class="card">
      <h3>证书列表</h3>
      <div style="margin-bottom:10px">
        筛选域名：<select id="certFilterDomain"><option value="">全部域名</option></select>
      </div>
      <div id="certList">加载中...</div>
      <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
        <label><input type="checkbox" id="selectAllCerts" /> 全选</label>
        <button class="danger" id="batchDeleteCertsBtn">批量删除</button>
      </div>
    </div>`;

  const domains = await api("/domains");
  state.domains = domains;
  document.getElementById("sslDomain").innerHTML = domains.map((d) => `<option value="${d.id}">${d.domain_name}</option>`).join("");
  document.getElementById("certFilterDomain").innerHTML +=
    domains.map((d) => `<option value="${d.id}">${d.domain_name}</option>`).join("");

  const loadCertList = async () => {
    const filterDomainId = document.getElementById("certFilterDomain").value;
    const certs = filterDomainId ? await api(`/domains/${filterDomainId}/certs`) : await api(`/domains/certs`);
    const certListEl = document.getElementById("certList");
    certListEl.innerHTML = certs.length
      ? `<table><tr><th></th><th>域名</th><th>证书域名</th><th>状态</th><th>到期时间</th><th>操作</th></tr>${certs
          .map((c) => {
            const sans = JSON.parse(c.sans || "[]").filter((s) => s !== c.common_name);
            return `<tr>
              <td><input type="checkbox" class="certRowCheck" data-id="${c.id}" /></td>
              <td>${c.domain_name || ""}</td>
              <td>${[c.common_name, ...sans].join("<br/>")}</td>
              <td><span class="tag ${c.status}">${c.status}</span></td>
              <td>${c.expires_at ? new Date(c.expires_at * 1000).toLocaleDateString() : "-"}</td>
              <td style="white-space:nowrap">${
                c.status === "issued"
                  ? `<button class="detail secondary" data-cert='${JSON.stringify(c).replace(/'/g, "&apos;")}'>详情</button> <button class="view secondary" data-id="${c.id}" data-domain="${c.domain_id}">查看</button> <button class="dl" data-id="${c.id}" data-domain="${c.domain_id}">下载</button> <button class="renew secondary" data-id="${c.id}" data-domain="${c.domain_id}">续签</button> `
                  : ""
              }<button class="danger delCert" data-id="${c.id}" data-cn="${c.common_name}">删除</button></td></tr>`;
          })
          .join("")}</table>`
      : `<p>暂无证书</p>`;

    document.getElementById("selectAllCerts").onchange = (e) => {
      certListEl.querySelectorAll(".certRowCheck").forEach((cb) => (cb.checked = e.target.checked));
    };

    certListEl.querySelectorAll(".detail").forEach(
      (btn) => (btn.onclick = () => {
        const cert = JSON.parse(btn.dataset.cert.replace(/&apos;/g, "'"));
        showCertDetailModal(cert);
      })
    );

    certListEl.querySelectorAll(".delCert").forEach(
      (btn) => (btn.onclick = async () => {
        if (!confirm(`确认删除证书「${btn.dataset.cn}」的记录？\n\n注意：这只是删除本系统里保存的证书记录，不会向CA吊销该证书。如果已经把证书部署到了服务器上，它仍然有效。`)) return;
        try {
          await api("/domains/certs/batch-delete", { method: "POST", body: { certIds: [Number(btn.dataset.id)] } });
          toast("已删除", "success");
          loadCertList();
        } catch (e) {
          toast(e.message, "error");
        }
      })
    );

    certListEl.querySelectorAll(".view").forEach(
      (btn) => (btn.onclick = async () => {
        try {
          const data = await api(`/domains/${btn.dataset.domain}/certs/${btn.dataset.id}/download`);
          showCertModal(data.certPem, data.keyPem);
        } catch (e) {
          toast(e.message, "error");
        }
      })
    );
    certListEl.querySelectorAll(".dl").forEach(
      (btn) => (btn.onclick = async () => {
        const data = await api(`/domains/${btn.dataset.domain}/certs/${btn.dataset.id}/download`);
        const blob = new Blob([`${data.certPem}\n${data.keyPem}`], { type: "text/plain" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `cert-${btn.dataset.id}.pem`;
        a.click();
      })
    );
    certListEl.querySelectorAll(".renew").forEach(
      (btn) => (btn.onclick = async () => {
        try {
          const r = await api(`/domains/${btn.dataset.domain}/certs/${btn.dataset.id}/renew`, { method: "POST" });
          toast("已提交续签，正在后台处理中，可能需要1~3分钟", "success");
          loadCertList();
          pollCertStatus(btn.dataset.domain, Number(btn.dataset.id), loadCertList);
        } catch (e) {
          toast(e.message, "error");
        }
      })
    );
  };

  document.getElementById("certFilterDomain").onchange = loadCertList;
  document.getElementById("batchDeleteCertsBtn").onclick = async () => {
    const ids = [...document.querySelectorAll(".certRowCheck:checked")].map((cb) => Number(cb.dataset.id));
    if (!ids.length) return toast("请先勾选要删除的证书", "error");
    if (!confirm(`确认批量删除这 ${ids.length} 条证书记录？（只删除本地记录，不会去CA吊销证书）`)) return;
    try {
      const r = await api(`/domains/certs/batch-delete`, { method: "POST", body: { certIds: ids } });
      toast(`已删除 ${r.deleted} 条`, "success");
      loadCertList();
    } catch (e) {
      toast(e.message, "error");
    }
  };

  loadCertList();

  document.getElementById("issueBtn").onclick = async () => {
    const domainId = document.getElementById("sslDomain").value;
    const domain = state.domains.find((d) => String(d.id) === String(domainId));
    const cnInput = document.getElementById("cn").value.trim();
    const cn = cnInput || (domain ? domain.domain_name : "");
    const sansRaw = document.getElementById("sans").value;
    const sans = sansRaw
      ? sansRaw.split("\n").map((s) => s.trim()).filter(Boolean)
      : [];
    if (!cn) return toast("请先选择域名", "error");
    try {
      const r = await api(`/domains/${domainId}/certs`, { method: "POST", body: { commonName: cn, sans } });
      toast("已提交申请，正在后台签发中，可能需要1~3分钟，请不要重复点击", "success");
      loadCertList();
      pollCertStatus(domainId, r.certId, loadCertList);
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

/** 每隔5秒刷新一次证书列表，最多轮询2分钟，直到状态不再是pending（签发在Worker后台异步执行，不依赖本次页面停留） */
function pollCertStatus(domainId, certId, onUpdate, triesLeft = 24) {
  if (triesLeft <= 0) return;
  setTimeout(async () => {
    try {
      const certs = await api(`/domains/${domainId}/certs`);
      const cert = certs.find((c) => c.id === certId);
      if (cert && cert.status === "issued") {
        toast(`证书 ${cert.common_name} 签发成功`, "success");
        onUpdate();
      } else if (cert && cert.status === "failed") {
        toast(`证书 ${cert.common_name} 签发失败，请查看 GitHub Actions 的 Issue SSL Certificate 工作流日志`, "error");
        onUpdate();
      } else {
        onUpdate();
        pollCertStatus(domainId, certId, onUpdate, triesLeft - 1);
      }
    } catch (e) {
      pollCertStatus(domainId, certId, onUpdate, triesLeft - 1);
    }
  }, 5000);
}

/** 证书详情弹窗 */
function showCertDetailModal(cert) {
  const sans = JSON.parse(cert.sans || "[]").filter((s) => s !== cert.common_name);
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:480px">
      <h3>证书详情</h3>
      <table>
        <tr><th style="width:110px;text-align:left">主域名</th><td>${cert.common_name}</td></tr>
        <tr><th style="text-align:left">附加域名</th><td>${sans.length ? sans.join("<br/>") : "（无）"}</td></tr>
        <tr><th style="text-align:left">颁发机构</th><td>${cert.issuer || "（未知，可能是本系统迁移GitHub Actions签发前签发的旧证书）"}</td></tr>
        <tr><th style="text-align:left">生效时间</th><td>${cert.issued_at ? new Date(cert.issued_at * 1000).toLocaleString() : "-"}</td></tr>
        <tr><th style="text-align:left">过期时间</th><td>${cert.expires_at ? new Date(cert.expires_at * 1000).toLocaleString() : "-"}</td></tr>
        <tr><th style="text-align:left">自动续签</th><td>${cert.auto_renew ? "已开启" : "已关闭"}</td></tr>
      </table>
      <div class="modal-actions">
        <button id="closeCertDetailBtn">关闭</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("closeCertDetailBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
}

// ---------------- 用户管理 ----------------
async function renderUsers(main) {
  main.innerHTML = `<div class="card"><h3>新增用户</h3>
    <input id="uName" placeholder="用户名" />
    <input id="uPass" placeholder="密码" type="password" />
    <select id="uRole"><option value="user">普通用户</option><option value="admin">管理员</option></select>
    <button id="addUserBtn">创建</button></div>
    <div class="card"><h3>用户列表</h3><div id="userList">加载中...</div></div>`;

  document.getElementById("addUserBtn").onclick = async () => {
    try {
      await api("/users", {
        method: "POST",
        body: {
          username: document.getElementById("uName").value,
          password: document.getElementById("uPass").value,
          role: document.getElementById("uRole").value,
        },
      });
      toast("创建成功", "success");
      renderUsers(main);
    } catch (e) {
      toast(e.message, "error");
    }
  };

  const users = await api("/users");
  document.getElementById("userList").innerHTML = `<table><tr><th>用户名</th><th>角色</th><th>状态</th><th>操作</th></tr>${users
    .map(
      (u) => `<tr><td>${u.username}</td><td>${u.role}</td><td>${u.status}</td>
        <td>${
          u.username !== "admin"
            ? `<button class="secondary toggleStatus" data-id="${u.id}" data-status="${u.status === "active" ? "disabled" : "active"}">${
                u.status === "active" ? "禁用" : "启用"
              }</button>
              <button class="secondary resetPwd" data-id="${u.id}" data-username="${u.username}">修改密码</button>
              <button class="secondary grantP" data-id="${u.id}" data-username="${u.username}">授权域名</button>
              <button class="danger delUser" data-id="${u.id}" data-username="${u.username}">删除</button>`
            : ""
        }</td></tr>`
    )
    .join("")}</table>`;

  document.querySelectorAll(".toggleStatus").forEach(
    (btn) => (btn.onclick = async () => {
      await api(`/users/${btn.dataset.id}/status`, { method: "PUT", body: { status: btn.dataset.status } });
      renderUsers(main);
    })
  );

  document.querySelectorAll(".resetPwd").forEach(
    (btn) => (btn.onclick = () => showResetPasswordModal(btn.dataset.id, btn.dataset.username))
  );

  document.querySelectorAll(".delUser").forEach(
    (btn) => (btn.onclick = async () => {
      if (!confirm(`确认删除用户「${btn.dataset.username}」？这会同时清除该用户的域名授权、API Key、通知渠道配置，且不可恢复。`)) return;
      try {
        await api(`/users/${btn.dataset.id}`, { method: "DELETE" });
        toast("已删除", "success");
        renderUsers(main);
      } catch (e) {
        toast(e.message, "error");
      }
    })
  );

  document.querySelectorAll(".grantP").forEach(
    (btn) => (btn.onclick = () => showDomainPermModal(btn.dataset.id, btn.dataset.username))
  );
}

/** 修改密码弹窗（管理员直接重置，不需要旧密码） */
function showResetPasswordModal(userId, username) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:360px">
      <h3>修改密码 - ${username}</h3>
      <label>新密码（至少6位）</label>
      <input id="newPwdInput" type="password" style="width:100%" />
      <div class="modal-actions">
        <button class="secondary" id="cancelPwdBtn">取消</button>
        <button id="savePwdBtn">保存</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("cancelPwdBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  document.getElementById("savePwdBtn").onclick = async () => {
    const newPassword = document.getElementById("newPwdInput").value;
    if (!newPassword || newPassword.length < 6) {
      toast("新密码长度至少6位", "error");
      return;
    }
    try {
      await api(`/users/${userId}/password`, { method: "PUT", body: { newPassword } });
      toast("密码已修改", "success");
      overlay.remove();
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

/** 授权域名弹窗：所有域名以勾选框形式列出，勾选=授权，每个勾选项旁可选只读/读写 */
async function showDomainPermModal(userId, username) {
  let domains, currentPerms;
  try {
    [domains, currentPerms] = await Promise.all([
      api("/domains"),
      api(`/users/${userId}/domain-perms`),
    ]);
  } catch (e) {
    toast(`加载失败: ${e.message}`, "error");
    return;
  }
  const permMap = {};
  currentPerms.forEach((p) => (permMap[p.domain_id] = p.perm));

  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box">
      <h3>授权域名 - ${username}</h3>
      <div style="max-height:50vh;overflow:auto">
        <table>
          <tr><th></th><th>域名</th><th>权限</th></tr>
          ${domains
            .map((d) => {
              const granted = permMap[d.id];
              return `<tr>
                <td><input type="checkbox" class="domCheck" data-domain="${d.id}" ${granted ? "checked" : ""} /></td>
                <td>${d.domain_name}</td>
                <td>
                  <select class="domPerm" data-domain="${d.id}" ${granted ? "" : "disabled"}>
                    <option value="readwrite" ${granted === "readwrite" || !granted ? "selected" : ""}>读写</option>
                    <option value="readonly" ${granted === "readonly" ? "selected" : ""}>只读</option>
                  </select>
                </td>
              </tr>`;
            })
            .join("")}
        </table>
      </div>
      <div class="modal-actions">
        <button class="secondary" id="cancelPermBtn">取消</button>
        <button id="savePermBtn">保存</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  overlay.querySelectorAll(".domCheck").forEach((cb) => {
    cb.onchange = () => {
      const select = overlay.querySelector(`.domPerm[data-domain="${cb.dataset.domain}"]`);
      select.disabled = !cb.checked;
    };
  });

  document.getElementById("cancelPermBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  document.getElementById("savePermBtn").onclick = async () => {
    const checks = [...overlay.querySelectorAll(".domCheck")];
    try {
      for (const cb of checks) {
        const domainId = Number(cb.dataset.domain);
        const wasGranted = !!permMap[domainId];
        if (cb.checked) {
          const perm = overlay.querySelector(`.domPerm[data-domain="${domainId}"]`).value;
          // 新勾选的，或者权限档位变了，才调用保存接口（避免没改动的也重复请求）
          if (!wasGranted || permMap[domainId] !== perm) {
            await api(`/users/${userId}/domain-perms`, { method: "POST", body: { domainId, perm } });
          }
        } else if (wasGranted) {
          await api(`/users/${userId}/domain-perms/${domainId}`, { method: "DELETE" });
        }
      }
      toast("授权已更新", "success");
      overlay.remove();
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

// ---------------- 通知渠道 ----------------
const NOTIFY_TYPES = [
  ["email", "邮件"],
  ["wechat_mp", "微信公众号"],
  ["telegram", "Telegram"],
  ["dingtalk", "钉钉"],
  ["feishu", "飞书"],
  ["wecom", "企业微信"],
  ["serverchan", "Server酱"],
];
const NOTIFY_FIELDS = {
  email: ["apiKey", "from", "to"],
  wechat_mp: ["appId", "appSecret", "templateId", "toOpenId"],
  telegram: ["botToken", "chatId"],
  dingtalk: ["webhookUrl", "secret"],
  feishu: ["webhookUrl"],
  wecom: ["webhookUrl"],
  serverchan: ["sendKey"],
};

const NOTIFY_TYPE_LABELS = Object.fromEntries(NOTIFY_TYPES);

async function renderNotify(main) {
  main.innerHTML = `<div class="card"><h3>新增通知渠道</h3>
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:8px">
      <select id="nType"></select>
      <div id="nFields" style="display:flex;flex-wrap:wrap;gap:8px"></div>
      <button id="addNotifyBtn">新增</button>
    </div></div>
    <div class="card"><h3>已配置渠道</h3><div id="notifyList">加载中...</div></div>`;

  const sel = document.getElementById("nType");
  sel.innerHTML = NOTIFY_TYPES.map(([v, l]) => `<option value="${v}">${l}</option>`).join("");
  const renderFields = () => {
    document.getElementById("nFields").innerHTML = (NOTIFY_FIELDS[sel.value] || [])
      .map((f) => `<input data-f="${f}" placeholder="${f}" />`)
      .join("");
  };
  sel.onchange = renderFields;
  renderFields();

  document.getElementById("addNotifyBtn").onclick = async () => {
    const config = {};
    document.querySelectorAll("#nFields input").forEach((i) => (config[i.dataset.f] = i.value));
    try {
      await api("/notify", { method: "POST", body: { type: sel.value, config } });
      toast("新增成功", "success");
      renderNotify(main);
    } catch (e) {
      toast(e.message, "error");
    }
  };

  const list = await api("/notify");
  document.getElementById("notifyList").innerHTML = list.length
    ? `<table><tr><th>类型</th><th>状态</th><th>操作</th></tr>${list
        .map(
          (n) => `<tr><td>${NOTIFY_TYPE_LABELS[n.type] || n.type}</td><td>${n.enabled ? "启用" : "禁用"}</td>
          <td><button class="testN" data-id="${n.id}">测试</button>
              <button class="secondary editN" data-id="${n.id}" data-type="${n.type}">修改</button>
              <button class="danger delN" data-id="${n.id}">删除</button></td></tr>`
        )
        .join("")}</table>`
    : `<p>暂未配置通知渠道</p>`;

  document.querySelectorAll(".testN").forEach(
    (btn) => (btn.onclick = async () => {
      const r = await api(`/notify/${btn.dataset.id}/test`, { method: "POST" });
      toast(r.ok ? "发送成功，请查收" : r.error, r.ok ? "success" : "error");
    })
  );
  document.querySelectorAll(".editN").forEach(
    (btn) => (btn.onclick = () => showEditNotifyModal(btn.dataset.id, btn.dataset.type, main))
  );
  document.querySelectorAll(".delN").forEach(
    (btn) => (btn.onclick = async () => {
      await api(`/notify/${btn.dataset.id}`, { method: "DELETE" });
      renderNotify(main);
    })
  );
}

/** 修改通知渠道弹窗：渠道类型不能改（改类型等于换成另一种渠道，直接新增更清楚），只改配置字段 */
async function showEditNotifyModal(channelId, type, main) {
  let detail;
  try {
    detail = await api(`/notify/${channelId}`);
  } catch (e) {
    toast(e.message, "error");
    return;
  }
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:400px">
      <h3>修改通知渠道 - ${NOTIFY_TYPE_LABELS[type] || type}</h3>
      <div id="editNFields">${(NOTIFY_FIELDS[type] || [])
        .map((f) => `<input data-f="${f}" placeholder="${f}" value="${(detail.config[f] || "").toString().replace(/"/g, "&quot;")}" style="width:100%;margin:4px 0" />`)
        .join("")}</div>
      <div class="modal-actions">
        <button class="secondary" id="cancelEditNBtn">取消</button>
        <button id="saveEditNBtn">保存</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("cancelEditNBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  document.getElementById("saveEditNBtn").onclick = async () => {
    const config = {};
    overlay.querySelectorAll("#editNFields input").forEach((i) => (config[i.dataset.f] = i.value));
    try {
      await api(`/notify/${channelId}`, { method: "PUT", body: { config } });
      toast("修改成功", "success");
      overlay.remove();
      renderNotify(main);
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

// ---------------- 开放API / 登录直达链接 ----------------
async function renderApplink(main) {
  main.innerHTML = `<div class="card"><h3>API Key（供 IDC 系统调用「获取域名登录直达链接」接口）</h3>
    <p style="font-size:13px;color:var(--muted)">
      调用方式：POST ${API || location.origin}/api/open/applink&nbsp;
      body: {"apiKey":"...","apiSecret":"...","domainId":1} → 返回 {"url": "https://.../direct-login?token=..."}
    </p>
    <button id="createKeyBtn">生成新的 API Key</button>
    <div id="keyList">加载中...</div></div>`;

  document.getElementById("createKeyBtn").onclick = async () => {
    const r = await api("/open/keys", { method: "POST", body: { userId: state.user.id, remark: "IDC对接" } });
    alert(`API Key: ${r.apiKey}\nAPI Secret: ${r.apiSecret}\n\n请妥善保存，Secret仅显示这一次！`);
    renderApplink(main);
  };

  const list = await api("/open/keys");
  document.getElementById("keyList").innerHTML = list.length
    ? `<table><tr><th>API Key</th><th>备注</th><th>状态</th><th>操作</th></tr>${list
        .map(
          (k) => `<tr><td>${k.key}</td><td>${k.remark || ""}</td><td>${k.status}</td>
          <td><button class="danger delKey" data-id="${k.id}">吊销</button></td></tr>`
        )
        .join("")}</table>`
    : `<p>暂无API Key</p>`;

  document.querySelectorAll(".delKey").forEach(
    (btn) => (btn.onclick = async () => {
      await api(`/open/keys/${btn.dataset.id}`, { method: "DELETE" });
      renderApplink(main);
    })
  );
}

// ---------------- 证书查看弹窗 ----------------
function showCertModal(certPem, keyPem) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box">
      <h3>证书内容</h3>
      <label>证书（Certificate）</label>
      <textarea id="certText" readonly>${certPem || ""}</textarea>
      <label>私钥（Private Key）</label>
      <textarea id="keyText" readonly>${keyPem || ""}</textarea>
      <div class="modal-actions">
        <button class="secondary" id="copyCertBtn">复制证书</button>
        <button class="secondary" id="copyKeyBtn">复制私钥</button>
        <button id="closeCertModalBtn">关闭</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);

  const copy = async (text, label) => {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${label}已复制到剪贴板`, "success");
    } catch {
      // 部分浏览器/非HTTPS环境剪贴板API不可用，退化为手动选中
      toast(`自动复制失败，请手动选中${label}文本框内容复制`, "error");
    }
  };
  document.getElementById("copyCertBtn").onclick = () => copy(certPem || "", "证书");
  document.getElementById("copyKeyBtn").onclick = () => copy(keyPem || "", "私钥");
  document.getElementById("closeCertModalBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => {
    if (e.target === overlay) overlay.remove();
  };
}

// ---------------- 工具箱 ----------------
async function renderTools(main) {
  main.innerHTML = `
    <div class="card">
      <h3>DNS 查询</h3>
      <input id="dnsLookupDomain" placeholder="example.com" />
      <select id="dnsLookupType">
        <option>A</option><option>AAAA</option><option>CNAME</option><option>TXT</option><option>MX</option><option>NS</option><option>SOA</option>
      </select>
      <button id="dnsLookupBtn">查询</button>
      <div id="dnsLookupResult" style="margin-top:10px"></div>
    </div>
    <div class="card">
      <h3>Whois 查询</h3>
      <input id="whoisDomain" placeholder="example.com" />
      <button id="whoisBtn">查询</button>
      <div id="whoisResult" style="margin-top:10px"></div>
    </div>
    <div class="card">
      <h3>网站证书检查</h3>
      <p style="color:var(--muted);font-size:13px;margin-top:-6px">基于 Certificate Transparency 公开日志（crt.sh）查询该域名最近签发过的证书记录</p>
      <input id="certCheckDomain" placeholder="example.com" />
      <button id="certCheckBtn">查询</button>
      <div id="certCheckResult" style="margin-top:10px"></div>
    </div>`;

  document.getElementById("dnsLookupBtn").onclick = async () => {
    const domain = document.getElementById("dnsLookupDomain").value.trim();
    const type = document.getElementById("dnsLookupType").value;
    const resultEl = document.getElementById("dnsLookupResult");
    if (!domain) return toast("请输入域名", "error");
    resultEl.innerHTML = "查询中...";
    try {
      const data = await api(`/tools/dns-lookup?domain=${encodeURIComponent(domain)}&type=${type}`);
      resultEl.innerHTML = data.answers.length
        ? `<table><tr><th>名称</th><th>类型</th><th>TTL</th><th>值</th></tr>${data.answers
            .map((a) => `<tr><td>${a.name}</td><td>${a.type}</td><td>${a.ttl}</td><td>${a.data}</td></tr>`)
            .join("")}</table>`
        : `<p style="color:var(--muted)">未查询到记录</p>`;
    } catch (e) {
      resultEl.innerHTML = `<p style="color:red">${e.message}</p>`;
    }
  };

  document.getElementById("whoisBtn").onclick = async () => {
    const domain = document.getElementById("whoisDomain").value.trim();
    const resultEl = document.getElementById("whoisResult");
    if (!domain) return toast("请输入域名", "error");
    resultEl.innerHTML = "查询中...";
    try {
      const data = await api(`/tools/whois?domain=${encodeURIComponent(domain)}`);
      resultEl.innerHTML = `<table>
        <tr><th>注册商</th><td>${data.registrar || "-"}</td></tr>
        <tr><th>注册时间</th><td>${data.registeredAt || "-"}</td></tr>
        <tr><th>到期时间</th><td>${data.expiresAt || "-"}</td></tr>
        <tr><th>最近更新</th><td>${data.updatedAt || "-"}</td></tr>
        <tr><th>域名状态</th><td>${(data.status || []).join(", ") || "-"}</td></tr>
        <tr><th>DNS服务器</th><td>${(data.nameservers || []).join(", ") || "-"}</td></tr>
      </table>`;
    } catch (e) {
      resultEl.innerHTML = `<p style="color:red">${e.message}</p>`;
    }
  };

  document.getElementById("certCheckBtn").onclick = async () => {
    const domain = document.getElementById("certCheckDomain").value.trim();
    const resultEl = document.getElementById("certCheckResult");
    if (!domain) return toast("请输入域名", "error");
    resultEl.innerHTML = "查询中...";
    try {
      const data = await api(`/tools/cert-check?domain=${encodeURIComponent(domain)}`);
      resultEl.innerHTML = data.certificates.length
        ? `<table><tr><th>通用名称</th><th>颁发机构</th><th>生效时间</th><th>失效时间</th></tr>${data.certificates
            .map((c) => `<tr><td>${c.commonName}</td><td>${c.issuer}</td><td>${c.notBefore}</td><td>${c.notAfter}</td></tr>`)
            .join("")}</table>`
        : `<p style="color:var(--muted)">未查询到相关证书记录</p>`;
    } catch (e) {
      resultEl.innerHTML = `<p style="color:red">${e.message}</p>`;
    }
  };
}

// ---------------- MiSub 订阅管理 ----------------
const MISUB_ICONS = {
  eye: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>`,
  qrcode: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M14 14h3v3h-3zM20 14v3M14 20h3M20 20v.01"/></svg>`,
  edit: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>`,
  trash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg>`,
  bolt: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/></svg>`,
  copy: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
};

const PROTO_COLORS = {
  vmess: "#16a34a", vless: "#2563eb", trojan: "#dc2626", ss: "#d97706", ssr: "#d97706", hysteria2: "#7c3aed", hysteria: "#7c3aed", tuic: "#0891b2",
};

let misubNodeGroupFilter = "全部";
let misubDomain = null;

async function renderMisub(main) {
  main.innerHTML = `
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h3>我的订阅组 <span id="profileCount" style="color:var(--muted);font-weight:400;font-size:14px"></span></h3>
        <button id="createProfileBtn">新增</button>
      </div>
      <p style="color:var(--muted);font-size:13px;margin-top:-4px">把手动节点自由组合，生成一条对外的订阅链接，卡片可拖动排序。</p>
      <div id="profileGrid" class="misub-grid-profiles" style="margin-top:10px">加载中...</div>
    </div>

    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <h3>手动节点 <span id="nodeCount" style="color:var(--muted);font-weight:400;font-size:14px"></span></h3>
        <div>
          <button class="secondary" id="importSubAsNodesBtn">订阅导入</button>
          <button id="addNodeBtn">新增</button>
        </div>
      </div>
      <div class="misub-group-tabs" id="nodeGroupTabs" style="margin-top:10px"></div>
      <div id="nodeGrid" class="misub-grid-nodes">加载中...</div>
      <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
        <label><input type="checkbox" id="selectAllNodes" /> 全选</label>
        <button class="danger" id="batchDeleteNodesBtn" style="margin-left:6px">批量删除</button>
      </div>
    </div>`;

  try {
    misubDomain = (await api("/misub/settings")).domain;
  } catch {
    misubDomain = null;
  }
  await loadMisubProfiles();
  await loadMisubNodes();

  document.getElementById("createProfileBtn").onclick = () => showMisubProfileModal();
  document.getElementById("addNodeBtn").onclick = () => showAddNodeModal();
  document.getElementById("importSubAsNodesBtn").onclick = () => showImportSubAsNodesModal();
}

// ---------------- 订阅域名设置（独立页面，在「系统设置」里） ----------------
async function renderMisubDomainSettings(main) {
  main.innerHTML = `<div class="card" style="max-width:560px">
    <h3>订阅域名设置</h3>
    <div id="misubDomainBody">加载中...</div>
  </div>`;
  await loadMisubDomainSetting(main);
}

async function loadMisubDomainSetting(main) {
  const { domain } = await api("/misub/settings");
  misubDomain = domain;
  const body = document.getElementById("misubDomainBody");
  const isAdmin = state.user.role === "admin";

  body.innerHTML = `
    <p style="color:var(--muted);font-size:14px">
      MiSub 订阅链接默认用当前Worker的地址。想用自己的短域名（比如 <code>sub.你的域名.com</code>），
      要先去 <b>Cloudflare Dashboard → Workers & Pages → 这个Worker → Settings → Domains & Routes → Add Custom Domain</b>
      绑定一个你名下、DNS托管在Cloudflare上的域名，绑定成功后把同一个域名填在下面，订阅链接就会用这个域名了。
    </p>
    ${
      isAdmin
        ? `<input id="misubDomainInput" placeholder="例如 sub.example.com" value="${domain || ""}" style="width:280px" />
           <button id="saveMisubDomainBtn">保存</button>`
        : domain
        ? `<p>当前订阅域名：<b>${domain}</b></p>`
        : `<p style="color:var(--muted)">管理员还没有配置订阅域名，暂时用Worker默认地址</p>`
    }`;

  if (isAdmin) {
    document.getElementById("saveMisubDomainBtn").onclick = async () => {
      const value = document.getElementById("misubDomainInput").value.trim();
      try {
        await api("/misub/settings", { method: "PUT", body: { domain: value } });
        toast("已保存", "success");
        loadMisubDomainSetting(main);
      } catch (e) {
        toast(e.message, "error");
      }
    };
  }
}

function misubProfileLink(profile) {
  const base = misubDomain ? `https://${misubDomain}` : API || location.origin;
  return `${base}/${profile.custom_id || profile.share_token}`;
}

// ---------------- 订阅组卡片 ----------------
async function loadMisubProfiles() {
  const profiles = await api("/misub/profiles");
  document.getElementById("profileCount").textContent = profiles.length ? `${profiles.length}` : "";
  const grid = document.getElementById("profileGrid");

  if (!profiles.length) {
    grid.innerHTML = `<p style="color:var(--muted)">还没有订阅组，点右上角"新增"创建一个</p>`;
    return;
  }

  grid.innerHTML = profiles
    .map((p) => {
      const link = misubProfileLink(p);
      const nodeCount = JSON.parse(p.node_ids || "[]").length;
      return `<div class="misub-card" draggable="true" data-id="${p.id}">
        <div class="misub-card-head">
          <div class="misub-card-title">${p.name}</div>
          <div class="misub-card-icons">
            <span class="showQr" data-link="${link}" title="二维码">${MISUB_ICONS.qrcode}</span>
            <span class="editProfile" data-id="${p.id}" title="编辑">${MISUB_ICONS.edit}</span>
            <span class="delProfile" data-id="${p.id}" title="删除">${MISUB_ICONS.trash}</span>
          </div>
        </div>
        <div class="misub-card-sub">${nodeCount} 个节点</div>
        <div class="misub-toggle-row">
          <span>启用状态</span>
          <label class="switch"><input type="checkbox" class="toggleProfileEnabled" data-id="${p.id}" ${p.enabled ? "checked" : ""} /><span class="slider"></span></label>
        </div>
        <div class="misub-link-row">
          <span class="value-cell" style="max-width:none;flex:1;font-size:13px;color:var(--muted)">${link}</span>
          <span class="copyProfileLink" data-link="${link}" title="复制链接">${MISUB_ICONS.copy}</span>
        </div>
      </div>`;
    })
    .join("");

  grid.querySelectorAll(".toggleProfileEnabled").forEach(
    (cb) => (cb.onchange = () => api(`/misub/profiles/${cb.dataset.id}`, { method: "PUT", body: { enabled: cb.checked } }))
  );
  grid.querySelectorAll(".copyProfileLink").forEach((el) => (el.onclick = () => copyMisubLink(el.dataset.link)));
  grid.querySelectorAll(".showQr").forEach((el) => (el.onclick = () => showQrModal(el.dataset.link)));
  grid.querySelectorAll(".editProfile").forEach((el) => (el.onclick = () => showMisubProfileModal(Number(el.dataset.id))));
  grid.querySelectorAll(".delProfile").forEach(
    (el) => (el.onclick = async () => {
      if (!confirm("确认删除该订阅组？对应的订阅链接会立即失效。")) return;
      await api(`/misub/profiles/${el.dataset.id}`, { method: "DELETE" });
      loadMisubProfiles();
    })
  );

  enableDragReorder(grid, ".misub-card", async (orderedIds) => {
    await api("/misub/profiles/reorder", { method: "PUT", body: { orderedIds: orderedIds.map(Number) } });
  });
}

async function copyMisubLink(link) {
  try {
    await navigator.clipboard.writeText(link);
    toast("链接已复制", "success");
  } catch {
    toast("复制失败，请手动选中复制", "error");
  }
}

function showQrModal(link) {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:280px;text-align:center">
      <h3>订阅二维码</h3>
      <img src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(link)}" width="220" height="220" style="border-radius:8px" />
      <p style="font-size:13px;color:var(--muted);word-break:break-all;margin-top:10px">${link}</p>
      <div class="modal-actions" style="justify-content:center">
        <button class="secondary" id="copyQrLinkBtn">复制链接</button>
        <button id="closeQrBtn">关闭</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("copyQrLinkBtn").onclick = () => copyMisubLink(link);
  document.getElementById("closeQrBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
}

/** 新建/编辑分组弹窗：右侧"已选节点"支持拖拽排序，顺序决定生成的订阅链接里节点的先后顺序 */
async function showMisubProfileModal(profileId) {
  const [nodes, profiles] = await Promise.all([api("/misub/nodes"), profileId ? api("/misub/profiles") : []]);
  const existing = profileId ? profiles.find((p) => p.id === profileId) : null;
  let selectedIds = existing ? JSON.parse(existing.node_ids).filter((id) => nodes.some((n) => n.id === id)) : [];
  const nodeById = Object.fromEntries(nodes.map((n) => [n.id, n]));

  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:560px">
      <h3>${profileId ? "编辑订阅组" : "新建订阅组"}</h3>
      <input id="profileName" placeholder="分组名称" value="${existing ? existing.name : ""}" style="width:100%" />
      <input id="profileCustomId" placeholder="自定义ID（可选，3-32位字母数字，不填则用随机生成）" value="${existing ? existing.custom_id || "" : ""}" style="width:100%;margin-top:6px" />
      <div style="display:flex;gap:12px;margin-top:10px">
        <div style="flex:1">
          <label style="font-size:14px;color:var(--muted)">可选节点（点击加入）</label>
          <div id="availableNodesList" style="max-height:38vh;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:6px;margin-top:4px"></div>
        </div>
        <div style="flex:1">
          <label style="font-size:14px;color:var(--muted)">已选节点（可拖动排序，决定订阅链接里的先后顺序）</label>
          <div id="selectedNodesList" style="max-height:38vh;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:6px;margin-top:4px"></div>
        </div>
      </div>
      <div class="modal-actions">
        <button class="secondary" id="cancelProfileBtn">取消</button>
        <button id="saveProfileBtn">保存</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("cancelProfileBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  function renderAvailable() {
    const el = overlay.querySelector("#availableNodesList");
    const remaining = nodes.filter((n) => !selectedIds.includes(n.id));
    el.innerHTML = remaining.length
      ? remaining.map((n) => `<div class="misub-pick-row" data-id="${n.id}">+ ${n.name || n.url}</div>`).join("")
      : `<p style="font-size:13px;color:var(--muted);padding:4px">没有更多可选节点了</p>`;
    el.querySelectorAll(".misub-pick-row").forEach(
      (row) => (row.onclick = () => {
        selectedIds.push(Number(row.dataset.id));
        renderAvailable();
        renderSelected();
      })
    );
  }

  function renderSelected() {
    const el = overlay.querySelector("#selectedNodesList");
    el.innerHTML = selectedIds.length
      ? selectedIds
          .map((id) => `<div class="misub-pick-row selected" draggable="true" data-id="${id}">⠿ ${nodeById[id] ? nodeById[id].name || nodeById[id].url : "（节点已被删除）"} <span class="removePick" data-id="${id}" style="float:right;cursor:pointer">✕</span></div>`)
          .join("")
      : `<p style="font-size:13px;color:var(--muted);padding:4px">还没有选节点，从左边点击加入</p>`;
    el.querySelectorAll(".removePick").forEach(
      (btn) => (btn.onclick = (e) => {
        e.stopPropagation();
        selectedIds = selectedIds.filter((id) => id !== Number(btn.dataset.id));
        renderAvailable();
        renderSelected();
      })
    );
    enableDragReorder(el, ".misub-pick-row.selected", (orderedIds) => {
      selectedIds = orderedIds.map(Number);
    });
  }

  renderAvailable();
  renderSelected();

  document.getElementById("saveProfileBtn").onclick = async () => {
    const name = document.getElementById("profileName").value;
    const customId = document.getElementById("profileCustomId").value.trim();
    if (!name) return toast("请填写分组名称", "error");
    try {
      if (profileId) {
        await api(`/misub/profiles/${profileId}`, { method: "PUT", body: { name, nodeIds: selectedIds, customId } });
      } else {
        await api("/misub/profiles", { method: "POST", body: { name, nodeIds: selectedIds, customId } });
      }
      toast("保存成功", "success");
      overlay.remove();
      loadMisubProfiles();
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

// ---------------- 手动节点卡片 ----------------
async function loadMisubNodes() {
  const [nodes, groups] = await Promise.all([api("/misub/nodes"), api("/misub/nodes/groups")]);
  document.getElementById("nodeCount").textContent = nodes.length ? `${nodes.length}` : "";

  const tabsEl = document.getElementById("nodeGroupTabs");
  const tabs = ["全部", "未分组", ...groups];
  tabsEl.innerHTML = tabs
    .map((g) => `<span class="misub-group-tab ${g === misubNodeGroupFilter ? "active" : ""}" data-g="${g}">${g}</span>`)
    .join("");
  tabsEl.querySelectorAll(".misub-group-tab").forEach(
    (tab) => (tab.onclick = () => {
      misubNodeGroupFilter = tab.dataset.g;
      tabsEl.querySelectorAll(".misub-group-tab").forEach((t) => t.classList.toggle("active", t === tab));
      renderNodeGrid(nodes);
    })
  );

  renderNodeGrid(nodes);

  document.getElementById("selectAllNodes").onchange = (e) => {
    document.querySelectorAll(".nodeCheck").forEach((cb) => (cb.checked = e.target.checked));
  };
  document.getElementById("batchDeleteNodesBtn").onclick = async () => {
    const ids = [...document.querySelectorAll(".nodeCheck:checked")].map((cb) => Number(cb.dataset.id));
    if (!ids.length) return toast("请先勾选", "error");
    if (!confirm(`确认删除这 ${ids.length} 个节点？`)) return;
    await api("/misub/nodes/batch-delete", { method: "POST", body: { ids } });
    toast("已删除", "success");
    loadMisubNodes();
  };
}

function renderNodeGrid(allNodes) {
  const grid = document.getElementById("nodeGrid");
  const filtered = allNodes.filter((n) => {
    if (misubNodeGroupFilter === "全部") return true;
    if (misubNodeGroupFilter === "未分组") return !n.group_name;
    return n.group_name === misubNodeGroupFilter;
  });
  // 只在"全部"视图下才允许拖拽排序：分组筛选下的局部拖拽会把全局排序值搞乱（之前bug的来源），
  // 想调整顺序请先切回"全部"标签
  const draggable = misubNodeGroupFilter === "全部";

  grid.innerHTML = filtered.length
    ? filtered
        .map((n) => {
          const proto = n.url.split("://")[0].toLowerCase();
          const color = PROTO_COLORS[proto] || "#64748b";
          const latencyBadge = n.last_latency_ms
            ? `<span class="chip" style="background:#dcfce7;color:#166534">${n.last_latency_ms}ms</span>`
            : n.last_tested_at
            ? `<span class="chip" style="background:#fee2e2;color:#991b1b">超时</span>`
            : "";
          return `<div class="misub-node-card" draggable="${draggable}" data-id="${n.id}">
            <input type="checkbox" class="nodeCheck" data-id="${n.id}" />
            ${n.group_name ? `<span class="chip">${n.group_name}</span>` : ""}
            <span class="chip proto" style="background:${color}22;color:${color}">${proto.toUpperCase()}</span>
            <span class="node-name" title="${n.url.replace(/"/g, "&quot;")}">${n.name || n.url}</span>
            ${latencyBadge}
            <span class="node-actions">
              <span class="speedtestNode" data-id="${n.id}" title="测速">${MISUB_ICONS.bolt}</span>
              <span class="editNode" data-node='${JSON.stringify(n).replace(/'/g, "&apos;")}' title="编辑">${MISUB_ICONS.edit}</span>
              <span class="delNode" data-id="${n.id}" title="删除">${MISUB_ICONS.trash}</span>
            </span>
          </div>`;
        })
        .join("")
    : `<p style="color:var(--muted)">暂无节点</p>`;

  grid.querySelectorAll(".speedtestNode").forEach(
    (el) => (el.onclick = async () => {
      const original = el.innerHTML;
      el.innerHTML = "…";
      try {
        const r = await api(`/misub/nodes/${el.dataset.id}/speedtest`, { method: "POST" });
        toast(r.ok ? `延迟 ${r.latency}ms` : `测速失败: ${r.error}`, r.ok ? "success" : "error");
      } catch (e) {
        toast(e.message, "error");
      }
      el.innerHTML = original;
      loadMisubNodes();
    })
  );
  grid.querySelectorAll(".editNode").forEach(
    (el) => (el.onclick = () => showAddNodeModal(JSON.parse(el.dataset.node.replace(/&apos;/g, "'"))))
  );
  grid.querySelectorAll(".delNode").forEach(
    (el) => (el.onclick = async () => {
      if (!confirm("确认删除该节点？")) return;
      await api("/misub/nodes/batch-delete", { method: "POST", body: { ids: [Number(el.dataset.id)] } });
      loadMisubNodes();
    })
  );

  if (draggable) {
    enableDragReorder(grid, ".misub-node-card", async (orderedIds) => {
      await api("/misub/nodes/reorder", { method: "PUT", body: { orderedIds: orderedIds.map(Number) } });
    });
  }
}

/** 新增/编辑手动节点弹窗：支持单条编辑，也支持多行粘贴批量导入 */
async function showAddNodeModal(editingNode) {
  const groups = await api("/misub/nodes/groups");
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:480px">
      <h3>${editingNode ? "编辑节点" : "新增手动节点"}</h3>
      <p style="color:var(--muted);font-size:13px;margin-top:-6px">${editingNode ? "" : "支持单条编辑，也支持多行粘贴后批量导入节点。"}</p>
      <div style="display:flex;gap:8px;margin-top:6px">
        <input id="nodeNameInput" placeholder="节点名称（可选）" value="${editingNode ? (editingNode.name || "").replace(/"/g, "&quot;") : ""}" style="flex:1" />
        <input id="nodeGroupInput" placeholder="分组（可选，可输入新分组名）" list="nodeGroupOptions" value="${editingNode ? editingNode.group_name || "" : ""}" style="flex:1" />
        <datalist id="nodeGroupOptions">${groups.map((g) => `<option value="${g}">`).join("")}</datalist>
      </div>
      <textarea id="nodeUrlInput" placeholder="输入单个链接，或粘贴多行链接批量导入..." style="width:100%;min-height:160px;font-family:monospace;font-size:13px;margin-top:8px">${editingNode ? editingNode.url : ""}</textarea>
      <div class="modal-actions">
        <button class="secondary" id="cancelNodeBtn">取消</button>
        <button id="saveNodeBtn">确认</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  document.getElementById("cancelNodeBtn").onclick = () => overlay.remove();
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  document.getElementById("saveNodeBtn").onclick = async () => {
    const name = document.getElementById("nodeNameInput").value;
    const group = document.getElementById("nodeGroupInput").value;
    const text = document.getElementById("nodeUrlInput").value;
    if (!text.trim()) return toast("请输入节点链接", "error");
    try {
      if (editingNode) {
        await api(`/misub/nodes/${editingNode.id}`, { method: "PUT", body: { name, url: text.trim(), group, enabled: true } });
      } else {
        const r = await api("/misub/nodes", { method: "POST", body: { name, group, text } });
        toast(`已导入 ${r.imported} 个节点`, "success");
      }
      overlay.remove();
      loadMisubNodes();
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

/** 把外部订阅地址的内容直接拍平导入成一批手动节点 */
function showImportSubAsNodesModal() {
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.innerHTML = `
    <div class="modal-box" style="width:520px">
      <h3>订阅导入为节点</h3>
      <p style="color:var(--muted);font-size:13px;margin-top:-6px" id="importSubHint">拉取该订阅地址的内容，提取出节点后勾选要导入的（一次性导入，之后跟原订阅没有关联，订阅更新不会自动同步）。</p>
      <div id="importSubStep1">
        <input id="importSubUrl" placeholder="订阅地址 https://..." style="width:100%;margin-top:6px" />
        <div class="modal-actions">
          <button class="secondary" id="cancelImportSubBtn">取消</button>
          <button id="extractSubBtn">提取节点</button>
        </div>
      </div>
      <div id="importSubStep2" style="display:none">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
          <label><input type="checkbox" id="selectAllPreview" checked /> 全选（共 <span id="previewCount">0</span> 个）</label>
          <button class="secondary" id="speedtestAllBtn">全部测速</button>
        </div>
        <div id="previewNodesList" style="max-height:40vh;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:6px;margin-top:6px"></div>
        <input id="importSubGroup" placeholder="导入到分组（可选）" style="width:100%;margin-top:8px" />
        <div class="modal-actions">
          <button class="secondary" id="backToStep1Btn">上一步</button>
          <button id="confirmImportSubBtn">导入选中节点</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
  document.getElementById("cancelImportSubBtn").onclick = () => overlay.remove();

  let previewItems = [];

  document.getElementById("extractSubBtn").onclick = async () => {
    const url = document.getElementById("importSubUrl").value.trim();
    if (!url) return toast("请填写订阅地址", "error");
    const btn = document.getElementById("extractSubBtn");
    btn.textContent = "提取中...";
    btn.disabled = true;
    try {
      const r = await api("/misub/nodes/preview-subscription", { method: "POST", body: { url } });
      if (r.error) {
        toast(r.error, "error");
        return;
      }
      previewItems = r.items.map((it) => ({ ...it, latency: null }));
      renderPreviewList();
      document.getElementById("importSubStep1").style.display = "none";
      document.getElementById("importSubStep2").style.display = "block";
      document.getElementById("importSubHint").textContent = `提取到 ${previewItems.length} 个节点，勾选要导入的，也可以先全部测速看看哪些能连上。`;
    } catch (e) {
      toast(e.message, "error");
    } finally {
      btn.textContent = "提取节点";
      btn.disabled = false;
    }
  };

  document.getElementById("backToStep1Btn").onclick = () => {
    document.getElementById("importSubStep1").style.display = "block";
    document.getElementById("importSubStep2").style.display = "none";
  };

  function renderPreviewList() {
    document.getElementById("previewCount").textContent = previewItems.length;
    const el = document.getElementById("previewNodesList");
    el.innerHTML = previewItems
      .map(
        (it, i) => `<div class="misub-pick-row" style="display:flex;align-items:center;gap:6px;cursor:default">
          <input type="checkbox" class="previewCheck" data-i="${i}" checked />
          <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${it.name}</span>
          <span class="previewLatency" data-i="${i}" style="font-size:13px;color:var(--muted);flex-shrink:0">${
            it.latency === null ? "" : it.latency === "timeout" ? "超时" : `${it.latency}ms`
          }</span>
        </div>`
      )
      .join("");
  }

  document.getElementById("selectAllPreview").onchange = (e) => {
    overlay.querySelectorAll(".previewCheck").forEach((cb) => (cb.checked = e.target.checked));
  };

  document.getElementById("speedtestAllBtn").onclick = async () => {
    const btn = document.getElementById("speedtestAllBtn");
    btn.textContent = "测速中...";
    btn.disabled = true;
    // 逐个测，避免同时发太多并发TCP连接
    for (let i = 0; i < previewItems.length; i++) {
      try {
        const r = await api("/misub/speedtest-url", { method: "POST", body: { url: previewItems[i].url } });
        previewItems[i].latency = r.ok ? r.latency : "timeout";
      } catch {
        previewItems[i].latency = "timeout";
      }
      const badge = overlay.querySelector(`.previewLatency[data-i="${i}"]`);
      if (badge) badge.textContent = previewItems[i].latency === "timeout" ? "超时" : `${previewItems[i].latency}ms`;
    }
    btn.textContent = "全部测速";
    btn.disabled = false;
    toast("测速完成", "success");
  };

  document.getElementById("confirmImportSubBtn").onclick = async () => {
    const checkedIdx = [...overlay.querySelectorAll(".previewCheck:checked")].map((cb) => Number(cb.dataset.i));
    if (!checkedIdx.length) return toast("请至少勾选一个节点", "error");
    const items = checkedIdx.map((i) => ({ name: previewItems[i].name, url: previewItems[i].url }));
    const group = document.getElementById("importSubGroup").value;
    try {
      const r = await api("/misub/nodes/import-selected", { method: "POST", body: { items, group } });
      toast(`已导入 ${r.imported} 个节点`, "success");
      overlay.remove();
      loadMisubNodes();
    } catch (e) {
      toast(e.message, "error");
    }
  };
}

// ---------------- 通用拖拽排序（HTML5原生拖拽，不依赖第三方库） ----------------
function enableDragReorder(container, itemSelector, onReorder) {
  let dragEl = null;
  container.querySelectorAll(itemSelector).forEach((el) => {
    if (el.getAttribute("draggable") !== "true") return;
    el.addEventListener("dragstart", () => {
      dragEl = el;
      el.classList.add("dragging");
    });
    el.addEventListener("dragend", async () => {
      el.classList.remove("dragging");
      const orderedIds = [...container.querySelectorAll(itemSelector)].map((e) => e.dataset.id);
      await onReorder(orderedIds);
    });
    el.addEventListener("dragover", (e) => {
      e.preventDefault();
      if (!dragEl || dragEl === el) return;
      const rect = el.getBoundingClientRect();
      const after = e.clientY > rect.top + rect.height / 2;
      container.insertBefore(dragEl, after ? el.nextSibling : el);
    });
  });
}

// ---------------- CloudSSH 服务器管理 ----------------
function cssMaskHost(h) {
  const m = (h || "").match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
  return m ? `${m[1]}.${m[2]}.*.*` : h || "";
}
function cssRelTime(ts) {
  if (!ts) return "从未连接";
  const s = ts < 1e12 ? ts : Math.floor(ts / 1000);
  const d = Math.floor(Date.now() / 1000 - s);
  if (d < 60) return "刚刚";
  if (d < 3600) return `${Math.floor(d / 60)} 分钟前`;
  if (d < 86400) return `${Math.floor(d / 3600)} 小时前`;
  return `${Math.floor(d / 86400)} 天前`;
}
function cssEsc(s) {
  return (s == null ? "" : String(s)).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function cssHost() {
  try { return new URL(CLOUDSSH).host; } catch { return CLOUDSSH; }
}

async function renderCloudSSH(main) {
  main.innerHTML = `<div class="card"><h3>CloudSSH 服务器</h3>
    <p style="color:var(--muted);font-size:14px;margin-bottom:12px">服务器数据来自 CloudSSH（${cssEsc(cssHost())}）。点击「连接」会在新标签页打开全屏终端。</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
      <input id="cssSearch" placeholder="按名称、主机或用户名搜索" style="flex:1;min-width:200px" />
      <button class="secondary" id="cssRefresh">刷新</button>
      <button class="secondary" id="cssOpenConsole">打开 CloudSSH 控制台</button>
    </div>
    <div id="cssList">加载中...</div></div>`;

  document.getElementById("cssOpenConsole").onclick = () => window.open(CLOUDSSH, "_blank");
  document.getElementById("cssRefresh").onclick = loadCssServers;
  document.getElementById("cssSearch").oninput = () => {
    const kw = document.getElementById("cssSearch").value.trim().toLowerCase();
    document.querySelectorAll("#cssList .css-card").forEach((card) => {
      card.style.display = !kw || (card.dataset.haystack || "").includes(kw) ? "" : "none";
    });
  };
  await loadCssServers();
}

async function loadCssServers() {
  const el = document.getElementById("cssList");
  if (!el) return;
  el.innerHTML = "加载中...";
  try {
    const r = await fetch(`${CLOUDSSH}/api/servers`, { credentials: "include" });
    if (r.status === 401) {
      el.innerHTML = `<div style="padding:16px;border:1px dashed var(--border);border-radius:8px;text-align:center">
        <p>尚未登录 CloudSSH，请先在新标签页登录（GitHub 账号），登录后回到本页点「刷新」。</p>
        <button class="css-login">去登录 CloudSSH</button></div>`;
      el.querySelector(".css-login").onclick = () => window.open(CLOUDSSH, "_blank");
      return;
    }
    if (!r.ok) throw new Error(`CloudSSH 返回 ${r.status}`);
    const servers = await r.json();
    if (!servers.length) {
      el.innerHTML = `<p style="color:var(--muted)">CloudSSH 里还没有保存服务器，去控制台「添加服务器」后回来刷新。</p>`;
      return;
    }
    el.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px">${
      servers.map((s) => {
        const hay = cssEsc(`${s.name} ${s.host} ${s.username}`.toLowerCase());
        const tags = [s.os, s.region].filter(Boolean)
          .map((t) => `<span class="tag issued" style="font-size:12px">${cssEsc(t)}</span>`).join(" ");
        return `<div class="card css-card" style="margin-bottom:0" data-haystack="${hay}">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
            <b style="font-size:15px">${cssEsc(s.name)}</b>
            <button class="css-connect secondary" data-id="${Number(s.id)}" data-name="${cssEsc(s.name)}">连接</button>
          </div>
          <div style="color:var(--muted);font-size:13px;margin-top:6px">${cssEsc(cssMaskHost(s.host))}:${cssEsc(s.port || 22)} · ${cssEsc(s.username || "")}</div>
          <div style="margin-top:8px">${tags}<span style="color:var(--muted);font-size:12px;margin-left:6px">最近连接 ${cssRelTime(s.last_connected_at)}</span></div>
        </div>`;
      }).join("")
    }</div>`;

    el.querySelectorAll(".css-connect").forEach((btn) => (btn.onclick = () => cssConnect(btn.dataset.id, btn.dataset.name)));
  } catch (e) {
    el.innerHTML = `<p style="color:red">加载失败：${cssEsc(e.message)}。<br/>
      <span style="color:var(--muted);font-size:13px">若提示 Failed to fetch：请确认 CloudSSH 的 CORS 补丁已部署、CORS_ALLOWED_ORIGINS 已配置、且你已在浏览器登录过 CloudSSH。</span></p>`;
  }
}

async function cssConnect(id, name) {
  // 先同步开窗，避免 await 之后 window.open 被浏览器弹窗拦截
  const win = window.open("", "_blank");
  try {
    const r = await fetch(`${CLOUDSSH}/api/servers/${id}/connect`, {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" }, body: "{}",
    });
    if (r.status === 401) {
      win && win.close();
      toast("请先登录 CloudSSH", "error");
      window.open(CLOUDSSH, "_blank");
      return;
    }
    if (!r.ok) throw new Error(`连接请求失败（${r.status}）`);
    const { wsUrl } = await r.json();
    const url = `${CLOUDSSH}/?wsUrl=${encodeURIComponent(wsUrl)}&name=${encodeURIComponent(name || "Server")}`;
    if (win) win.location.href = url; else window.open(url, "_blank");
  } catch (e) {
    win && win.close();
    toast(e.message, "error");
  }
}

// ---------------- 渲染入口 ----------------
async function render() {
  if (!state.token) {
    renderLogin();
    return;
  }
  if (!state.user) {
    try {
      const me = await api("/auth/me");
      state.user = { id: me.id, username: me.username, role: me.role };
      localStorage.setItem("dnsmgr_user", JSON.stringify(state.user));
    } catch (e) {
      logout();
      return;
    }
  }
  renderShell();
}

render();
