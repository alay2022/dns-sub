    // 2. 完成 DNS-01 挑战（两阶段：先写完所有 TXT → 统一等待传播 → 统一通知验证 → 统一轮询结果）
    //    不能"写一个验一个"：CN 和通配符共用 _acme-challenge.<根域> 同名TXT，
    //    串行验证时第一条产生的 DNS 缓存（TTL 内）会让 Let's Encrypt 的 secondary validation
    //    部分视角看不到新写入的第二条 TXT，误判 unauthorized（536677.xyz 失败的根因）
    const createdTxtRecordIds: string[] = [];
    try {
      const tasks: { authzUrl: string; challengeUrl: string; fqdn: string; sub: string; txtValue: string }[] = [];

      // 阶段一：为每个授权写入 TXT（同名多条共存，Cloudflare 等主流平台均支持）
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

      // 阶段二：等待全部 TXT 在公共 DoH 可见——之后任何视角首次查询都会看到完整记录
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