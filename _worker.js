export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. 绑定 R2 存储桶，严格隔离 ASSETS
    let bucket = env.BUCKET || env.MY_BUCKET || env.R2 || env.R2_BUCKET || env.PAN || env.FILES || env.FILE_BUCKET;
    if (!bucket) {
      for (const [k, v] of Object.entries(env)) {
        if (k !== "ASSETS" && v && typeof v.list === "function" && typeof v.get === "function") {
          bucket = v;
          break;
        }
      }
    }

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, x-license-key, Range",
      "Referrer-Policy": "strict-origin-when-cross-origin"
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    function jsonResponse(data, status = 200) {
      return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8" } });
    }

    // 🌟 卡密核心加密校验算法 (HMAC-SHA256)
    const SECRET_KEY = env.LICENSE_SECRET || "YINJI_SECRET_888";
    
    async function verifyLicenseKey(key) {
      if (!key || !key.startsWith("YJ-")) return null;
      const parts = key.split("-");
      if (parts.length !== 4) return null;
      
      const days = parseInt(parts[1], 10);
      const timestamp = parseInt(parts[2], 10);
      const sig = parts[3];

      const maxRedeemWindow = timestamp + (365 * 24 * 60 * 60 * 1000);
      if (Date.now() > maxRedeemWindow) return null;

      const encoder = new TextEncoder();
      const data = encoder.encode(`${days}-${timestamp}`);
      const keyMaterial = await crypto.subtle.importKey("raw", encoder.encode(SECRET_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const hashBuffer = await crypto.subtle.sign("HMAC", keyMaterial, data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const expectedSig = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16).toUpperCase();

      if (sig !== expectedSig) return null;
      return { days, timestamp };
    }

    async function getSystemLicenseRecord() {
      if (!bucket) return { licensed: false, expireAt: 0, usedKeys: [] };
      try {
        const configObj = await bucket.get("_config/license.json");
        if (!configObj) return { licensed: false, expireAt: 0, usedKeys: [] };
        const data = JSON.parse(await configObj.text());
        const expireAt = Number(data.expireAt) || 0;
        return {
          licensed: Date.now() < expireAt,
          expireAt,
          usedKeys: Array.isArray(data.usedKeys) ? data.usedKeys : []
        };
      } catch (_) {
        return { licensed: false, expireAt: 0, usedKeys: [] };
      }
    }

    function extractTitleFromHtml(html) {
      if (!html) return "";
      const match = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      return match ? match[1].trim() : "";
    }

    /* ==========================================================
       🌐 1. 公开短链单页访问 (/p/:slug) - 全局到期双向封锁守卫
    ========================================================== */
    if (url.pathname.startsWith("/p/")) {
      const rawSlug = url.pathname.slice(3).replace(/\/+$/, "").trim();
      if (!rawSlug || !bucket) return new Response("Page Not Found", { status: 404 });

      // 🌟 核心双向封锁机制：检查全局授权状态
      const sysRecord = await getSystemLicenseRecord();
      if (!sysRecord.licensed) {
        // 未授权或已到期，直接熔断 R2 读取，返回高奢版封存提示页
        return new Response(`
          <!DOCTYPE html>
          <html lang="zh-CN">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
            <title>时空已封存 - 印记</title>
            <style>
              body { font-family: -apple-system, sans-serif; background: #020617; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 20px;}
              .box { text-align: center; background: rgba(15, 23, 42, 0.88); padding: 40px 30px; border-radius: 24px; border: 1.5px solid rgba(245, 158, 11, 0.4); box-shadow: 0 20px 60px rgba(0,0,0,0.8); max-width: 400px; width: 100%; backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
              h1 { font-size: 22px; color: #f8fafc; margin: 0 0 12px; letter-spacing: 1px; font-weight: 900; }
              p { font-size: 14px; color: #94a3b8; margin-bottom: 26px; line-height: 1.7; }
              button { background: linear-gradient(135deg, #f59e0b, #d97706); color: #fff; border: none; padding: 14px 24px; border-radius: 12px; font-weight: 800; font-size: 15px; cursor: pointer; box-shadow: 0 6px 16px rgba(245, 158, 11, 0.3); transition: all 0.2s ease; width: 100%; }
              button:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(245, 158, 11, 0.4); }
              #wx { display: none; margin-top: 24px; animation: fadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1); }
              img { width: 100%; max-width: 200px; border-radius: 12px; border: 4px solid #fff; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
              @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
            </style>
          </head>
          <body>
            <div class="box">
              <div style="font-size: 48px; margin-bottom: 16px; filter: drop-shadow(0 4px 8px rgba(0,0,0,0.5));">🔐</div>
              <h1>专属时空已封存</h1>
              <p>很抱歉，当前专属网页的服务授权已到达终点。<br>核心数据已被安全冻结保护。</p>
              <button onclick="document.getElementById('wx').style.display='block'">💬 联系管理员续费解锁</button>
              <div id="wx">
                <!-- 🌟 核心防裂图修复：动态相对路径与绝对路径双重兜底 -->
                <img src="../微信二维码.jpg" onerror="this.onerror=null; this.src='/微信二维码.jpg';" alt="微信咨询">
                <p style="font-size:12px; color:#cbd5e1; margin-top:12px; margin-bottom:0;">长按或扫码添加客服获取卡密</p>
              </div>
            </div>
          </body>
          </html>
        `, { status: 403, headers: { "Content-Type": "text/html; charset=utf-8" } });
      }

      const slug = rawSlug.toLowerCase();
      const object = await bucket.get(`_pages/${slug}.html`);
      if (!object) return new Response("Page Not Found", { status: 404 });

      const pageMeta = object.customMetadata || {};
      const requiredPassword = pageMeta.password;
      const clientPass = url.searchParams.get("pwd") || request.headers.get("x-page-password");

      if (requiredPassword && clientPass !== requiredPassword) {
        return new Response(`
          <!DOCTYPE html>
          <html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>私密验证 - 印记</title>
          <style>body{background:#0f172a;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;} .card{background:#1e293b;border:1px solid #f59e0b;padding:30px;border-radius:20px;text-align:center;color:#fff;} input{padding:10px;border-radius:8px;border:none;margin-bottom:10px;width:80%;text-align:center;} button{background:#f59e0b;border:none;padding:10px 20px;border-radius:8px;color:#fff;font-weight:bold;cursor:pointer;}</style></head>
          <body><div class="card"><h2>🔒 访问受限</h2><p>请输入密码继续浏览</p><form onsubmit="event.preventDefault(); location.href = location.pathname + '?pwd=' + encodeURIComponent(document.getElementById('p').value);"><input type="password" id="p" required autofocus><br><button type="submit">解锁空间</button></form></div></body></html>
        `, { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } });
      }

      const htmlBody = await object.text();
      return new Response(htmlBody, { status: 200, headers: { ...corsHeaders, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400" } });
    }

    /* ==========================================================
       🛠️ 2. API 接口区
    ========================================================== */
    try {
      if (url.pathname === "/api/auth/verify" && request.method === "POST") {
        if (!bucket) return jsonResponse({ valid: false, error: "未绑定存储空间" }, 500);
        const { key } = await request.json();
        const validData = await verifyLicenseKey(key);
        if (!validData) return jsonResponse({ valid: false, error: "卡密格式错误或已超过兑换保质期" }, 401);

        const currentRec = await getSystemLicenseRecord();
        if (currentRec.usedKeys.includes(key)) {
          return jsonResponse({ valid: false, error: "❌ 该卡密已被核销使用，无法重复充值！" }, 400);
        }

        const baseTimestamp = (currentRec.expireAt > Date.now()) ? currentRec.expireAt : Date.now();
        const addedDuration = validData.days * 24 * 60 * 60 * 1000;
        const newExpireAt = baseTimestamp + addedDuration;

        const updatedUsedKeys = [...currentRec.usedKeys, key];
        await bucket.put("_config/license.json", JSON.stringify({
          expireAt: newExpireAt,
          lastActiveKey: key,
          usedKeys: updatedUsedKeys.slice(-200)
        }));

        return jsonResponse({
          valid: true,
          addedDays: validData.days,
          expireAt: newExpireAt
        });
      }

      // 获取系统状态与用量 (已更新为 21MB)
      if (url.pathname === "/api/system/status" && request.method === "GET") {
        if (!bucket) return jsonResponse({ licensed: false, expireAt: 0, usedStorage: 0, maxStorage: 21 * 1024 * 1024, error: "未绑定存储空间" });
        const record = await getSystemLicenseRecord();
        let usedBytes = 0;
        try {
          const listed = await bucket.list({ prefix: "_pages/" });
          for (const obj of (listed.objects || [])) usedBytes += obj.size;
        } catch (_) {}

        return jsonResponse({
          licensed: record.licensed,
          expireAt: record.expireAt,
          usedStorage: usedBytes,
          maxStorage: 21 * 1024 * 1024
        });
      }

      const currentRec = await getSystemLicenseRecord();
      if (url.pathname.startsWith("/api/page/")) {
        if (!bucket) return jsonResponse({ error: "存储空间未绑定" }, 500);
        if (!currentRec.licensed) {
          return jsonResponse({ error: "系统服务已到期，请先输入有效卡密完成续费" }, 401);
        }

        if (url.pathname === "/api/page/list" && request.method === "GET") {
          const listed = await bucket.list({ prefix: "_pages/", include: ["customMetadata", "httpMetadata"] });
          const pages = [];
          for (const obj of (listed.objects || [])) {
            if (!obj.key.endsWith(".html")) continue;
            const slug = obj.key.slice("_pages/".length, -5);
            const meta = obj.customMetadata || {};
            let displayTitle = slug;
            if (meta.title) { try { displayTitle = decodeURIComponent(meta.title); } catch (_) { displayTitle = meta.title; } }
            pages.push({ slug, title: displayTitle, size: obj.size, date: obj.uploaded ? obj.uploaded.toISOString().split("T")[0] : "-", hasPassword: Boolean(meta.password) });
          }
          pages.sort((a, b) => b.slug.localeCompare(a.slug));
          return jsonResponse({ success: true, pages });
        }

        if (url.pathname === "/api/page/get" && request.method === "GET") {
          const slug = (url.searchParams.get("slug") || "").trim().toLowerCase();
          const object = await bucket.get(`_pages/${slug}.html`);
          if (!object) return jsonResponse({ error: "页面不存在" }, 404);
          const html = await object.text();
          const meta = object.customMetadata || {};
          let title = slug;
          if (meta.title) { try { title = decodeURIComponent(meta.title); } catch (_) { title = meta.title; } }
          return jsonResponse({ success: true, slug, title, password: meta.password || "", html });
        }

        if (url.pathname === "/api/page/publish" && request.method === "POST") {
          const reqData = await request.json();
          const { slug, html, password } = reqData;
          let { title } = reqData;
          if (!html || !html.trim()) return jsonResponse({ error: "HTML 源码不能为空" }, 400);

          let cleanSlug = (slug || "").trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
          if (!cleanSlug) cleanSlug = "p" + Math.random().toString(36).substring(2, 7);

          // 🌟 核心拦截：计算 21MB 存储上限
          const listed = await bucket.list({ prefix: "_pages/" });
          let totalSize = 0;
          for (const obj of listed.objects) {
            if (obj.key !== `_pages/${cleanSlug}.html`) totalSize += obj.size;
          }
          const newSize = new TextEncoder().encode(html).length;
          if (totalSize + newSize > 21 * 1024 * 1024) {
            return jsonResponse({ error: "云端存储空间已达 21MB 上限，请删除旧网页释放空间！" }, 403);
          }

          if (!title || !title.trim()) title = extractTitleFromHtml(html);
          const finalTitle = (title && title.trim()) ? title.trim() : cleanSlug;
          const customMetadata = { title: encodeURIComponent(finalTitle.slice(0, 100)), updatedAt: new Date().toISOString() };
          if (password && password.trim()) customMetadata.password = password.trim();

          await bucket.put(`_pages/${cleanSlug}.html`, html, { httpMetadata: { contentType: "text/html; charset=utf-8" }, customMetadata });
          return jsonResponse({ success: true, slug: cleanSlug, title: finalTitle, url: `/p/${cleanSlug}` });
        }

        if (url.pathname === "/api/page/delete" && request.method === "POST") {
          const { slug } = await request.json();
          if (!slug) return jsonResponse({ error: "缺少 slug 参数" }, 400);
          await bucket.delete(`_pages/${slug.toLowerCase()}.html`);
          return jsonResponse({ success: true });
        }
      }

      if (url.pathname.startsWith("/api/")) {
        return jsonResponse({ error: "API Route Not Found" }, 404);
      }
      
    } catch (err) {
      return jsonResponse({ error: err.message || "服务器处理异常" }, 500);
    }

    return env.ASSETS ? env.ASSETS.fetch(request) : new Response("Not Found", { status: 404 });
  }
};
