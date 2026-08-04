/**
 * IP 归属地解析与 iprisk 风险检测脚本 (v2 多源容错版)
 * 数据源: ip-api.com → ipapi.is → ipinfo.io 自动 fallback
 * 只缓存成功结果，失败节点下次更新自动重试
 */
async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore;
    const { cache = true, timeout = 6000 } = $arguments || {};

    function countryToEmoji(code) {
        if (!code || code.length !== 2) return '🏳️';
        try {
            return String.fromCodePoint(
                ...code.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0))
            );
        } catch (e) {
            return '🏳️';
        }
    }

    function safeParse(body) {
        try { return JSON.parse(body); } catch (e) { return null; }
    }

    // ===== 源1: ip-api.com (免费免Key, 带 proxy/hosting 标记) =====
    async function viaIpApi(server) {
        const { statusCode, body } = await $.http.get({
            url: `http://ip-api.com/json/${server}?fields=status,countryCode,proxy,hosting,mobile`,
            timeout,
        });
        if (statusCode !== 200) throw new Error(`状态码 ${statusCode}`);
        const d = safeParse(body);
        if (!d || d.status !== 'success') throw new Error(`返回异常: ${String(body).slice(0, 120)}`);
        let score = 0;
        if (d.hosting) score += 30; // 机房/数据中心 IP
        if (d.proxy)   score += 40; // 被标记为代理出口
        if (d.mobile)  score += 10; // 移动运营商 IP
        return { emoji: countryToEmoji(d.countryCode), country: d.countryCode || 'UN', score, source: 'ip-api' };
    }

    // ===== 源2: ipapi.is (HTTPS, 标记最细) =====
    async function viaIpapiIs(server) {
        const { statusCode, body } = await $.http.get({
            url: `https://api.ipapi.is/${server}`,
            timeout,
        });
        if (statusCode !== 200) throw new Error(`状态码 ${statusCode}`);
        const d = safeParse(body);
        if (!d) throw new Error('解析失败');
        let score = 0;
        if (d.is_datacenter) score += 30;
        if (d.is_proxy || d.is_vpn) score += 40;
        if (d.is_tor) score += 50;
        if (d.is_crawler) score += 20;
        if (d.is_mobile) score += 10;
        const cc = d.country_code || (d.location && d.location.country_code);
        return { emoji: countryToEmoji(cc), country: cc || 'UN', score, source: 'ipapi.is' };
    }

    // ===== 源3: ipinfo.io (HTTPS兜底, 只有国家+用org粗判机房) =====
    async function viaIpinfo(server) {
        const { statusCode, body } = await $.http.get({
            url: `https://ipinfo.io/${server}/json`,
            timeout,
        });
        if (statusCode !== 200) throw new Error(`状态码 ${statusCode}`);
        const d = safeParse(body);
        if (!d || !d.country) throw new Error('无国家信息');
        const org = String(d.org || '').toLowerCase();
        const dc = /cloudflare|amazon|aws|google|microsoft|azure|digitalocean|vultr|linode|oracle|ovh|hosting|server|cloud|cdn/.test(org);
        return { emoji: countryToEmoji(d.country), country: d.country, score: dc ? 30 : 0, source: 'ipinfo' };
    }

    async function queryServer(server) {
        for (const fn of [viaIpApi, viaIpapiIs, viaIpinfo]) {
            try {
                const info = await fn(server);
                info.score = Math.min(info.score, 100);
                info.tag = `[风险${info.score}%]`;
                $.info(`[${server}] 查询成功 (源: ${fn.name}), 风险 ${info.score}%`);
                return info;
            } catch (e) {
                $.info(`[${server}] ${fn.name} 失败: ${e.message || e}`);
            }
        }
        $.error(`[${server}] 三个数据源全部失败`);
        return null;
    }

    // 去重 + 读缓存
    const uniqueServers = [...new Set(proxies.map((p) => p.server).filter(Boolean))];
    const infoMap = {};
    const toQuery = [];
    for (const server of uniqueServers) {
        const cached = cache && typeof scriptResourceCache !== 'undefined'
            ? scriptResourceCache.get(`ip_info_v2_${server}`)
            : null;
        if (cached) infoMap[server] = JSON.parse(cached);
        else toQuery.push(server);
    }

    // 分块并发查询 (ip-api 限制 45次/分钟)
    if (toQuery.length > 0) {
        $.info(`需查询 ${toQuery.length} 个独立 IP...`);
        const chunkSize = 5;
        for (let i = 0; i < toQuery.length; i += chunkSize) {
            const chunk = toQuery.slice(i, i + chunkSize);
            await Promise.all(chunk.map(async (server) => {
                const info = await queryServer(server);
                if (info) {
                    infoMap[server] = info;
                    if (cache && typeof scriptResourceCache !== 'undefined') {
                        scriptResourceCache.set(`ip_info_v2_${server}`, JSON.stringify(info));
                    }
                }
            }));
            if (i + chunkSize < toQuery.length) await new Promise((r) => setTimeout(r, 1200));
        }
    }

    // 写入节点名; 全部失败的节点不污染原名
    return proxies.map((p) => {
        const info = infoMap[p.server];
        if (info) {
            p.name = `${info.tag} ${info.emoji} ${info.country} | ${p.name}`;
        }
        return p;
    });
}
