/**
 * IP 归属地 + iprisk 风险检测 (v3 最大兼容版)
 * 源顺序: ip.sb → ipapi.co → ip-api.com → ipinfo.io
 */
async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore;
    const { cache = true } = $arguments || {};

    const EMOJI = (code) => {
        if (!code || code.length !== 2) return '🏳️';
        try {
            return String.fromCodePoint(...code.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0)));
        } catch (e) { return '🏳️'; }
    };
    const parse = (b) => { try { return JSON.parse(b); } catch (e) { return null; } };
    const dcTest = (org) => /cloudflare|cloudfront|amazon|aws|google|microsoft|azure|digitalocean|vultr|linode|oracle|ovh|hetzner|hosting|server|cloud|cdn|datacenter/.test(String(org || '').toLowerCase());

    // 源1: ip.sb (HTTPS, 免Key)
    async function srcIpSb(s) {
        const { statusCode, body } = await $.http.get(`https://api.ip.sb/geoip/${s}`);
        if (statusCode !== 200) throw new Error(`ip.sb 状态码 ${statusCode}`);
        const d = parse(body);
        if (!d || !d.country_code) throw new Error('ip.sb 返回异常');
        return { cc: d.country_code, score: dcTest(d.organization) ? 30 : 0, source: 'ip.sb' };
    }
    // 源2: ipapi.co (HTTPS, 免Key)
    async function srcIpapiCo(s) {
        const { statusCode, body } = await $.http.get(`https://ipapi.co/${s}/json/`);
        if (statusCode !== 200) throw new Error(`ipapi.co 状态码 ${statusCode}`);
        const d = parse(body);
        if (!d || d.error) throw new Error('ipapi.co 返回异常');
        return { cc: d.country_code, score: dcTest(d.org) ? 30 : 0, source: 'ipapi.co' };
    }
    // 源3: ip-api.com (唯一带 proxy/hosting 风险标记的免费源)
    async function srcIpApi(s) {
        const { statusCode, body } = await $.http.get(`http://ip-api.com/json/${s}?fields=status,countryCode,proxy,hosting,mobile`);
        if (statusCode !== 200) throw new Error(`ip-api 状态码 ${statusCode}`);
        const d = parse(body);
        if (!d || d.status !== 'success') throw new Error('ip-api 返回异常');
        let score = 0;
        if (d.hosting) score += 30;
        if (d.proxy) score += 40;
        if (d.mobile) score += 10;
        return { cc: d.countryCode, score, source: 'ip-api' };
    }
    // 源4: ipinfo.io 兜底
    async function srcIpinfo(s) {
        const { statusCode, body } = await $.http.get(`https://ipinfo.io/${s}/json`);
        if (statusCode !== 200) throw new Error(`ipinfo 状态码 ${statusCode}`);
        const d = parse(body);
        if (!d || !d.country) throw new Error('ipinfo 返回异常');
        return { cc: d.country, score: dcTest(d.org) ? 30 : 0, source: 'ipinfo' };
    }

    async function queryServer(server) {
        for (const fn of [srcIpSb, srcIpapiCo, srcIpApi, srcIpinfo]) {
            try {
                const info = await fn(server);
                info.score = Math.min(info.score, 100);
                info.tag = `[风险${info.score}%]`;
                $.info(`[${server}] 成功 (源: ${info.source}) ${info.cc} 风险${info.score}%`);
                return info;
            } catch (e) {
                $.info(`[${server}] ${fn.name} 失败: ${e.message || e}`);
            }
        }
        $.error(`[${server}] 四源全灭`);
        return null;
    }

    const uniqueServers = [...new Set(proxies.map((p) => p.server).filter(Boolean))];
    const infoMap = {};
    const toQuery = [];
    for (const server of uniqueServers) {
        const cached = cache && typeof scriptResourceCache !== 'undefined'
            ? scriptResourceCache.get(`ip_info_v3_${server}`) : null;
        if (cached) infoMap[server] = JSON.parse(cached);
        else toQuery.push(server);
    }

    if (toQuery.length > 0) {
        $.info(`需查询 ${toQuery.length} 个独立 IP...`);
        for (let i = 0; i < toQuery.length; i += 5) {
            const chunk = toQuery.slice(i, i + 5);
            await Promise.all(chunk.map(async (server) => {
                const info = await queryServer(server);
                if (info) {
                    infoMap[server] = info;
                    if (cache && typeof scriptResourceCache !== 'undefined') {
                        scriptResourceCache.set(`ip_info_v3_${server}`, JSON.stringify(info));
                    }
                }
            }));
            if (i + 5 < toQuery.length) await new Promise((r) => setTimeout(r, 1200));
        }
    }

    return proxies.map((p) => {
        const info = infoMap[p.server];
        if (info) p.name = `${info.tag} ${EMOJI(info.cc)} ${info.cc} | ${p.name}`;
        return p;
    });
}
