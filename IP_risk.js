/**
 * IP 归属地 + 综合风控检测 (v9 修正防误杀版)
 * 
 * 修正: 域名解析失败时，不再判定为死节点，而是标记为 [未检测] 并保留，防止误杀可用节点。
 * 
 * 参数: 
 * abuseKey=你的AbuseIPDB_Key
 * cache=true
 */
async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore;
    const { cache = true, abuseKey = '' } = $arguments || {};

    if (!abuseKey) throw new Error('请配置 abuseKey');

    const EMOJI = (code) => {
        if (!code || code.length !== 2) return '🏳️';
        try { return String.fromCodePoint(...code.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0))); } 
        catch (e) { return '🏳️'; }
    };
    const parse = (b) => { try { return JSON.parse(b); } catch (e) { return null; } };
    const isIP = (str) => /^(\d{1,3}\.){3}\d{1,3}$/.test(str) || /:/.test(str);

    async function resolveDomainToIP(domain) {
        try {
            const { statusCode, body } = await $.http.get(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
            if (statusCode === 200) {
                const data = parse(body);
                if (data?.Answer) {
                    const a = data.Answer.find(a => a.type === 1);
                    if (a) return a.data;
                }
            }
        } catch (e) {}
        
        try {
            const { statusCode, body } = await $.http.get(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            if (statusCode === 200) {
                const data = parse(body);
                if (data?.Answer) {
                    const a = data.Answer.find(a => a.type === 1);
                    if (a) return a.data;
                }
            }
        } catch (e) {}
        
        return null; 
    }

    async function queryAbuseIPDB(server) {
        let ipToQuery = server;
        
        if (!isIP(server)) {
            $.info(`[${server}] 是域名，正在尝试解析真实 IP...`);
            const resolvedIP = await resolveDomainToIP(server);
            if (!resolvedIP) {
                // 🚨 关键修正：解析失败不代表节点死了，只是当前环境DNS查不到。
                // 标记为 [未检测]，不查 API，保留节点供客户端自行连接。
                $.info(`[${server}] 公网DNS解析失败，标记为 [未检测]，跳过风控查询`);
                return { cc: 'UN', tag: '[未检测]' }; 
            }
            ipToQuery = resolvedIP;
            $.info(`[${server}] 成功解析为 IP: ${ipToQuery}`);
        }

        const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipToQuery)}`;
        const { statusCode, body } = await $.http.get({
            url, headers: { Key: abuseKey, Accept: 'application/json' },
        });

        if (statusCode !== 200) throw new Error(`API 状态码 ${statusCode}`);

        const d = parse(body);
        if (!d?.data) throw new Error('API 返回异常');

        const data = d.data;
        const score = data.abuseConfidenceScore ?? 0;
        const cc = data.countryCode || 'UN';
        const usageType = (data.usageType || '').toLowerCase();

        let tag = '';
        if (score > 50) tag = `[高危${score}%]`;
        else if (score > 10) tag = `[风控${score}%]`;
        else if (/fixed line|cable|dsl|residential/.test(usageType)) tag = '[极品·家宽]';
        else if (/data center|hosting|cdn/.test(usageType)) tag = `[优质·机房${score}%]`;
        else tag = `[普通${score}%]`;

        return { cc, tag };
    }

    const uniqueServers = [...new Set(proxies.map((p) => p.server).filter(Boolean))];
    const infoMap = {};
    const toQuery = [];

    for (const server of uniqueServers) {
        const cached = cache && typeof scriptResourceCache !== 'undefined'
            ? scriptResourceCache.get(`ip_abuse_v9_${server}`) : null;
        if (cached) infoMap[server] = JSON.parse(cached);
        else toQuery.push(server);
    }

    if (toQuery.length > 0) {
        $.info(`需查询 ${toQuery.length} 个独立节点...`);
        for (const server of toQuery) {
            try {
                const info = await queryAbuseIPDB(server);
                infoMap[server] = info;
                if (info.tag !== '[未检测]') {
                    $.info(`[${server}] 成功: ${info.cc} ${info.tag}`);
                }
                if (cache && typeof scriptResourceCache !== 'undefined') {
                    scriptResourceCache.set(`ip_abuse_v9_${server}`, JSON.stringify(info));
                }
            } catch (e) {
                $.error(`[${server}] 查询失败: ${e.message || e}`);
            }
            await new Promise((r) => setTimeout(r, 300)); 
        }
    }

    return proxies.map((p) => {
        const info = infoMap[p.server];
        if (info) p.name = `${info.tag} ${EMOJI(info.cc)} ${info.cc} | ${p.name}`;
        return p;
    });
}
