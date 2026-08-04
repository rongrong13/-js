/**
 * IP 归属地 + 综合风控检测 (v5 最终版)
 * 
 * 效果: 结合 ip-api (查机房/家宽) + AbuseIPDB (查真实风控百分比)
 * 标签示例: [极品·家宽] 🇺🇸 US | 原始名称 / [优质·机房0%] 🇯🇵 JP | ...
 * 
 * 参数: 
 * abuseKey=你的AbuseIPDB_Key
 * cache=true
 */
async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore;
    const { cache = true, abuseKey = '' } = $arguments || {};

    const EMOJI = (code) => {
        if (!code || code.length !== 2) return '🏳️';
        try {
            return String.fromCodePoint(...code.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0)));
        } catch (e) { return '🏳️'; }
    };
    const parse = (b) => { try { return JSON.parse(b); } catch (e) { return null; } };

    async function queryServer(server) {
        let cc = 'UN', isHosting = false, isProxy = false, riskScore = 0;
        
        // 1. 查 ip-api 拿基础属性 (国家、是否机房、是否代理)
        try {
            const { statusCode, body } = await $.http.get(`http://ip-api.com/json/${server}?fields=status,countryCode,proxy,hosting,mobile`);
            if (statusCode === 200) {
                const d = parse(body);
                if (d && d.status === 'success') {
                    cc = d.countryCode;
                    isHosting = d.hosting; // 机房/数据中心
                    isProxy = d.proxy;     // 代理/VPN
                }
            }
        } catch(e) { $.info(`[${server}] ip-api 失败: ${e.message || e}`); }

        // 2. 查 AbuseIPDB 拿真实风控分 (0-100)
        if (abuseKey) {
            try {
                const { statusCode, body } = await $.http.get({
                    url: `https://api.abuseipdb.com/api/v2/check?ip=${server}`,
                    headers: { Key: abuseKey, Accept: 'application/json' },
                });
                if (statusCode === 200) {
                    const d = parse(body);
                    if (d && d.data) {
                        riskScore = d.data.abuseConfidencePercentage ?? 0;
                    }
                }
            } catch(e) { $.info(`[${server}] AbuseIPDB 失败: ${e.message || e}`); }
        }

        // 3. 生成类似 ping0 的综合标签
        let tag = '';
        if (riskScore > 50) {
            tag = `[高危${riskScore}%]`;
        } else if (riskScore > 10) {
            tag = `[风控${riskScore}%]`;
        } else {
            // 低风险情况，区分线路质量 (这是 ping0 的精髓)
            if (!isHosting && !isProxy) {
                tag = '[极品·家宽]'; // 住宅IP，最稀有，解锁最好
            } else if (isHosting) {
                tag = `[优质·机房${riskScore}%]`; // 干净机房
            } else {
                tag = `[风控${riskScore}%]`;
            }
        }

        $.info(`[${server}] 综合结果: ${cc} | ${tag}`);
        return { cc, tag, score: riskScore };
    }

    const uniqueServers = [...new Set(proxies.map((p) => p.server).filter(Boolean))];
    const infoMap = {};
    const toQuery = [];
    for (const server of uniqueServers) {
        const cached = cache && typeof scriptResourceCache !== 'undefined'
            ? scriptResourceCache.get(`ip_info_v5_${server}`) : null;
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
                        scriptResourceCache.set(`ip_info_v5_${server}`, JSON.stringify(info));
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
