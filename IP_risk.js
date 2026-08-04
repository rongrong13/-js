/**
 * IP 归属地 + 综合风控检测 (v6 纯净版)
 * 
 * 唯一数据源: AbuseIPDB (提供真实风控分 + 国家 + 线路用途)
 * 标签示例: [极品·家宽] 🇺🇸 US | 原始名称 / [优质·机房0%] 🇯🇵 JP | ...
 * 
 * 参数: 
 * abuseKey=你的AbuseIPDB_Key
 * cache=true
 */
async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore;
    const { cache = true, abuseKey = '' } = $arguments || {};

    if (!abuseKey) {
        throw new Error('请在脚本参数中配置 abuseKey (你的 AbuseIPDB API Key)');
    }

    const EMOJI = (code) => {
        if (!code || code.length !== 2) return '🏳️';
        try {
            return String.fromCodePoint(...code.toUpperCase().split('').map((c) => 127397 + c.charCodeAt(0)));
        } catch (e) { return '🏳️'; }
    };
    const parse = (b) => { try { return JSON.parse(b); } catch (e) { return null; } };

    async function queryAbuseIPDB(server) {
        const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(server)}`;
        const { statusCode, body } = await $.http.get({
            url,
            headers: { 
                Key: abuseKey, 
                Accept: 'application/json' 
            },
        });

        if (statusCode !== 200) {
            throw new Error(`状态码 ${statusCode}, 响应: ${String(body).slice(0, 100)}`);
        }

        const d = parse(body);
        if (!d || !d.data) {
            throw new Error('返回数据格式异常');
        }

        const data = d.data;
        const score = data.abuseConfidenceScore ?? 0;
        const cc = data.countryCode || 'UN';
        const usageType = (data.usageType || '').toLowerCase();
        const isp = (data.isp || '').toLowerCase();

        let tag = '';
        
        // 通过 usageType 和 isp 智能识别线路质量
        const isResidential = /fixed line|cable|dsl|residential/.test(usageType) || /residential/.test(isp);
        const isDataCenter = /data center|hosting|transit|cdn|content delivery/.test(usageType);

        // 生成综合标签
        if (score > 50) {
            tag = `[高危${score}%]`;
        } else if (score > 10) {
            tag = `[风控${score}%]`;
        } else {
            // 低风险情况，区分线路质量 (这是 ping0 的精髓)
            if (isResidential) {
                tag = '[极品·家宽]'; // 住宅IP，最稀有，解锁最好
            } else if (isDataCenter) {
                tag = `[优质·机房${score}%]`; // 干净机房
            } else {
                tag = `[普通${score}%]`;
            }
        }

        return { cc, tag };
    }

    const uniqueServers = [...new Set(proxies.map((p) => p.server).filter(Boolean))];
    const infoMap = {};
    const toQuery = [];

    for (const server of uniqueServers) {
        const cached = cache && typeof scriptResourceCache !== 'undefined'
            ? scriptResourceCache.get(`ip_abuse_v6_${server}`) 
            : null;
        if (cached) {
            infoMap[server] = JSON.parse(cached);
        } else {
            toQuery.push(server);
        }
    }

    if (toQuery.length > 0) {
        $.info(`需查询 ${toQuery.length} 个独立 IP (AbuseIPDB)...`);
        // AbuseIPDB 免费版限制每秒请求数，串行查询并加延迟防 429 报错
        for (const server of toQuery) {
            try {
                const info = await queryAbuseIPDB(server);
                infoMap[server] = info;
                $.info(`[${server}] 成功: ${info.cc} ${info.tag}`);
                if (cache && typeof scriptResourceCache !== 'undefined') {
                    scriptResourceCache.set(`ip_abuse_v6_${server}`, JSON.stringify(info));
                }
            } catch (e) {
                $.error(`[${server}] 查询失败: ${e.message || e}`);
            }
            // 延迟 300ms，防止触发速率限制
            await new Promise((r) => setTimeout(r, 300)); 
        }
    }

    return proxies.map((p) => {
        const info = infoMap[p.server];
        if (info) {
            p.name = `${info.tag} ${EMOJI(info.cc)} ${info.cc} | ${p.name}`;
        }
        return p;
    });
}
