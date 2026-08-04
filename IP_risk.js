/**
 * IP 归属地 + 综合风控检测 (v7 支持域名解析版)
 * 
 * 唯一数据源: AbuseIPDB (提供真实风控分 + 国家 + 线路用途)
 * 新增功能: 自动识别域名，并通过 DNS 解析为真实 IP 后再查询
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
    
    // 判断是否为 IP 地址
    const isIP = (str) => /^(\d{1,3}\.){3}\d{1,3}$/.test(str) || /:/.test(str);

    // DNS 解析域名到 IP
    async function resolveDomainToIP(domain) {
        try {
            const { statusCode, body } = await $.http.get(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
            if (statusCode === 200) {
                const data = parse(body);
                if (data && data.Answer) {
                    const aRecord = data.Answer.find(a => a.type === 1); // type 1 是 A 记录 (IPv4)
                    if (aRecord) return aRecord.data;
                }
            }
        } catch (e) {
            $.info(`[DNS] 解析 ${domain} 失败: ${e.message || e}`);
        }
        return null;
    }

    async function queryAbuseIPDB(server) {
        let ipToQuery = server;
        
        // 如果是域名，先解析
        if (!isIP(server)) {
            $.info(`[${server}] 是域名，正在解析真实 IP...`);
            const resolvedIP = await resolveDomainToIP(server);
            if (!resolvedIP) {
                throw new Error('域名解析失败，无法获取真实 IP');
            }
            ipToQuery = resolvedIP;
            $.info(`[${server}] 成功解析为 IP: ${ipToQuery}`);
        }

        const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipToQuery)}`;
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
            if (isResidential) {
                tag = '[极品·家宽]'; 
            } else if (isDataCenter) {
                tag = `[优质·机房${score}%]`; 
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
            ? scriptResourceCache.get(`ip_abuse_v7_${server}`) 
            : null;
        if (cached) {
            infoMap[server] = JSON.parse(cached);
        } else {
            toQuery.push(server);
        }
    }

    if (toQuery.length > 0) {
        $.info(`需查询 ${toQuery.length} 个独立节点 (AbuseIPDB)...`);
        for (const server of toQuery) {
            try {
                const info = await queryAbuseIPDB(server);
                infoMap[server] = info;
                $.info(`[${server}] 成功: ${info.cc} ${info.tag}`);
                if (cache && typeof scriptResourceCache !== 'undefined') {
                    scriptResourceCache.set(`ip_abuse_v7_${server}`, JSON.stringify(info));
                }
            } catch (e) {
                $.error(`[${server}] 查询失败: ${e.message || e}`);
            }
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
