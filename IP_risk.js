/**
 * IP 归属地解析与 iprisk 风险检测脚本
 * 说明: 查询真实 IP 信息，计算风险百分比，并注入节点名供后续 AI 脚本使用
 */
async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore;
    const { cache = true, timeout = 10000 } = $arguments || {};

    // 国家代码转 Emoji 函数
    function countryToEmoji(code) {
        if (!code || code.length !== 2) return '🏳️';
        try {
            const codePoints = code.toUpperCase().split('').map(char => 127397 + char.charCodeAt(0));
            return String.fromCodePoint(...codePoints);
        } catch (e) { return '🏳️'; }
    }

    // 1. 提取并去重 server (IP 或域名)
    const uniqueServers = [...new Set(proxies.map(p => p.server).filter(Boolean))];
    const infoMap = {};
    const toQuery = [];

    // 2. 读取缓存
    for (const server of uniqueServers) {
        const cacheKey = `ip_info_${server}`;
        const cached = cache ? scriptResourceCache.get(cacheKey) : null;
        if (cached) {
            infoMap[server] = JSON.parse(cached);
        } else {
            toQuery.push(server);
        }
    }

    // 3. 并发查询 ipapi.is (免费，每天 1000 次额度)
    if (toQuery.length > 0) {
        $.info(`开始查询 ${toQuery.length} 个节点的 IP 信息与风险...`);
        const chunkSize = 5; // 每次并发 5 个，防止触发限流
        for (let i = 0; i < toQuery.length; i += chunkSize) {
            const chunk = toQuery.slice(i, i + chunkSize);
            const promises = chunk.map(async (server) => {
                try {
                    const url = `https://api.ipapi.is/${encodeURIComponent(server)}/`;
                    const { statusCode, body } = await $.http.get({ url, timeout });
                    if (statusCode === 200) {
                        const data = JSON.parse(body);
                        let score = 0;
                        
                        // 风险分计算逻辑 (最高 100%)
                        if (data.is_datacenter) score += 30; // 机房 IP
                        if (data.is_proxy || data.is_vpn) score += 40; // 被标记为代理/VPN
                        if (data.is_tor) score += 50; // Tor 节点
                        if (data.is_crawler) score += 20; // 爬虫/恶意 IP
                        if (data.is_mobile) score += 10; // 移动基站 IP
                        score = Math.min(score, 100);
                        
                        const emoji = countryToEmoji(data.country_code);
                        const country = data.country_code || 'UN';
                        
                        infoMap[server] = {
                            emoji,
                            country,
                            score,
                            tag: `[风险${score}%]`
                        };
                        if (cache) scriptResourceCache.set(`ip_info_${server}`, JSON.stringify(infoMap[server]));
                    } else {
                        infoMap[server] = { emoji: '🏳️', country: 'UN', score: -1, tag: '[查询失败]' };
                    }
                } catch (e) {
                    $.error(`查询 ${server} 失败: ${e}`);
                    infoMap[server] = { emoji: '🏳️', country: 'UN', score: -1, tag: '[超时]' };
                }
            });
            await Promise.all(promises);
            if (i + chunkSize < toQuery.length) await new Promise(r => setTimeout(r, 1000));
        }
    }

    // 4. 将真实信息注入节点名，格式: [风险30%] 🇺🇸 US | 原始名称
    return proxies.map(p => {
        const info = infoMap[p.server];
        if (info) {
            p.name = `${info.tag} ${info.emoji} ${info.country} | ${p.name}`;
        }
        return p;
    });
}