/**
 * Sub-Store Gemini 节点重命名脚本
 *
 * 说明:
 * 使用 Gemini OpenAI 兼容接口修改 Sub-Store 节点名称。
 * 适合部署到 GitHub 后通过远程 URL 拉取。
 *
 * 推荐参数:
 * key=你的Gemini_API_Key
 * model=gemini-2.5-flash-lite
 * fields=type
 * cache=true
 * nameExample=国家地区 Emoji ISO 3166-1 alpha-2 [协议类型] 分组内序号，例如：🇺🇸 US [VLESS] 01
 */

async function operator(proxies = [], targetPlatform, context) {
    const $ = $substore;

    const args = $arguments || {};

    const timeout = Number(args.timeout || 30000);

    const url =
        args.url ||
        'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions';

    const model = args.model || 'gemini-2.5-flash-lite';

    const key = args.key || '';

    const nameExample =
        args.nameExample ||
        '国家地区 Emoji ISO 3166-1 alpha-2 [协议类型] 分组内序号，例如：🇺🇸 US [VLESS] 01。请整理节点名称，使其更规范、简洁、易读。';

    const fields = args.fields || 'type';

    const enableCache = String(args.cache ?? true) !== 'false';

    if (!key) {
        throw new Error(
            '缺少 Gemini API Key，请在 Sub-Store 脚本参数中配置 key=你的API密钥。不要把 Key 写死在 GitHub 脚本里。'
        );
    }

    if (!Array.isArray(proxies) || proxies.length === 0) {
        return proxies;
    }

    const fieldList = String(fields || '')
        .split(/,|，/g)
        .map((item) => item.trim())
        .filter((item) => item.length > 0);

    const proxyNamesArray = proxies.map((proxy, index) => {
        const obj = {
            id: `${index}`,
            name: proxy.name,
        };

        fieldList.forEach((field) => {
            if (proxy[field] !== undefined && proxy[field] !== null) {
                obj[field] = proxy[field];
            }
        });

        return obj;
    });

    const proxyNamesStr = JSON.stringify(proxyNamesArray);

    const content = `
你将收到一个 JSON 数组字符串。

任务：
按照以下规则转换每个对象的 "name" 字段：

${nameExample}

输入：
${proxyNamesStr}

输出要求：
1. 只返回 JSON 数组字符串。
2. 每个对象仅保留 "name" 和 "id" 字段。
3. id 必须与输入中的 id 完全一致。
4. 不允许输出任何 JSON 之外的内容。
5. 输出必须是合法 JSON，可被 JSON.parse 解析。
6. 不要输出 Markdown 代码块。
7. 不要输出解释、注释、说明。
8. 如果某个节点无法识别或无法整理，请保留其原始 name。

输出示例格式：
[
  { "name": "...", "id": "0" },
  { "name": "...", "id": "1" }
]
`;

    const cacheStr = JSON.stringify({
        url,
        model,
        nameExample,
        fields,
        content,
        proxyNamesStr,
    });

    const cacheId =
        typeof ProxyUtils !== 'undefined' && ProxyUtils.hex_md5
            ? ProxyUtils.hex_md5(cacheStr)
            : cacheStr;

    let result = [];

    const cached =
        enableCache && typeof scriptResourceCache !== 'undefined'
            ? scriptResourceCache.get(cacheId)
            : null;

    if (cached) {
        $.info('使用缓存结果，不消耗 Gemini 请求次数。');

        try {
            result = JSON.parse(cached);
        } catch (error) {
            $.error(`缓存结果解析失败，将重新请求 Gemini：${error}`);
            result = [];
        }
    }

    if (!Array.isArray(result) || result.length === 0) {
        $.info('发送请求到 Gemini OpenAI 兼容接口...');
        $.info(`模型: ${model}`);
        $.info(`节点数量: ${proxies.length}`);

        const response = await $.http.post({
            timeout,
            url,
            headers: {
                Authorization: `Bearer ${key}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                model,
                temperature: 0.2,
                messages: [
                    {
                        role: 'user',
                        content,
                    },
                ],
            }),
        });

        const { statusCode, body } = response;

        $.info(`Gemini 状态码: ${statusCode}`);
        $.info(`Gemini 响应内容: ${body}`);

        let data;

        try {
            data = JSON.parse(body);
        } catch (error) {
            throw new Error(
                `Gemini 响应不是合法 JSON。状态码: ${statusCode}，响应内容: ${String(
                    body
                ).slice(0, 500)}`
            );
        }

        if (statusCode !== 200) {
            const errorMessage =
                data?.error?.message ||
                data?.message ||
                '未知错误';

            throw new Error(
                `Gemini 请求失败，状态码: ${statusCode}，错误信息: ${errorMessage}`
            );
        }

        let rawContent =
            data?.choices?.[0]?.message?.content || '';

        if (!rawContent) {
            throw new Error('Gemini 未返回有效内容。');
        }

        rawContent = String(rawContent).trim();

        rawContent = rawContent
            .replace(/^```(?:json)?\s*/i, '')
            .replace(/```\s*$/, '')
            .trim();

        const start = rawContent.indexOf('[');
        const end = rawContent.lastIndexOf(']');

        if (start !== -1 && end !== -1 && end > start) {
            rawContent = rawContent.slice(start, end + 1);
        }

        try {
            result = JSON.parse(rawContent);
        } catch (error) {
            $.error(`解析 Gemini 返回内容失败: ${error}`);
            $.error(`原始返回内容: ${rawContent}`);
            throw new Error('Gemini 返回内容不是合法 JSON。');
        }

        if (!Array.isArray(result)) {
            throw new Error('Gemini 返回内容不是 JSON 数组。');
        }

        if (enableCache && typeof scriptResourceCache !== 'undefined') {
            scriptResourceCache.set(cacheId, JSON.stringify(result));
            $.info('已缓存本次结果。');
        }
    }

    return proxies.map((proxy, index) => {
        const item = result.find(
            (r) => String(r?.id) === String(index)
        );

        if (
            item &&
            typeof item.name === 'string' &&
            item.name.trim().length > 0
        ) {
            return {
                ...proxy,
                name: item.name.trim(),
            };
        }

        return proxy;
    });
}