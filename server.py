#!/usr/bin/env python3
"""
Clash 订阅生成服务
"""

import os
import sys
import yaml
import time
import hashlib
import requests
from pathlib import Path
from flask import Flask, jsonify, Response, abort, request

app = Flask(__name__)

BASE_DIR = Path("/home/ubuntu/dev/customGFWlist")
CONFIG_FILE = BASE_DIR / "config.yaml"
PROVIDERS_DIR = BASE_DIR / "providers"
RULES_DIR = BASE_DIR / "rules"

CONFIG = {}


def load_config():
    """加载配置文件"""
    global CONFIG
    if not CONFIG_FILE.exists():
        print(f"错误: 配置文件 {CONFIG_FILE} 不存在")
        print(f"请复制 config.example.yaml 为 config.yaml")
        sys.exit(1)

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        CONFIG = yaml.safe_load(f)

    return CONFIG


def save_config():
    """保存配置文件"""
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        yaml.dump(CONFIG, f, allow_unicode=True, default_flow_style=False)


def fetch_subscription(url, timeout=30):
    """拉取订阅"""
    # 这里不要伪装成 Clash 客户端；部分机场会针对不同 UA 返回不同格式。
    # 使用通用浏览器 UA，优先拿到原始订阅（通常是 Base64 URI 列表）。
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response.text


def parse_uri_subscription(content):
    """解析 Base64/纯文本 URI 订阅，目前支持 anytls:// 和 ss://"""
    import base64
    from urllib.parse import parse_qs, unquote, urlsplit

    raw = content.strip()
    if not raw:
        return None

    decoded = raw
    if "://" not in raw:
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
        except Exception:
            return None

    lines = [line.strip() for line in decoded.splitlines() if line.strip()]
    if not lines or not any("://" in line for line in lines):
        return None

    proxies = []
    for line in lines:
        if "://" not in line:
            continue

        parsed = urlsplit(line)
        scheme = parsed.scheme.lower()

        if scheme == "anytls":
            params = parse_qs(parsed.query)
            proxy = {
                "name": unquote(parsed.fragment) or f"anytls-{parsed.hostname}:{parsed.port}",
                "type": "anytls",
                "server": parsed.hostname,
                "port": parsed.port,
                "password": unquote(parsed.username or ""),
                "udp": True,
            }

            sni = params.get("sni", [None])[0]
            if sni:
                proxy["sni"] = sni
                proxy["servername"] = sni

            insecure = params.get("insecure", [None])[0]
            if insecure is not None:
                proxy["skip-cert-verify"] = str(insecure) in {"1", "true", "True"}

            proxies.append(proxy)
            continue

        if scheme == "ss":
            try:
                auth = parsed.username or ""
                decoded_auth = base64.b64decode(auth + "=" * (-len(auth) % 4)).decode(
                    "utf-8"
                )
                cipher, password = decoded_auth.split(":", 1)
                params = parse_qs(parsed.query)
                proxy = {
                    "name": unquote(parsed.fragment)
                    or f"ss-{parsed.hostname}:{parsed.port}",
                    "type": "ss",
                    "server": parsed.hostname,
                    "port": parsed.port,
                    "cipher": cipher,
                    "password": password,
                    "udp": True,
                }

                plugin = params.get("plugin", [None])[0]
                if plugin:
                    plugin = unquote(plugin)
                    if plugin.startswith("simple-obfs"):
                        proxy["plugin"] = "obfs"
                        plugin_parts = {}
                        for part in plugin.split(";")[1:]:
                            if "=" in part:
                                k, v = part.split("=", 1)
                                plugin_parts[k] = v
                        plugin_opts = {}
                        if "obfs" in plugin_parts:
                            plugin_opts["mode"] = plugin_parts["obfs"]
                        if "obfs-host" in plugin_parts:
                            plugin_opts["host"] = plugin_parts["obfs-host"]
                        if plugin_opts:
                            proxy["plugin-opts"] = plugin_opts

                proxies.append(proxy)
            except Exception:
                continue

    if not proxies:
        return None

    return {"proxies": proxies}


def decode_subscription(content):
    """解码订阅内容 (Base64 URI / 纯 YAML)"""
    # 先尝试 URI 订阅（Base64 节点链接）
    uri_data = parse_uri_subscription(content)
    if uri_data:
        return uri_data

    # 再尝试 YAML
    try:
        return yaml.safe_load(content)
    except Exception as e:
        print(f"解析订阅失败: {e}")
        return None


def apply_node_mapping(proxies, node_mapping):
    """应用节点映射，重命名节点"""
    if not node_mapping:
        return proxies

    if not proxies:
        return proxies

    # 建立反向映射: 关键词 -> 标准化名称
    keyword_to_region = {}
    for region, keywords in node_mapping.items():
        for kw in keywords:
            keyword_to_region[kw.lower()] = region

    # 标准化代理名称
    for proxy in proxies:
        original_name = proxy.get("name", "")
        name_lower = original_name.lower()

        # 查找匹配的地区
        matched_region = None
        for kw, region in keyword_to_region.items():
            if kw in name_lower:
                matched_region = region
                break

        # 如果找到匹配，保留原名（因为 filter 会根据名称筛选）
        # 不需要重命名，只需要返回原始节点
        # 节点是否能被筛选，取决于 filter 正则是否匹配节点名

    return proxies


def generate_provider_config(provider_name, url, node_mapping=None):
    """生成单个 provider 的配置文件"""
    try:
        if str(url).startswith("local://"):
            provider_file = PROVIDERS_DIR / f"{provider_name}.yaml"
            if not provider_file.exists():
                print(f"警告: {provider_name} 本地 provider 文件不存在")
                return None
            with open(provider_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        else:
            content = fetch_subscription(url)
            data = decode_subscription(content)

        if not data or "proxies" not in data:
            print(f"警告: {provider_name} 订阅解析失败")
            return None

        proxies = data.get("proxies", [])
        proxies = apply_node_mapping(proxies, node_mapping)

        provider_data = {"proxies": proxies}
        provider_file = PROVIDERS_DIR / f"{provider_name}.yaml"
        with open(provider_file, "w", encoding="utf-8") as f:
            yaml.dump(provider_data, f, allow_unicode=True, default_flow_style=False)

        return len(proxies)

    except Exception as e:
        print(f"拉取 {provider_name} 失败: {e}")
        return None


def generate_full_config(base_url=None):
    """生成完整的 Clash 配置"""
    template_file = CONFIG.get("template", "test1_public.yaml")
    template_path = RULES_DIR / template_file

    if not template_path.exists():
        raise FileNotFoundError(f"模板文件不存在: {template_path}")

    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()

    providers = CONFIG.get("providers", [])
    enabled_providers = [p for p in providers if p.get("enabled", True)]

    for provider in enabled_providers:
        name = provider.get("name")
        url = provider.get("url")
        node_mapping = provider.get("node_mapping", {})

        print(f"更新 provider: {name}")
        node_count = generate_provider_config(name, url, node_mapping)

        if node_count is not None:
            provider["_node_count"] = node_count
            provider["_last_update"] = time.strftime("%Y-%m-%dT%H:%M:%S")

    save_config()

    region_meta = {
        "HK": ("🇭🇰 香港", ["香港", "HK", "Hong Kong"]),
        "TW": ("🇹🇼 台湾", ["台湾", "TW", "Taiwan"]),
        "JP": ("🇯🇵 日本", ["日本", "JP", "Japan", "东京", "大阪", "软银"]),
        "SG": ("🇸🇬 新加坡", ["新加坡", "SG", "Singapore"]),
        "US": ("🇺🇸 美国", ["美国", "US", "States", "United States", "洛杉矶", "硅谷"]),
        "KR": ("🇰🇷 韩国", ["韩国", "KR", "Korea"]),
        "DE": ("🇩🇪 德国", ["德国", "DE", "Germany"]),
        "GB": ("🇬🇧 英国", ["英国", "GB", "UK", "Britain"]),
        "CA": ("🇨🇦 加拿大", ["加拿大", "CA", "Canada"]),
        "AU": ("🇦🇺 澳大利亚", ["澳大利亚", "澳洲", "AU", "Australia"]),
        "MO": ("🇲🇴 澳门", ["澳门", "MO"]),
        "TH": ("🇹🇭 泰国", ["泰国", "TH", "Thailand"]),
        "VN": ("🇻🇳 越南", ["越南", "VN", "Vietnam"]),
        "PH": ("🇵🇭 菲律宾", ["菲律宾", "PH", "Philippines"]),
        "MY": ("🇲🇾 马来西亚", ["马来西亚", "MY", "Malaysia"]),
        "ID": ("🇮🇩 印尼", ["印尼", "印度尼西亚", "ID", "Indonesia"]),
        "IN": ("🇮🇳 印度", ["印度", "IN", "India"]),
        "NL": ("🇳🇱 荷兰", ["荷兰", "NL", "Netherlands"]),
        "TR": ("🇹🇷 土耳其", ["土耳其", "TR", "Turkey"]),
        "EG": ("🇪🇬 埃及", ["埃及", "EG", "Egypt"]),
        "MN": ("🇲🇳 蒙古", ["蒙古", "MN", "Mongolia"]),
        "PK": ("🇵🇰 巴基斯坦", ["巴基斯坦", "PK", "Pakistan"]),
    }

    def indent_lines(lines, spaces):
        prefix = " " * spaces
        return "\n".join(prefix + line for line in lines)

    provider_blocks = []
    all_provider_names = []
    region_keywords = {}
    token = CONFIG.get("server", {}).get("token", "")
    base_url = (base_url or "http://10.0.0.8:8000").rstrip("/")

    for provider in enabled_providers:
        name = provider.get("name")
        all_provider_names.append(name)
        provider_blocks.extend(
            [
                f"  {name}:",
                "    type: http",
                f"    url: {base_url}/provider/{token}/{name}.yaml",
                f"    path: ./providers/{name}.yaml",
                "    interval: 3600",
                "    health-check:",
                "      enable: true",
                "      interval: 600",
                "      url: http://www.gstatic.com/generate_204",
            ]
        )

        for region, keywords in (provider.get("node_mapping") or {}).items():
            region_keywords.setdefault(region, [])
            for kw in keywords:
                if kw not in region_keywords[region]:
                    region_keywords[region].append(kw)

    # 只保留常用地区
    ordered_regions = [r for r in ["HK", "TW", "JP", "SG", "US"] if r in region_keywords]

    region_group_lines = [
        "  - name: ♻️ 自动优选",
        "    type: url-test",
        f"    use: [{', '.join(all_provider_names)}]",
        "    url: 'http://www.gstatic.com/generate_204'",
        "    interval: 300",
    ]

    for region in ordered_regions:
        label, default_keywords = region_meta.get(region, (region, [region]))
        keywords = region_keywords.get(region) or default_keywords
        escaped = [str(k).replace("'", "\\'") for k in keywords]
        filt = "(?i)(" + "|".join(escaped) + ")"
        region_group_lines.extend(
            [
                f"  - name: {label}",
                "    type: url-test",
                f"    use: [{', '.join(all_provider_names)}]",
                f"    filter: '{filt}'",
                "    url: 'http://www.gstatic.com/generate_204'",
                "    interval: 300",
            ]
        )

    region_names = [(region_meta.get(r, (r,))[0]) for r in ordered_regions]
    ai_regions = [region_meta[r][0] for r in ["US", "JP", "SG", "TW", "HK", "DE", "GB"] if r in ordered_regions and r in region_meta]
    media_regions = [region_meta[r][0] for r in ["HK", "TW", "SG", "US", "JP", "KR", "DE"] if r in ordered_regions and r in region_meta]

    node_select = ["- ♻️ 自动优选"] + [f"- {name}" for name in region_names] + ["- DIRECT"]
    ai_select = [f"- {name}" for name in (ai_regions or region_names)] + ["- ♻️ 自动优选", "- DIRECT"]
    media_select = [f"- {name}" for name in (media_regions or region_names)] + ["- ♻️ 自动优选", "- DIRECT"]

    template_content = template_content.replace("${PROXY_PROVIDERS}", "\n".join(provider_blocks))
    template_content = template_content.replace("${NODE_SELECT_PROXIES}", indent_lines(node_select, 6))
    template_content = template_content.replace("${AI_SELECT_PROXIES}", indent_lines(ai_select, 6))
    template_content = template_content.replace("${MEDIA_SELECT_PROXIES}", indent_lines(media_select, 6))
    template_content = template_content.replace("${REGION_GROUPS}", "\n".join(region_group_lines))

    return template_content


@app.route("/sub/<token>")
def get_subscription(token):
    """获取 Clash 订阅"""
    # 验证 token
    expected_token = CONFIG.get("server", {}).get("token", "")
    if token != expected_token:
        abort(403)

    try:
        content = generate_full_config(request.host_url.rstrip('/'))

        # 生成 ETag
        etag = hashlib.md5(content.encode()).hexdigest()

        # 返回内容
        response = Response(content, content_type="application/x-yaml; charset=utf-8")
        response.headers["ETag"] = etag
        response.headers["Content-Disposition"] = "attachment; filename=clash.yaml"

        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health_check():
    """健康检查"""
    return jsonify({"status": "ok"})


@app.route("/provider/<token>/<name>.yaml")
def get_provider_file(token, name):
    """对外提供 provider 文件（受 token 保护）"""
    expected_token = CONFIG.get("server", {}).get("token", "")
    if token != expected_token:
        abort(403)

    provider_file = PROVIDERS_DIR / f"{name}.yaml"
    if not provider_file.exists():
        abort(404)

    content = provider_file.read_text(encoding="utf-8")
    return Response(content, content_type="application/x-yaml; charset=utf-8")


@app.route("/api/<token>/config")
def get_config(token):
    """获取配置信息"""
    expected_token = CONFIG.get("server", {}).get("token", "")
    if token != expected_token:
        abort(403)

    providers = CONFIG.get("providers", [])
    return jsonify(
        {
            "template": CONFIG.get("template"),
            "providers": [
                {
                    "name": p.get("name"),
                    "enabled": p.get("enabled", True),
                    "url": p.get("url"),
                    "node_count": p.get("_node_count"),
                    "last_update": p.get("_last_update"),
                }
                for p in providers
            ],
        }
    )


@app.route("/api/<token>/providers/<name>", methods=["POST"])
def add_provider(token, name):
    """添加 provider"""
    from flask import request

    expected_token = CONFIG.get("server", {}).get("token", "")
    if token != expected_token:
        abort(403)

    data = request.json or {}
    url = data.get("url", "")
    node_mapping = data.get("node_mapping", {})

    if not url:
        return jsonify({"error": "url is required"}), 400

    providers = CONFIG.get("providers", [])

    # 检查是否已存在
    for p in providers:
        if p.get("name") == name:
            p["url"] = url
            p["node_mapping"] = node_mapping
            p["enabled"] = True
            break
    else:
        providers.append(
            {
                "name": name,
                "url": url,
                "enabled": True,
                "node_mapping": node_mapping,
            }
        )

    CONFIG["providers"] = providers
    save_config()

    # 立即拉取
    node_count = generate_provider_config(name, url, node_mapping)

    return jsonify(
        {
            "name": name,
            "url": url,
            "node_count": node_count,
        }
    )


@app.route("/api/<token>/providers/<name>", methods=["DELETE"])
def delete_provider(token, name):
    """删除 provider"""
    expected_token = CONFIG.get("server", {}).get("token", "")
    if token != expected_token:
        abort(403)

    providers = CONFIG.get("providers", [])
    CONFIG["providers"] = [p for p in providers if p.get("name") != name]
    save_config()

    # 删除缓存文件
    provider_file = PROVIDERS_DIR / f"{name}.yaml"
    if provider_file.exists():
        provider_file.unlink()

    return jsonify({"status": "deleted", "name": name})


@app.route("/api/<token>/providers/<name>/refresh", methods=["POST"])
def refresh_provider(token, name):
    """刷新单个 provider"""
    expected_token = CONFIG.get("server", {}).get("token", "")
    if token != expected_token:
        abort(403)

    providers = CONFIG.get("providers", [])
    provider = None
    for p in providers:
        if p.get("name") == name:
            provider = p
            break

    if not provider:
        return jsonify({"error": "provider not found"}), 404

    url = provider.get("url")
    node_mapping = provider.get("node_mapping", {})

    node_count = generate_provider_config(name, url, node_mapping)

    return jsonify(
        {
            "name": name,
            "node_count": node_count,
        }
    )


def main():
    """主函数"""
    print("=" * 50)
    print("Clash 订阅服务")
    print("=" * 50)

    # 加载配置
    config = load_config()

    server_config = config.get("server", {})
    host = server_config.get("host", "0.0.0.0")
    port = server_config.get("port", 8000)
    token = server_config.get("token", "")

    print(f"模板: {config.get('template')}")
    print(f"Providers: {len(config.get('providers', []))}")
    print(f"Token: {token[:8]}..." if token else "Token: (未设置)")
    print(f"监听: {host}:{port}")
    print("=" * 50)

    # 确保目录存在
    PROVIDERS_DIR.mkdir(exist_ok=True)
    RULES_DIR.mkdir(exist_ok=True)

    # 启动服务
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
