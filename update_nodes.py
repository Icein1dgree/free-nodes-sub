#!/usr/bin/env python3
"""
每小时更新免费节点订阅（草稿 v1，供用户确认来源/阈值后再部署到服务器）

流程：
  1. 从 SOURCES 里的公开订阅地址拉取内容（base64 或明文链接，每行一个）
  2. 解析 ss / vmess / vless / trojan 链接，去重（server:port:协议:凭据）
  3. TCP 连通性 + 延迟测试，筛掉连不上 / 超时的
  4. 按延迟排序，原子写入 FlClash 可用的 Clash YAML 订阅
     （proxies + PROXY select 组 + MATCH,PROXY）
  5. 同时保留一份纯链接 txt，方便排查

注意（诚实说明）：
  - TCP 通 != 代理一定能用：完整握手/流量测试需要客户端或
    clash 内核实测，v1 只做第一层筛选，避免把明显死节点放进订阅。
  - 公开免费节点不可信：不要用它登录重要账号、网银等。
  - 来源地址经常失效：SOURCES 为空或全部拉取失败时，脚本不覆盖
    旧订阅，只写日志退出，避免把订阅清空。

部署（用户确认服务器路径后填）：
  脚本放：/opt/free-nodes/update_nodes.py
  输出放：/var/www/html/sub.yaml  （或 nginx 实际的订阅目录）
  root crontab：
    17 * * * * /usr/bin/flock -n /var/lock/free-nodes.lock \
      /usr/bin/python3 /opt/free-nodes/update_nodes.py \
      >> /var/log/free-nodes.log 2>&1

  flock 在 crontab 里再加一层防重入；脚本内部也用锁文件兜底。
  Python 仅用标准库，无需 pip 安装。
"""

import base64
import json
import os
import socket
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---- 用户需确认的配置（先留空/示例阈值，不编造可用来源） ----
# 把你平时用的公开订阅地址填进来，每行一个，例如：
#   https://example.com/sub.txt
SOURCES = [
    # GitHub 筛选 2026-11-01 实测：snakem982/proxypool v2ray 纯链接
    # 当时拉到 62 条，本脚本可解析 58 条（vless/trojan/vmess/ss）；
    # 其余 4 条多为 hy2/tuic 等本版暂不支持的协议，需扩展解析器才进订阅。
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt",
    # 多来源 2026-11-01 实测：Au1rxx/free-vpn-subscriptions v2ray 纯链接
    # 当时拉到 1751 条，可解析 1580 条，去重后 523 条；
    # 作者称每小时刷新、每个节点做过真实 HTTP 代理验证。
    # 脚本会在所有来源之间去重（服务器:端口:协议:凭据），再统一测速排序。
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
    # 备选（已验证文件存在、量大，但它是完整 Clash YAML，不是纯链接，
    #  直接喂给本版会解析为 0，需要另加 YAML proxies 解析才可用）：
    # "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.meta.yml",
]

OUTPUT_YAML = os.environ.get("OUTPUT_YAML", "./sub.yaml")
OUTPUT_TXT = os.environ.get("OUTPUT_TXT", "./sub.txt")
OUTPUT_CONFIG = os.environ.get("OUTPUT_CONFIG", "./config.yaml")
# 筛选阈值（可调）
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "3"))  # 秒
MAX_LATENCY_MS = float(os.environ.get("MAX_LATENCY_MS", "3000"))
MAX_NODES = int(os.environ.get("MAX_NODES", "100"))
TEST_WORKERS = int(os.environ.get("TEST_WORKERS", "20"))
USER_AGENT = "Mozilla/5.0"


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def fetch_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def b64decode_padded(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")


def split_links(text):
    """订阅内容可能是 base64 整体，也可能是明文链接。"""
    text = text.strip()
    if not text:
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) == 1 and not lines[0].startswith(("ss://", "vmess://", "vless://", "trojan://")):
        try:
            text = b64decode_padded(lines[0])
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        except Exception:
            pass
    out = []
    for ln in lines:
        # 有些订阅里单条链接本身是 base64 编码的 vmess 等，交给解析函数处理
        out.append(ln)
    return out


def parse_node(link):
    """只解析到 Clash proxy 所需的最小字段；解析失败返回 None。"""
    try:
        if link.startswith("ss://"):
            body = link[5:].split("#", 1)[0]
            name = urllib.parse.unquote(link.split("#", 1)[1]) if "#" in link else ""
            if "@" not in body:
                body = b64decode_padded(body)
            info, hostport = body.rsplit("@", 1)
            if ":" not in info:
                info = b64decode_padded(info)
            method, password = info.split(":", 1)
            server, port = hostport.split(":", 1)
            port = int(port.split("/")[0].split("?")[0])
            return {"type": "ss", "name": name or f"{server}:{port}",
                    "server": server, "port": port, "cipher": method,
                    "password": password, "link": link}
        if link.startswith("vmess://"):
            data = json.loads(b64decode_padded(link[8:].split("#", 1)[0]))
            return {"type": "vmess", "name": data.get("ps") or f"{data.get('add')}:{data.get('port')}",
                    "server": data["add"], "port": int(data["port"]),
                    "uuid": data["id"], "alterId": int(data.get("aid", 0)),
                    "cipher": "auto", "tls": data.get("tls") == "tls",
                    "network": normalize_network(data.get("net", "tcp")),
                    "ws-path": data.get("path", "/"),
                    "ws-host": data.get("host", ""),
                    "ws-headers": {"Host": data["host"]} if data.get("host") else {},
                    "servername": data.get("sni", "") or data.get("host", ""),
                    "fingerprint": data.get("fp", ""),
                    "alpn": data.get("alpn", ""),
                    "grpc-service-name": data.get("serviceName", ""),
                    "link": link}
        if link.startswith(("vless://", "trojan://")):
            proto = "vless" if link.startswith("vless") else "trojan"
            parsed = urllib.parse.urlparse(link)
            qs = urllib.parse.parse_qs(parsed.query)
            def q(k, d=""):
                return qs.get(k, [d])[0]
            node = {"type": proto, "name": urllib.parse.unquote(parsed.fragment) or f"{parsed.hostname}:{parsed.port}",
                    "server": parsed.hostname, "port": parsed.port,
                    "link": link}
            if proto == "vless":
                node["uuid"] = parsed.username
                # Reality 在技术上是 TLS 的一种伪装形式，握手看起来像访问真实网站，
                # 不能把它当成明文；之前版本把 reality 算成 tls=False 是错的，这里修正。
                node["security"] = q("security", "")
                node["tls"] = node["security"] in ("tls", "reality")
                node["reality"] = node["security"] == "reality"
                node["public_key"] = q("pbk", "")
                node["short_id"] = q("sid", "")
                node["network"] = normalize_network(q("type", "tcp"))
                node["servername"] = q("sni", "")
                node["flow"] = q("flow", "")
                node["fingerprint"] = q("fp", "")
                node["alpn"] = q("alpn", "")
                node["ws-path"] = q("path", "/")
                node["ws-host"] = q("host", "")
                node["grpc-service-name"] = q("serviceName", "")
                node["xhttp-path"] = q("path", "/")
                node["xhttp-mode"] = q("mode", "")
            else:
                node["password"] = parsed.username
                node["sni"] = q("sni", "")
                # trojan 两种写法都要兼容：标准 type=ws/grpc，以及老式的 ws=1&wspath=
                node["network"] = normalize_network(q("type", "ws" if q("ws") == "1" else "tcp"))
                node["ws-path"] = q("path", "") or q("wspath", "/")
                node["ws-host"] = q("host", "")
                node["grpc-service-name"] = q("serviceName", "")
                node["alpn"] = q("alpn", "")
                node["fingerprint"] = q("fp", "")
                node["skip-cert-verify"] = q("allowInsecure") == "1" or q("skip-cert-verify") == "true"
            return node
    except Exception:
        return None
    return None


def tcp_latency_ms(server, port):
    start = time.time()
    try:
        with socket.create_connection((server, port), timeout=CONNECT_TIMEOUT):
            return (time.time() - start) * 1000
    except Exception:
        return None


def yaml_escape(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ws_opts(p):
    if p.get("network") != "ws":
        return ""
    # WS 握手里 Host 很关键：原链接没给 host 时，用 sni/servername 兜底，
    # 否则 FlClash 会拿服务器 IP 当 Host，握手直接失败——这是上一版“一个都不能用”
    # 的主要原因之一。
    host = p.get("ws-host", "") or p.get("servername", "") or p.get("sni", "")
    path = p.get("ws-path", "/") or "/"
    if host:
        return f", ws-opts: {{path: {yaml_escape(path)}, headers: {{Host: {yaml_escape(host)}}}}}"
    return f", ws-opts: {{path: {yaml_escape(path)}}}"


def _grpc_opts(p):
    if p.get("network") != "grpc":
        return ""
    return f", grpc-opts: {{grpc-service-name: {yaml_escape(p.get('grpc-service-name', ''))}}}"


def _xhttp_opts(p):
    if p.get("network") != "xhttp":
        return ""
    mode = p.get("xhttp-mode", "")
    if mode:
        return f", xhttp-opts: {{path: {yaml_escape(p.get('xhttp-path', '/'))}, mode: {yaml_escape(mode)}}}"
    return f", xhttp-opts: {{path: {yaml_escape(p.get('xhttp-path', '/'))}}}"


# Clash/mihomo 不接受的字段会让整份配置导入失败，所以这里要归一化：
#   - network=raw（原始链接里表示裸 TCP）在 Clash 里不是合法 network，
#     必须写成 tcp；这是上一版“配置无法使用”最可能的直接原因。
#   - client-fingerprint 只保留 Clash 认识的值，unsafe 之类直接丢掉。
#   - alpn 在 Clash 里是列表，h2,http/1.1 要拆成 ["h2", "http/1.1"]。
VALID_FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"}


def normalize_network(net):
    if net in ("raw", "none", "", None):
        return "tcp"
    return net


def _extra_tls(p):
    out = ""
    fp = p.get("fingerprint", "")
    if fp in VALID_FINGERPRINTS:
        out += f", client-fingerprint: {yaml_escape(fp)}"
    if p.get("alpn"):
        parts = [x.strip() for x in str(p["alpn"]).split(",") if x.strip()]
        if parts:
            out += ", alpn: [" + ", ".join(yaml_escape(x) for x in parts) + "]"
    return out


def proxy_to_yaml(p):
    n = yaml_escape(p["name"])
    if p["type"] == "ss":
        return (f"  - {{name: {n}, type: ss, server: {p['server']}, port: {p['port']}, "
                f"cipher: {p['cipher']}, password: {yaml_escape(p['password'])}}}")
    if p["type"] == "vmess":
        tls = "true" if p.get("tls") else "false"
        base = (f"  - {{name: {n}, type: vmess, server: {p['server']}, port: {p['port']}, "
                f"uuid: {p['uuid']}, alterId: {p.get('alterId', 0)}, cipher: auto, tls: {tls}, "
                f"network: {p.get('network', 'tcp')}")
        if p.get("servername"):
            base += f", servername: {yaml_escape(p['servername'])}"
        base += _ws_opts(p) + _grpc_opts(p) + _xhttp_opts(p) + _extra_tls(p)
        return base + "}"
    if p["type"] == "vless":
        tls = "true" if p.get("tls") else "false"
        base = (f"  - {{name: {n}, type: vless, server: {p['server']}, port: {p['port']}, "
                f"uuid: {p['uuid']}, tls: {tls}, network: {p.get('network', 'tcp')}, "
                f"servername: {yaml_escape(p.get('servername', ''))}")
        if p.get("flow"):
            base += f", flow: {yaml_escape(p['flow'])}"
        base += _ws_opts(p) + _grpc_opts(p) + _xhttp_opts(p) + _extra_tls(p)
        if p.get("reality"):
            base += (f", reality-opts: {{public-key: {yaml_escape(p.get('public_key', ''))}, "
                     f"short-id: {yaml_escape(p.get('short_id', ''))}}}")
        return base + "}"
    if p["type"] == "trojan":
        base = (f"  - {{name: {n}, type: trojan, server: {p['server']}, port: {p['port']}, "
                f"password: {yaml_escape(p['password'])}, sni: {yaml_escape(p.get('sni', ''))}")
        if p.get("network") and p["network"] != "tcp":
            base += f", network: {p['network']}"
        base += _ws_opts(p) + _grpc_opts(p) + _extra_tls(p)
        if p.get("skip-cert-verify"):
            base += ", skip-cert-verify: true"
        return base + "}"
    return None


# fuzhang 格式重排（2026-11-01 用户选择）：节点改成块状 YAML（不再是单行 {...}），
# 并且 vless 补齐 fuzhang 那份里都有的字段：encryption: none、packet-encoding: xudp（ws 时）、
# udp、skip-cert-verify；vmess/trojan 也补 skip-cert-verify 和 udp，和 fuzhang 的取值一致
# （vless udp true，其余 udp false）。这样 FlClash 按配置导入时不再只看到最少字段。
def _block_opts_lines(p):
    lines = []
    if p.get("network") == "ws":
        host = p.get("ws-host", "") or p.get("servername", "") or p.get("sni", "")
        path = p.get("ws-path", "/") or "/"
        lines.append("    ws-opts:")
        lines.append(f"      path: {yaml_escape(path)}")
        if host:
            lines.append("      headers:")
            lines.append(f"        Host: {yaml_escape(host)}")
    if p.get("network") == "grpc":
        lines.append("    grpc-opts:")
        lines.append(f"      grpc-service-name: {yaml_escape(p.get('grpc-service-name', ''))}")
    if p.get("network") == "xhttp":
        lines.append("    xhttp-opts:")
        lines.append(f"      path: {yaml_escape(p.get('xhttp-path', '/'))}")
        if p.get("xhttp-mode"):
            lines.append(f"      mode: {yaml_escape(p['xhttp-mode'])}")
    return lines


def _block_tls_lines(p):
    lines = []
    fp = p.get("fingerprint", "")
    if fp in VALID_FINGERPRINTS:
        lines.append(f"    client-fingerprint: {yaml_escape(fp)}")
    if p.get("alpn"):
        parts = [x.strip() for x in str(p["alpn"]).split(",") if x.strip()]
        if parts:
            lines.append("    alpn:")
            for x in parts:
                lines.append(f"      - {yaml_escape(x)}")
    return lines


def proxy_to_block_lines(p):
    lines = [f"  - name: {yaml_escape(p['name'])}"]
    lines.append(f"    type: {p['type']}")
    lines.append(f"    server: {p['server']}")
    lines.append(f"    port: {p['port']}")
    if p["type"] == "ss":
        lines.append(f"    cipher: {p['cipher']}")
        lines.append(f"    password: {yaml_escape(p['password'])}")
    elif p["type"] == "vmess":
        lines.append(f"    uuid: {p['uuid']}")
        lines.append(f"    alterId: {p.get('alterId', 0)}")
        lines.append("    cipher: auto")
        lines.append(f"    tls: {'true' if p.get('tls') else 'false'}")
        if p.get("servername"):
            lines.append(f"    servername: {yaml_escape(p['servername'])}")
        lines.append(f"    network: {p.get('network', 'tcp')}")
        lines += _block_opts_lines(p)
        lines += _block_tls_lines(p)
        lines.append("    skip-cert-verify: false")
        lines.append("    udp: false")
    elif p["type"] == "vless":
        lines.append(f"    uuid: {p['uuid']}")
        if p.get("flow"):
            lines.append(f"    flow: {yaml_escape(p['flow'])}")
        lines.append(f"    tls: {'true' if p.get('tls') else 'false'}")
        lines.append(f"    servername: {yaml_escape(p.get('servername', ''))}")
        lines.append(f"    network: {p.get('network', 'tcp')}")
        lines += _block_opts_lines(p)
        if p.get("reality"):
            lines.append("    reality-opts:")
            lines.append(f"      public-key: {yaml_escape(p.get('public_key', ''))}")
            lines.append(f"      short-id: {yaml_escape(p.get('short_id', ''))}")
        lines += _block_tls_lines(p)
        lines.append("    encryption: none")
        if p.get("network") == "ws":
            lines.append("    packet-encoding: xudp")
        lines.append("    skip-cert-verify: false")
        lines.append("    udp: true")
    elif p["type"] == "trojan":
        lines.append(f"    password: {yaml_escape(p['password'])}")
        lines.append(f"    sni: {yaml_escape(p.get('sni', ''))}")
        if p.get("network") and p["network"] != "tcp":
            lines.append(f"    network: {p['network']}")
        lines += _block_opts_lines(p)
        lines += _block_tls_lines(p)
        lines.append(f"    skip-cert-verify: {'true' if p.get('skip-cert-verify') else 'false'}")
        lines.append("    udp: false")
    return lines


# 大陆使用时的审查风险过滤（2026-11-01 用户要求）：
#   保留：trojan（协议本身走 TLS）、vless tls、vless reality、vmess tls
#   去除：ss（无 TLS 层，流量特征易被识别）、vmess 明文、vless security=none/false/空
# 注意：这只是降低被识别的概率，不是保证不被封；节点本身仍可能被封 IP/域名。
DROP_RISKY = True


def is_risky(node):
    if not DROP_RISKY:
        return False
    if node["type"] == "ss":
        return True
    if node["type"] == "vmess":
        return not node.get("tls")
    if node["type"] == "vless":
        return node.get("security", "") not in ("tls", "reality")
    # trojan 协议本身走 TLS，保留
    return False


# 地区名补全：Au1rxx 的节点名本身是 vless-数字，没有地区。
# 用它按国家分的文件（output/by-country/clash-XX.yaml）做匹配，
# 按服务器:端口:协议找到国家，就把国家前缀写进名字。
# 只取主要国家，102 个全取太重；匹配不到的保留原名，不编造地区。
COUNTRY_CODES = ["JP", "US", "SG", "HK", "DE", "NL", "KR", "TW", "GB", "FR", "CA", "AU",
                 "TR", "IN", "PL", "RO", "SE", "FI", "ES", "IT", "CH", "AT", "DK", "NO",
                 "BR", "MX", "ZA", "TH", "VN", "MY", "ID", "PH",
                 "AE", "AL", "AM", "AR", "BA", "BE", "BG", "BY", "CL", "CY", "CZ",
                 "EE", "GR", "HU", "IE", "IL", "IR", "IS", "KZ", "LT", "LV", "MK",
                 "NZ", "PA", "PT", "RS", "RU", "UA"]
COUNTRY_NAMES = {
    "JP": ("🇯🇵", "日本"), "US": ("🇺🇸", "美国"), "SG": ("🇸🇬", "新加坡"),
    "HK": ("🇭🇰", "香港"), "DE": ("🇩🇪", "德国"), "NL": ("🇳🇱", "荷兰"),
    "KR": ("🇰🇷", "韩国"), "TW": ("🇹🇼", "台湾"), "GB": ("🇬🇧", "英国"),
    "FR": ("🇫🇷", "法国"), "CA": ("🇨🇦", "加拿大"), "AU": ("🇦🇺", "澳大利亚"),
    "TR": ("🇹🇷", "土耳其"), "IN": ("🇮🇳", "印度"), "PL": ("🇵🇱", "波兰"),
    "RO": ("🇷🇴", "罗马尼亚"), "SE": ("🇸🇪", "瑞典"), "FI": ("🇫🇮", "芬兰"),
    "ES": ("🇪🇸", "西班牙"), "IT": ("🇮🇹", "意大利"), "CH": ("🇨🇭", "瑞士"),
    "AT": ("🇦🇹", "奥地利"), "DK": ("🇩🇰", "丹麦"), "NO": ("🇳🇴", "挪威"),
    "BR": ("🇧🇷", "巴西"), "MX": ("🇲🇽", "墨西哥"), "ZA": ("🇿🇦", "南非"),
    "TH": ("🇹🇭", "泰国"), "VN": ("🇻🇳", "越南"), "MY": ("🇲🇾", "马来西亚"),
    "ID": ("🇮🇩", "印尼"), "PH": ("🇵🇭", "菲律宾"),
}


def fetch_country_mapping():
    mapping = {}
    for cc in COUNTRY_CODES:
        try:
            txt = fetch_text(f"https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-{cc}.yaml")
        except Exception as e:
            log(f"国家文件 {cc} 拉取失败 {e}")
            continue
        cur = {}
        for line in txt.splitlines():
            s = line.strip()
            if s.startswith("- name:"):
                if cur.get("server") and cur.get("port") and cur.get("type"):
                    mapping.setdefault((cur["server"], cur["port"], cur["type"]), cc)
                cur = {}
            elif s.startswith("server:"):
                cur["server"] = s.split(":", 1)[1].strip().strip('"').strip("'")
            elif s.startswith("port:"):
                try:
                    cur["port"] = int(s.split(":", 1)[1].strip())
                except Exception:
                    pass
            elif s.startswith("type:"):
                cur["type"] = s.split(":", 1)[1].strip()
        if cur.get("server") and cur.get("port") and cur.get("type"):
            mapping.setdefault((cur["server"], cur["port"], cur["type"]), cc)
    log(f"国家映射: {len(mapping)} 条")
    return mapping


# 地区范围（2026-11-01 用户要求：只留东亚、东南亚、北美，其他不要）
# 东亚：JP 日本、KR 韩国、TW 台湾、HK 香港（ mainland CN 不算：国内节点出不了墙，还多一层风险）
# 东南亚：SG 新加坡、MY 马来西亚、TH 泰国、VN 越南、ID 印尼、PH 菲律宾、KH 柬埔寨、LA 老挝、MM 缅甸
# 北美：US 美国、CA 加拿大、MX 墨西哥
ALLOWED_COUNTRIES = {"JP", "KR", "TW", "HK", "SG", "MY", "TH", "VN", "ID", "PH", "KH", "LA", "MM", "US", "CA", "MX"}
# proxypool 名字里的三字码 -> 二字码（只列常见，够判断是不是目标地区就行）
ISO3_TO_ISO2 = {"JPN": "JP", "KOR": "KR", "TWN": "TW", "HKG": "HK", "CHN": "CN",
                "SGP": "SG", "MYS": "MY", "THA": "TH", "VNM": "VN", "IDN": "ID", "PHL": "PH",
                "KHM": "KH", "LAO": "LA", "MMR": "MM", "USA": "US", "CAN": "CA", "MEX": "MX",
                "DEU": "DE", "NLD": "NL", "FRA": "FR", "GBR": "GB", "ITA": "IT", "ESP": "ES",
                "TUR": "TR", "POL": "PL", "RUS": "RU", "BRA": "BR", "AUS": "AU"}


def region_code(node, mapping):
    # 1) Au1rxx 国家文件匹配（服务器:端口:协议）
    cc = mapping.get((node["server"], node["port"], node["type"]))
    if cc:
        return cc
    # 2) 名字里的中文地区名（主要是 proxypool）
    for code, (flag, cn) in COUNTRY_NAMES.items():
        if cn in node["name"]:
            return code
    # 3) 名字末尾的三字码，如 "🇺🇸 美国 | USA"
    tail = node["name"].split("|")[-1].strip().upper()
    if tail in ISO3_TO_ISO2:
        return ISO3_TO_ISO2[tail]
    return None


def apply_region_names(nodes, mapping=None):
    if mapping is None:
        mapping = fetch_country_mapping()
    if not mapping:
        return 0
    changed = 0
    for node in nodes:
        name = node["name"]
        # 已有国旗/中文地区名的（主要是 proxypool）不动
        if "�" in name or any(cn in name for _, cn in COUNTRY_NAMES.values()):
            continue
        cc = mapping.get((node["server"], node["port"], node["type"]))
        if cc:
            if cc in COUNTRY_NAMES:
                flag, cn = COUNTRY_NAMES[cc]
                node["name"] = f"{flag} {cn} | {name}"
            else:
                node["name"] = f"{cc} | {name}"
            changed += 1
    log(f"补地区名: {changed} 个")
    return changed


def main():
    if not SOURCES:
        log("SOURCES 为空：请先填入公开订阅地址，本次不覆盖旧订阅。")
        return 2
    seen, nodes = set(), []
    risky = 0
    for url in SOURCES:
        try:
            links = split_links(fetch_text(url))
            log(f"{url}: 拉到 {len(links)} 条")
        except Exception as e:
            log(f"{url}: 拉取失败 {e}")
            continue
        for link in links:
            node = parse_node(link)
            if not node:
                continue
            if is_risky(node):
                risky += 1
                continue
            key = (node["server"], node["port"], node["type"],
                   node.get("uuid") or node.get("password"))
            if key in seen:
                continue
            seen.add(key)
            nodes.append(node)
    log(f"解析后去重: {len(nodes)} 个，因审查风险过滤掉: {risky} 个")
    if not nodes:
        log("无可用节点，不覆盖旧订阅。")
        return 3

    # 并发 TCP 测试
    alive = []
    with ThreadPoolExecutor(max_workers=TEST_WORKERS) as pool:
        futs = {pool.submit(tcp_latency_ms, n["server"], n["port"]): n for n in nodes}
        for fut in as_completed(futs):
            node, ms = futs[fut], fut.result()
            if ms is not None and ms <= MAX_LATENCY_MS:
                node["latency_ms"] = round(ms)
                alive.append(node)
    log(f"TCP 存活且延迟 <= {MAX_LATENCY_MS}ms: {len(alive)} 个")
    if not alive:
        log("筛选后为空，不覆盖旧订阅。")
        return 4

    # 地区过滤必须在取前 100 之前做，否则 GitHub 跑道（美国）测出的延迟会把
    # 欧洲节点排前面、把亚洲节点挤出前 100——这也是之前“基本用不了”的一个原因：
    # 从中国看，欧洲节点本来就远，还占了名额。
    # 先补地区名、再只留东亚/东南亚/北美、最后按延迟取前 100；地区未知的也去掉，
    # 因为无法证明它在目标地区，不编造地区。
    mapping = fetch_country_mapping()
    apply_region_names(alive, mapping)
    before_region = len(alive)
    alive = [n for n in alive if region_code(n, mapping) in ALLOWED_COUNTRIES]
    log(f"地区过滤: {before_region} -> {len(alive)} 个（只留东亚/东南亚/北美）")
    if not alive:
        log("地区过滤后为空，不覆盖旧订阅。")
        return 4
    alive.sort(key=lambda x: x["latency_ms"])
    alive = alive[:MAX_NODES]
    log(f"最终保留: {len(alive)} 个")
    for i, node in enumerate(alive, 1):
        node["name"] = f"{node['name']}-{i}" if alive else node["name"]

    # sub.yaml：订阅片段，节点改成块状写法（不再是单行 {...}）
    yaml_lines = ["proxies:"]
    for node in alive:
        yaml_lines += proxy_to_block_lines(node)
    yaml_lines += ["", "proxy-groups:", "  - name: PROXY", "    type: select", "    proxies:"]
    for node in alive:
        yaml_lines.append(f"      - {yaml_escape(node['name'])}")
    yaml_lines += ["", "rules:", "  - MATCH,PROXY"]
    yaml_text = "\n".join(yaml_lines) + "\n"

    # config.yaml：fuzhang 式完整配置，可直接按配置导入 FlClash，
    # 不再只靠订阅模式。节点和 sub.yaml 是同一批，只是多了顶层字段、
    # 三个策略组和 fuzhang 同款规则（国内直连、其余走漏网之鱼组）。
    cfg_lines = [
        "mixed-port: 7890", "allow-lan: false", "bind-address: '*'", "mode: rule",
        "log-level: info", "ipv6: false", "external-controller: 127.0.0.1:9090",
        "dns:", "  enable: true", "  ipv6: false", "  enhanced-mode: fake-ip",
        "  fake-ip-range: 198.18.0.1/16", "  nameserver:", "    - 223.5.5.5",
        "    - 119.29.29.29", "    - 8.8.8.8", "  fallback:",
        "    - tls://1.1.1.1:853", "    - tls://8.8.8.8:853",
        "geox-url:", "  geoip: https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
        "  geosite: https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
        "  mmdb: https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
        "", "proxies:",
    ]
    for node in alive:
        cfg_lines += proxy_to_block_lines(node)
    cfg_lines += ["", "proxy-groups:",
                  "  - name: 🚀 节点选择", "    type: select", "    proxies:",
                  "      - ♻️ 自动选择", "      - DIRECT"]
    for node in alive:
        cfg_lines.append(f"      - {yaml_escape(node['name'])}")
    cfg_lines += ["  - name: ♻️ 自动选择", "    type: url-test",
                  "    url: http://www.gstatic.com/generate_204", "    interval: 300",
                  "    proxies:"]
    for node in alive[:80]:
        cfg_lines.append(f"      - {yaml_escape(node['name'])}")
    cfg_lines += ["  - name: 🐟 漏网之鱼", "    type: select", "    proxies:",
                  "      - 🚀 节点选择", "      - DIRECT",
                  "", "rules:",
                  "  - DOMAIN-SUFFIX,cn,DIRECT",
                  "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
                  "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                  "  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
                  "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
                  "  - GEOIP,CN,DIRECT",
                  "  - MATCH,🐟 漏网之鱼"]
    config_text = "\n".join(cfg_lines) + "\n"

    # 原子写入：先写临时文件再 mv，避免 FlClash 读到一半的文件
    for path, text in ((OUTPUT_YAML, yaml_text),
                        (OUTPUT_TXT, "\n".join(n["link"] for n in alive) + "\n"),
                        (OUTPUT_CONFIG, config_text)):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    log(f"已写入 {OUTPUT_YAML} / {OUTPUT_TXT} / {OUTPUT_CONFIG}，共 {len(alive)} 个节点")
    return 0


if __name__ == "__main__":
    sys.exit(main())
