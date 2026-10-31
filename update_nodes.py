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
                    "network": data.get("net", "tcp"),
                    "ws-path": data.get("path", "/"),
                    "ws-headers": {"Host": data["host"]} if data.get("host") else {},
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
                node["network"] = q("type", "tcp")
                node["servername"] = q("sni", "")
            else:
                node["password"] = parsed.username
                node["sni"] = q("sni", "")
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


def proxy_to_yaml(p):
    n = yaml_escape(p["name"])
    if p["type"] == "ss":
        return (f"  - {{name: {n}, type: ss, server: {p['server']}, port: {p['port']}, "
                f"cipher: {p['cipher']}, password: {yaml_escape(p['password'])}}}")
    if p["type"] == "vmess":
        tls = "true" if p.get("tls") else "false"
        return (f"  - {{name: {n}, type: vmess, server: {p['server']}, port: {p['port']}, "
                f"uuid: {p['uuid']}, alterId: {p.get('alterId', 0)}, cipher: auto, tls: {tls}, "
                f"network: {p.get('network', 'tcp')}, ws-path: {yaml_escape(p.get('ws-path', '/'))}}}")
    if p["type"] == "vless":
        tls = "true" if p.get("tls") else "false"
        base = (f"  - {{name: {n}, type: vless, server: {p['server']}, port: {p['port']}, "
                f"uuid: {p['uuid']}, tls: {tls}, network: {p.get('network', 'tcp')}, "
                f"servername: {yaml_escape(p.get('servername', ''))}")
        if p.get("reality"):
            base += (f", reality-opts: {{public-key: {yaml_escape(p.get('public_key', ''))}, "
                     f"short-id: {yaml_escape(p.get('short_id', ''))}}}")
        return base + "}"
    if p["type"] == "trojan":
        return (f"  - {{name: {n}, type: trojan, server: {p['server']}, port: {p['port']}, "
                f"password: {yaml_escape(p['password'])}, sni: {yaml_escape(p.get('sni', ''))}}}")
    return None


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
    alive.sort(key=lambda x: x["latency_ms"])
    alive = alive[:MAX_NODES]
    log(f"TCP 存活且延迟 <= {MAX_LATENCY_MS}ms: {len(alive)} 个")
    if not alive:
        log("筛选后为空，不覆盖旧订阅。")
        return 4

    for i, node in enumerate(alive, 1):
        node["name"] = f"{node['name']}-{i}" if alive else node["name"]

    names = ", ".join(yaml_escape(n["name"]) for n in alive)
    yaml_lines = ["proxies:"]
    for node in alive:
        line = proxy_to_yaml(node)
        if line:
            yaml_lines.append(line)
    yaml_lines += ["", "proxy-groups:",
                   f"  - {{name: PROXY, type: select, proxies: [{names}]}}",
                   "", "rules:", "  - MATCH,PROXY"]
    yaml_text = "\n".join(yaml_lines) + "\n"

    # 原子写入：先写临时文件再 mv，避免 FlClash 读到一半的文件
    for path, text in ((OUTPUT_YAML, yaml_text),
                        (OUTPUT_TXT, "\n".join(n["link"] for n in alive) + "\n")):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    log(f"已写入 {OUTPUT_YAML} / {OUTPUT_TXT}，共 {len(alive)} 个节点")
    return 0


if __name__ == "__main__":
    sys.exit(main())
