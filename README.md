# 免费节点自动订阅（GitHub Actions 版）

每小时 17 分由 GitHub Actions 自动跑 `update_nodes.py`：

1. 从公开来源拉取节点（当前主来源：snakem982/proxypool 的 v2ray 纯链接）
2. 解析 ss / vmess / vless / trojan，去重
3. TCP 连通 + 延迟筛选（默认 3 秒超时、3000ms 以内、最多 100 个）
4. 生成 FlClash 可用的订阅文件并提交回本仓库

## FlClash 订阅地址

仓库建好后，把下面占位符换成实际仓库名：

```
https://raw.githubusercontent.com/<你的账号>/<仓库名>/main/sub.yaml
```

例如账号是 Icein1dgree、仓库名是 free-nodes-sub，地址就是：

```
https://raw.githubusercontent.com/Icein1dgree/free-nodes-sub/main/sub.yaml
```

## 注意事项

- 仓库必须是公开的，否则 FlClash 不带鉴权拉不到 raw 文件。
- 来源本身就是公开免费节点，重新发布不增加隐私风险，但公开节点不可信，
  不要用它登录重要账号。
- TCP 通不等于代理鉴权一定能用，最终以 FlClash 里实测为准。
- 来源全部失败或筛选后为空时，脚本不覆盖旧文件，只是不提交，
  FlClash 手里还是上一次的好文件。
- 手动立即跑一次：在仓库 Actions 页找到 Update free nodes，点 Run workflow。
