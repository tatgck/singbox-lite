# SNI 选择、Reality 回落与断流诊断

## 这次新加坡日志能说明什么

提供的日志显示 Reality 握手成功、VLESS 已认证，随后通过 direct 出站访问 `www.gstatic.com:443`，连接在约 247–284ms 后结束。这类短连接可能是客户端健康检查；片段没有超时、reset、认证失败或 OOM 的证据，不能据此断言 SNI、脚本或线路导致了断流，也不能据此证明长连接稳定。

`www.singtel.com` 在该日志中 CNAME 指向 `incapdns.net`，解析 IP 为 `45.60.35.24`，有明确的 Imperva/Incapsula CDN 证据。2026-10-10 查询 IP 数据库返回 AS19551 / Incapsula；数据库位置不是实测边缘位置，尤其不能用来断定 Anycast 流量绕行。新加坡品牌名称不代表新加坡源站。此域名在日志里握手成功，不能因为它使用 CDN 就断言它是本次断流原因。

日志源地址 `10.91.0.1` 是私网地址。应检查是否经过客户端 NAT、中转、容器或其他代理，并分别测试直连和中转路径。速度未显示不等于断流，短健康检查也不能替代真实下载/长连接测试。

## v29 筛选流程

1. 优先在菜单 `[20]` 选择自定义候选（默认选项）或本地文件，最多 12 个域名。只接受域名，不接受 URL、通配符、IP 段或命令。区域内置池只保留为未经验证的发现种子，不保证所有条目适合 Reality。
2. VPS 侧用 curl 的 HEAD 请求验证证书、强制 TLS1.3、协商 H2、HTTP 2xx、无跳转。同一解析 IPv4 必须连续三轮成功；每轮最多 6 秒。HEAD 不支持、临时 WAF 拦截或 IPv6-only 站点可能被保守排除，需另行人工测试。不会把测试 IP 固定写入生产配置。
3. 展示 CNAME、IP、ASN/国家信息以及 CDN/WAF 检测证据，默认排除检测到的 CDN。CDN 识别依据有限的 CNAME/组织名称；未知不等于直连源站。地理数据库、同国家与同 ASN 只是参考，不能证明同机房、低延迟或隐蔽性。
4. 中国出发点最多 5 个。目录中的 DNS IP 只能作为 VPS 向该 IP 发起 ping 的参考，不能把该 DNS 服务器变成主动测量探针。实际测试由 Globalping 中国探针发起，展示真实探针信息；目录数据本身未逐条核实。
5. 远程 HTTP 测量明确请求 HTTP/2 + HEAD，但 Globalping 不保证返回实际 ALPN 协商结果；TLS 成功与 HTTP 成功分开计数。城市精确匹配缺少有效探针（包括返回了探针但 HTTP 未通过）时，最多再请求一次同运营商 ASN 的中国探针；仅采用有效结果更多的回退数据，实际城市会单独标注，不冒充原选城市。同一探针不能满足同一运营商的多个出发点；缺探针或 HTTP 未成功的域名在任何模式下都只显示诊断，不进入排名。仅远程模式没有本地三轮稳定性/CDN 校验，不能单独用来推荐 Reality。
6. 从实际客户端复测节点：国内探针访问候选域名、中国探针 ping VPS、VPS 访问候选域名是三条不同路径，不等于“客户端 → VPS → 代理目标”的完整验证。Globalping 不保证返回 H2 协商结果，各次测量也不保证使用相同物理探针。

只有手动在 `[5]` 应用 SNI 才会修改节点。仅脚本生成的该节点专用自签证书可自动重签；共享证书、其他路径或正规 CA 证书保持不动，新 SNI 须已被现有证书覆盖，否则客户端可能拒绝连接。修改后会确认服务和原端口重新就绪；失败或正常信号中断时尝试恢复配置、客户端 YAML、元数据及本次重签的证书，并检查旧配置是否重新就绪。若磁盘/文件系统故障导致恢复失败，脚本会明确报错并保留快照；快照位于日志提示的私有临时目录，包含敏感信息，不应公开。强制断电或 `SIGKILL` 无法由脚本捕获。

## 域名来源与真实标准

- [XTLS/REALITY 官方说明](https://github.com/XTLS/REALITY)：国外站点、TLS1.3、H2、非跳转域名是基本筛选标准，IP 相近是加分项，不是必须同网段。
- [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner)：验证 TLS/ALPN/证书的方法可参考。项目提醒云端扫描可能使 VPS 被标记；本脚本不会自动扫描邻近网段，也不会运行扫描器的无限模式。
- [Ubuntu 官方镜像目录](https://launchpad.net/ubuntu/+archivemirrors)：可以按国家发现较少见的运营商/大学/托管商域名。目录记录可能仅支持 HTTP，必须独立确认 HTTPS、证书和 H2。例如新加坡目录包含 `mirror.sg.gs`、`mirror.0x.sg`、`mirror.soonkeat.sg`、`mirror.aktkn.sg`、`sg-mirrors.vhost.vn`，这些只是候选来源，未在你的 VPS 或国内实际客户端验证，且镜像站可能提供大文件，不宜把它们当作防回落滥用的默认答案。
- [Globalping](https://globalping.io/)：有公开 API 的跨地区测量服务。探针覆盖可能随时变化，有配额和外部故障；没有探针不代表候选域名或 VPS 被封。提交测试会向第三方服务披露目标域名、VPS IP 和所选测量位置。

优先考虑稳定的 HTTPS 小型站点、真实相近网络、良好证书和少量资源。不要选择本身就是代理入口、仅下载站、跳转站或证书无效站。“小众”无法保证国内可达、不被识别或不被封，SNI 筛选不是匿名性保证。

普通 AnyTLS 使用的是服务器自己的 TLS 证书，不是 Reality。第三方域名配自签证书并关闭验证，不能获得该域名的可信身份。普通 TLS 应使用你拥有且证书覆盖的域名，或按客户端能力固定自签证书指纹；不能把第三方 SNI 测试结果直接等同于普通 TLS 的可信伪装。

## 回落流量与防滥用边界

已认证 VLESS/Any-Reality 用户的目标流量不通过伪装网站；日志里的 direct 出站就是例子。绑定 CDN 本身不会把已认证用户流量交给 CDN。

Reality 未通过认证的连接可能被转发到固定握手目标，别人可利用这种回落访问目标网站，消耗 VPS 流量。随机 UUID/密码/私钥/Short ID 防止未授权代理认证，但不能彻底消除回落带宽滥用；不用 CDN 也不能保证零风险。

[sing-box 官方 TLS 配置](https://sing-box.sagernet.org/configuration/shared/tls/)及本库 `option/tls.go` 的 Reality 配置没有 Xray 的 `limitFallbackUpload` / `limitFallbackDownload`。不要把这些字段直接复制到 sing-box，否则配置可能无法启动。XTLS 还明确提醒固定回落限速本身可能形成特征。本次没有默认修改防火墙、限速或代理路由。

流量异常时先核对提供商带宽账单、连接来源/数量、目标流量及认证失败日志，再决定是否采用可维护的来源访问限制、自有握手站点或支持回落限速的另一核心。来源白名单会影响移动网络动态 IP；全端口限速会影响合法代理用户；只靠 SNI 或 Short ID 不能承诺防盗流量。

## 断流时需要采集什么

在故障发生时采集同一时间段的服务端和客户端日志、协议/核心版本、直连还是中转、客户端测试 URL。先做短连接和实际下载对照，不要仅看面板速度。

以下命令是 Linux 的只读诊断，不会改配置：

```bash
date -Is
/usr/local/bin/sing-box version
free -h
df -h / /var/log
ss -s
ss -tinp
dmesg -T | tail -n 80
```

systemd 使用 `journalctl -u sing-box --since '-10 min' --no-pager`；OpenRC/direct 检查 `/var/log/sing-box.log`。日志只保留故障窗口，注意遮盖 IP、UUID、密码、私钥和认证数据。生产环境通常用 `info`，按需临时开 `debug`；长期 `trace` 会暴露更多会话信息并增加 I/O，本次不强制覆盖已有日志等级。

另外分别检查 VPS 出站 IPv4/IPv6 DNS、TCP/TLS 与实际客户端到 VPS 的连通性。只在证据证明问题后再调整 DNS、IPv6、MTU 或 keepalive，不默认“优化”这些参数。ICMP 被禁或丢包不能单独证明 TCP 断流。

## 验证与发布

```bash
bash -n singbox.sh
bash scripts/test-sni.sh
git diff --check
```

回归测试使用模拟网络和临时配置，覆盖错误结果剔除、探针覆盖、CDN 策略及 SNI 修改回滚；不等于生产 Linux/Reality 端到端测试。发布前先在一个非关键节点运行 `[20]`，再手动修改并实测，保留原脚本和原配置。版本号为 v29，仓库中尚未提交/推送的本地改动不会自动出现在远端安装 URL。
