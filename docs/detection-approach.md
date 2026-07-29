# 从攻击流量生成到 C2 Beaconing 检测：方法论与 ATT&CK 映射

本文是 attack-traffic-generator 的技术说明：先讲这个靶场为什么能产出"真实"
的 C2 流量，再讲我们如何用两条互补的路径（离线 `tranalyzer` + 在线
Wazuh）从 Zeek 连接日志里检出 beaconing，最后给出 MITRE ATT&CK 映射。

面向读者：准备做紫队 / 检测工程 / SecOps 岗位的工程师。

## 1. 为什么需要"自己造"攻击流量

公开的恶意流量样本（如 Stratosphere IPSX、Malware-Traffic-Analysis）很
好，但有三个问题：

1. **没有"加噪"**：真实网络里 C2 流量是被海量正常流量淹没的。纯恶意
   pcap 里每个包都是恶意的，检测器在干净数据上跑出来的准确率没有参考
   价值。
2. **不可复现**：样本是一次性的，无法调参数（端口、心跳、payload）来
   测量检测器的边界。
3. **不可演化**：ATT&CK 在更新，EDR/NDR 在升级，检测工程需要能随时
   重放"今天这个版本"的攻击链。

本项目的做法（见 `range.yml`、`templates/`）：

- Vagrant 起一个隔离网段 `192.168.56.0/24`；
- 攻击者机（Kali）同时跑 **Metasploit** 与 **Cobalt Strike** 团队服务器，
  覆盖三种 C2 信道：reverse TCP、reverse HTTP、reverse HTTPS；
- 受害者机（Linux + Windows）回连生成各自的 beacon；
- `benign.sh` 通过 squid 代理随机抓取真实网页制造背景流量；
- `c2servers.sh` 在攻击者机上用 `tshark` 全程抓包。

由此得到一份"恶意 + 良性"混合的真实流量，检测器必须从噪声中把 beacon
挑出来——这正是 SecOps 工程师每天面对的场景。

## 2. C2 流量的三类指纹

Beacon（信标）是 C2 通信的本质：受控端周期性"打电话回家"，等指挥。
不同框架在三个维度上留指纹：

| 维度 | MSF meterpreter_reverse_tcp | MSF reverse_http(s) | Cobalt Strike beacon |
|------|------------------------------|---------------------|----------------------|
| 传输 | 原始 TCP 长连接 | HTTP/HTTPS 轮询 | HTTP/HTTPS 轮询 |
| 心跳 | 连接建立后常驻，无周期 | 周期 GET，jitter 小 | 可配 sleep+jitter（默认有 jitter） |
| 数据 | 交互式，突发大包 | 小请求 + 小响应 | 小请求 + 小响应，命令时才有大包 |
| 端口 | 任意（本靶场 7101-7103） | 任意非标准 | 任意非标准（本靶场 7202/7203） |

由此得到三条可落地的检测思路：

1. **周期性（Time regularity）**：连接时间间隔的离散度极低 → 像机器定时
   器，而非人。
2. **尺寸一致性（Data-size regularity）**：响应字节数高度一致 → 心跳包，
   而非真实浏览（真实浏览的响应尺寸方差极大）。
3. **非标准端口承载 web/加密协议**：`service=ssl` 却不在 443/8443 → 强
   C2 嫌疑。

## 3. 离线检测：`tranalyzer` 的 beaconing 评分

核心算法参考开源项目 RITA（Active Countermeasures）的 beacon score，实
现在 `src/c2_traffic_analyzer/`：

```
对每个 (src_ip, dst_ip, dst_port, proto) 通道：
  1. 连接数 < N（默认 10）           -> 丢弃
  2. 时间跨度 < 30 s                 -> 丢弃
  3. ts_score   = 1 - IQR(间隔) / 极差(间隔)      # 时间正则度
  4. ds_score   = 1 - IQR(响应字节) / 极差(字节)  # 尺寸正则度
  5. dur_score  = 1 - IQR(持续时长) / 极差(时长)
  6. beacon_score = mean(ts_score, ds_score, dur_score)
  7. 若 beacon_score >= 0.7 且 ts_score >= 0.5   -> 标记为 beacon
```

为什么用 **IQR / 极差** 而不是 stddev/mean？

- stddev 对异常值（如夜间网络断开造成的超长间隔）极度敏感；
- RITA 的做法是先剔除最长的一个间隔，再用 IQR 衡量"主体"的离散度；
- IQR 本身就是分位数，天然抗离群点。

工程上分成三层，便于单测（见 `tests/`，35 个用例）：

- `scoring.py`：纯函数的统计原语（`regularity_score`、`iqr`、
  `jitter_ratio`），无 IO，易测试；
- `beacon.py`：分组 + 打分 + 阈值过滤；
- `attack_mapping.py`：把 finding 映射到 ATT&CK 技术。

实测（合成数据见 `tests/conftest.py`）：

```
src_ip         dst_ip         dst_port ... beacon_score  techniques
192.168.56.44  192.168.56.33  7202      0.8929  T1071,T1071.001,T1571,T1132
192.168.56.41  192.168.56.33  7101      0.8890  T1071,T1571,T1132
```

两个 beacon 被命中，良性浏览（`56.51 -> 93.184.216.34:80`，间隔与尺寸都
高度随机）未被误报。这正是 beaconing 检测该有的表现。

## 4. 在线检测：Wazuh 规则

`tranalyzer` 是"事后复盘"，Wazuh 解决"流量回放时实时告警"。两者吃同一
份 Zeek 日志（`siem/`）：

| 规则 | 触发 | 等级 | 思路 |
|------|------|-----:|------|
| 100101 | 命中 `range.yml` 的 C2 端口 7101-7203 | 12 | 已知 IOC（端口） |
| 100102 | CS team_server 端口 50050 | 14 | 基础设施指纹 |
| 100103 | `service=ssl` 且端口非 443/8443 | 12 | 协议/端口错配 |
| 100110 | 120 s 内同源同目 ≥15 连接 | 10 | 频度启发式 |
| 100111 | 300 s 内同源同目 ≥40 连接 | 13 | 高置信 beacon |
| 100120 | C2 通道上 ≥1 MB 响应 | 11 | 工具下发（T1105） |

频度规则（`frequency` + `same_source_ip` + `same_destination_ip`）是
Wazuh/SIEM 平台最通用的 beaconing 原语：实现简单、可解释、零特征维护。
代价是粗糙——NTP、监控 agent 也会触发，需要 allow-list 抑制。

**两条路径如何互补**：SIEM 频度规则负责"先报警"，`tranalyzer` 的
IQR 评分负责"再确认"。把 `tranalyzer` 的 `beacon_findings.json` 当作
Wazuh 告警的复核与白名单来源——这是检测工程里典型的"低成本召回 +
高精度复核"两层结构。

## 5. MITRE ATT&CK 映射

| 现象 | ATT&CK | 说明 |
|------|--------|------|
| HTTP/HTTPS 承载 C2 | **T1071.001** Web Protocols | CS/MSF http(s) beacon |
| 任意应用层协议 C2 | **T1071** Application Layer Protocol | reverse_tcp 通用 |
| 加密信道 | **T1573.002** Asymmetric Cryptography | https/ssl beacon |
| 非标准端口 | **T1571** Non-Standard Port | 7101-7203 全部命中 |
| 通过 C2 下发工具 | **T1105** Ingress Tool Transfer | c2commands.sh 里的 `download` |
| 心跳数据编码 | **T1132** Data Encoding | beacon 请求体 |
| 内部代理转发 | **T1090.001** Internal Proxy | 靶场里的 squid（良性基础设施） |

映射的产物：`tranalyzer --format json` 输出的每条 finding 都带
`techniques` 字段；Wazuh 规则用 `<mitre><id>...</id></mitre>` 标注，可在
dashboard 的 ATT&CK 视图里直接钻取。

## 6. 局限与下一步

诚实说明边界，避免简历"过度包装"：

- **未覆盖**：域名/CDN 混淆（domain fronting、合法云域名做 C2）、mTLS
  pinning、可变形 beacon（sleep+jitter 抖动很大时 ts_score 会下降）、
  DNS over HTTPS、分阶段加载（stager）。这些是真实 APT 的演化方向，
  也是检测工程更难的部分。
- **靶场局限**：CS 4.4 较旧；流量在一个固定 /24 内，没有 NAT、没有企
  业代理链；用户行为（benign.sh）是 `curl` 模拟，真实办公流量更复杂。
- **可延伸的方向**（按性价比）：
  1. JA3/JA3S + HTTP 指纹接入，做 TLS client 指纹层检测；
  2. DNS 日志分析（`dns.log`）检出 tunneled C2（如 dnscat）；
  3. 把 `tranalyzer` 接入 SOAR：Wazuh 命中 → 触发复核 → 自动 allow/block；
  4. 引入 `zat`/polars 做长周期基线，从"阈值"升级到"异常"。

## 7. 复现路径

```sh
# 1) 起靶场、产 pcap
python startrange.py -r                      # 建 VM + 跑 C2 + 抓包

# 2) Zeek 解析为 JSON 日志
podman run --rm -v "$PWD/autorange:/in" -v "$PWD/zeek_logs:/out" zeek/zeek:lts \
  zeek -r /in/traffic.pcap local "Policy/tuning/json-logs.zeek" LogAscii::use_json=T

# 3a) 离线 beaconing 分析
tranalyzer zeek_logs/conn.log --format table

# 3b) 在线 SIEM 告警
cd siem && docker compose up -d && ./scripts/enable_zeek_ingest.sh
```

三个步骤、同一份数据，串起"造攻击 → 离线狩猎 → 在线告警"的完整闭环。
