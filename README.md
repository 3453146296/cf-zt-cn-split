# cf-zt-split v3 —— 让 WARP 分流真正可用

## 这是什么
把中国大陆 IP 段写进 Cloudflare Zero Trust 的 **Split Tunnels（exclude 列表）**，
让国内流量直连、其余走 WARP。配套一份可自动跑的 GitHub Actions 工作流。

## v3 为什么存在（2026-11-26 实测）
v2 之后本项目又手工补过三组条目，但 **Actions 每次运行都是整表 PUT 覆盖**，
于是这些补丁每周被冲掉一次。实测对账：

```
2026-11-22 10:24  Actions run #45012253460 (sha f5a1be6) success
之后线上 exclude = 1000 条纯 IPv4 + 1 条 192.168.1.0/24
      → 24 条 CN IPv6 全没了
      → 10.0.0.0/8 / 192.168.0.0/16 / 169.254.0.0/16 全没了
      → 202.89.233.0/24（cn.bing.com 直连补丁）全没了
```

后果是实打实的：国内大站全有 AAAA，IPv6 排除一丢，**国内 IPv6 流量全进隧道**，
表现就是「能打开但极慢」；局域网段一丢，`192.168.x` 被 WARP 抢走。

v3 把这三组补丁**焊进脚本**，并新增「保留线上手工条目」：

| 常驻补丁 | 条数 | 作用 |
|---|---|---|
| CN IPv6 段 | 24 | 国内 AAAA 直连（2409/2408/240e/2401-240f/2001:da8 等） |
| 局域网私网段 | 4 | 10.0.0.0/8、192.168.0.0/16、169.254.0.0/16、192.168.1.0/24 |
| 微软世纪互联 | 1 | 202.89.233.0/24 → cn.bing.com 从 736ms 隧道转 20ms 直连 |

> ⚠️ **绝不能加 `172.16.0.0/12`** —— WARP 隧道自身接口就用 `172.16.0.2`，
> 把它排除进去会直接断隧道（已实测）。

## v1 → v2 → v3 覆盖度
| 模式 | 条目 | CN 地址覆盖 | 误伤非 CN |
|---|---|---|---|
| v1（原始） | 1000 | 27.33% | 0 |
| v2 tight | 1000 | **98.06%** | 0 |
| v2 max（/16 合并） | 1000 | **99.05%** | 4.57M 地址 |
| **v3 tight** | 1000 + 29 补丁 | **98.06%** | 0 |

官方文档写「Combined Split Tunnel and Local Domain Fallback entries per device profile = 1,000」
是**不准的**——实测 API 接受 2000 条；本项目实际线上 1029 条长期稳定运行。

## 语言 / 环境 / 依赖
- 语言：Python 3（脚本只用标准库 `urllib` / `ipaddress` / `json`，**不需要 pip install**）
- 本机运行：`python cf-zt-cn-split.py`（本机 python 走 OpenSSL，能直连 GitHub；
  `curl.exe` 的 schannel 不行，别用 curl 下载数据源）
- 云端运行：GitHub Actions，`ubuntu-latest` + `python 3.12`

## 环境变量
| 变量 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `CF_API_TOKEN` | 是 | — | Cloudflare API Token，权限：Account → **Zero Trust: Edit** |
| `CF_ACCOUNT_ID` | 是 | — | 账号 ID（dashboard URL 里 `/accounts/<这一段>/`） |
| `CF_PROFILE_ID` | 否 | — | 设备配置 profile ID；不填用默认策略 |
| `MODE` | 否 | `exclude` | `exclude`（列出的直连）/ `include`（列出的走隧道） |
| `MAX_RULES` | 否 | `1000` | CN IPv4 CIDR 条目上限（常驻补丁另外算） |
| `OVERCOVER` | 否 | `0` | `1` 时把稀疏 /16 整段并入，覆盖 99.05%，代价是多排除 4.57M 非 CN 地址 |
| `ALL_PROFILES` | 否 | `1` | `1` = 账号下所有设备 profile 写同一份列表（PC/手机一致）；`0` = 只写一个 |
| `EXTRAS` | 否 | `1` | `1` = 写入常驻补丁（CN IPv6 / 局域网 / bing）；`0` = 不写 |
| `PRESERVE` | 否 | `1` | `1` = 保留线上「手工加的」条目（描述不以 `CN IP` 开头），`0` = 只写脚本算出的集合 |
| `DRY_RUN` | 否 | `0` | `1` 只算不写 |

## 三种落地方式

### A. 本机直接写线上（最快，5 分钟）
```powershell
cd C:\DSH\cf-zt-split
$env:CF_API_TOKEN  = "你的token"
$env:CF_ACCOUNT_ID = "你的account id"
$env:DRY_RUN = "1"          # 先试算，确认数字
python cf-zt-cn-split.py
$env:DRY_RUN = "0"          # 再真写
python cf-zt-cn-split.py
```
写完后 WARP 客户端最长 10 分钟拉取新策略。

### B. 让 GitHub Actions 常驻（推荐，不碰 token）
1. 把 `cf-zt-cn-split.py` 覆盖仓库里的同名文件；
2. 把 `sync-cn-split.yml` 覆盖 `.github/workflows/sync-cn-split.yml`；
3. 仓库 Settings → Secrets 里已有 `CF_API_TOKEN`、`CF_ACCOUNT_ID`（v1 能跑说明已配好）；
4. Actions → 同步 CN Split Tunnels → Run workflow。
5. 若想用 99.05% 覆盖：仓库 Settings → Variables 加 `OVERCOVER=1`。

> **v3 的关键**：Actions 跑完不再是「1000 条纯 IPv4」，而是 **1029 条（含 IPv6/局域网/bing）**。
> 再加手工条目也不会被冲掉（`PRESERVE=1`）。

### C. 两条 1000 行清单（面板/导入用）
- `cn-exclude-1000-tight.txt`：零误伤，98.06%
- `cn-exclude-1000-max.txt`：99.05%，误伤 4.57M 非 CN 地址（这些地址会绕过 WARP 走直连）

## API 路径坑（踩过的）
- **默认 profile 不带 ID**：`/devices/policy/exclude`、`/devices/policy/fallback_domains`
- **具名 profile 带 policy_id 单数路径**：`/devices/policy/{policy_id}/exclude`
- **`fallback_domains` 的 PUT 直接收数组**，字段名 `suffix`；
  包成 `{"fallback_domains":[...]}` 会报 `400 code 2003 invalid json request`
- **`exclude` 的 PUT 收 `[{address, description}]`**，description 会原样存回

## 验收（三步）
1. `warp-cli settings`：Exclude 列表条数 = 1029，且出现 `220.x` / `223.x` / `2409:` / `10.0.0.0/8`；
2. `Find-NetRoute -RemoteIPAddress 223.5.5.5`、`220.181.38.148` 应显示 `WLAN` 而非 `CloudflareWARP`；
3. 访问国内站点延迟下降、国外站点仍能通。

## 回滚
面板 → Zero Trust → Team & Resources → Devices → Device profiles → 目标 profile → Configure →
Split Tunnels → `Restore default entries`（或把 v1 脚本再跑一次）。
