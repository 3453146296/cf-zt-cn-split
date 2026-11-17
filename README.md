# cf-zt-split v2 —— 让 WARP 分流真正可用

## 这是什么
把中国大陆 IP 段写进 Cloudflare Zero Trust 的 **Split Tunnels（exclude 列表）**，
让国内流量直连、其余走 WARP。配套一份可自动跑的 GitHub Actions 工作流。

## 为什么改
实测现状：线上列表 1000 条 = 800 条 IP（按文件顺序，截止 `103.19.46.0/23`）+ 200 条随机域名，
只覆盖 CN 地址空间的 **27.33%**。`Find-NetRoute` 实测 `223.5.5.5 / 114.114.114.114 /
220.181.38.148 / 106.11.0.1` 全部走 CloudflareWARP 隧道 —— 国内主流段全在隧道里，所以慢。

v2 改成**按覆盖地址数排序**，同样 1000 条额度：

| 模式 | 条目 | CN 地址覆盖 | 误伤非 CN |
|---|---|---|---|
| v1（现状） | 1000 | 27.33% | 0 |
| v2 tight | 1000 | **98.06%** | 0 |
| v2 max（/16 合并） | 1000 | **99.05%** | 4.57M 地址 |

官方硬顶：`Combined Split Tunnel and Local Domain Fallback entries per device profile = 1,000`。

## 语言 / 环境 / 依赖
- 语言：Python 3（脚本只用标准库 `urllib` / `ipaddress` / `json`，**不需要 pip install**）
- 本机运行：`python cf-zt-cn-split.py`（本机 python 走 OpenSSL，能直连 GitHub；
  `curl.exe` 的 schannel 不行，别用 curl 下载数据源）
- 云端运行：GitHub Actions，`ubuntu-latest` + `python 3.12`

## 环境变量
| 变量 | 必填 | 说明 |
|---|---|---|
| `CF_API_TOKEN` | 是 | Cloudflare API Token，权限：Account → **Zero Trust: Edit** |
| `CF_ACCOUNT_ID` | 是 | 账号 ID（dashboard URL 里 `/accounts/<这一段>/`） |
| `CF_PROFILE_ID` | 否 | 设备配置 profile ID；不填用默认策略 |
| `MODE` | 否 | `exclude`（默认）/ `include` |
| `MAX_RULES` | 否 | 默认 1000 |
| `OVERCOVER` | 否 | `1` 时把稀疏 /16 整段并入，覆盖 99.05%，代价是多排除 4.57M 非 CN 地址 |
| `DRY_RUN` | 否 | `1` 只算不写 |

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

### B. 让 GitHub Actions 常驻（不碰 token）
1. 把 `cf-zt-cn-split.py` 覆盖仓库里的同名文件；
2. 把 `sync-cn-split.yml` 覆盖 `.github/workflows/sync-cn-split.yml`；
3. 仓库 Settings → Secrets 里已有 `CF_API_TOKEN`、`CF_ACCOUNT_ID`（v1 能跑说明已配好）；
4. Actions → 同步 CN Split Tunnels → Run workflow。
若想用 99.05% 覆盖：仓库 Settings → Variables 加 `OVERCOVER=1`。

### C. 两条 1000 行清单（面板/导入用）
- `cn-exclude-1000-tight.txt`：零误伤，98.06%
- `cn-exclude-1000-max.txt`：99.05%，误伤 4.57M 非 CN 地址（这些地址会绕过 WARP 走直连）

## 验收（三步）
1. `warp-cli settings`：Exclude 列表条数 = 1000，且出现 `220.x` / `223.x`；
2. `Find-NetRoute -RemoteIPAddress 223.5.5.5`、`220.181.38.148` 应显示 `WLAN` 而非 `CloudflareWARP`；
3. 访问国内站点延迟下降、国外站点仍能通。

## 回滚
面板 → Zero Trust → Team & Resources → Devices → Device profiles → 目标 profile → Configure →
Split Tunnels → `Restore default entries`（或把 v1 脚本再跑一次）。
