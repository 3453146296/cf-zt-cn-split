#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-zt-cn-split v2 —— 把中国大陆 IP 段写进 Cloudflare Zero Trust 的 Split Tunnels

和 v1 的区别（v1 只覆盖 27% 的 CN 地址空间）：
  v1: 按文件顺序取前 800 条 IP + 200 条随机域名（截止 103.x，110~223 段全漏）
  v2: 按「覆盖地址数」排序，取前 MAX_RULES 条 CIDR；可选把稀疏 /16 合并成整段，
      用同样 1000 条额度覆盖 98.06%（tight）或 99.05%（overcover）的 CN 地址。

环境变量：
  CF_API_TOKEN   必填，Cloudflare API Token（Account -> Zero Trust: Edit）
  CF_ACCOUNT_ID  必填，账号 ID
  CF_PROFILE_ID  可选，设备配置 profile 的 ID；不填则用默认策略
  MODE           exclude（默认，列出的直连）/ include（列出的走隧道）
  MAX_RULES      条目上限，默认 1000（官方：Split Tunnel + Local Domain Fallback 合计 1000）
  OVERCOVER      1 = 允许把稀疏 /16 整段并入（会多排除少量非 CN 地址），默认 0
  DRY_RUN        1 = 只算不写，打印统计与首尾样例

用法：
  DRY_RUN=1 python cf-zt-cn-split.py     # 先看效果
  python cf-zt-cn-split.py               # 真正写回 Cloudflare
"""
import os
import sys
import json
import ssl
import bisect
import ipaddress
import urllib.request
import urllib.error

IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"


def env(key, default=""):
    """读环境变量并去掉首尾空白"""
    return os.environ.get(key, default).strip()


def fetch_text(url):
    """下载文本；本机 python 走 OpenSSL，能通 github（curl 的 schannel 不行）"""
    req = urllib.request.Request(url, headers={"User-Agent": "cf-zt-cn-split/2.0"})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
        return resp.read().decode("utf-8", "replace")


def load_blocks(text):
    """把 CN-ip-cidr.txt 解析成 IPv4 网段列表（已是最小化、互不重叠）"""
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return [n for n in nets if n.version == 4]


def build_routes(blocks, limit, overcover):
    """
    选出覆盖 CN 地址最多的 limit 个网段。
    贪心：每次取「包含未覆盖 CN 地址最多」的候选；候选 = 原始块 + （可选）稀疏 /16 整段。
    返回 (routes, cn_covered, total_excluded)，单位是地址个数。
    """
    blocks = sorted(blocks, key=lambda n: int(n.network_address))
    starts = [int(n.network_address) for n in blocks]
    sizes = [n.num_addresses for n in blocks]
    ends = [s + z for s, z in zip(starts, sizes)]
    total_cn = sum(sizes)

    def span(net):
        """返回 net 完整包含的块下标区间 [i, j)，容纳不完整则返回 (i, i)"""
        a = int(net.network_address)
        b = a + net.num_addresses
        i = bisect.bisect_left(starts, a)
        j = i
        while j < len(blocks) and ends[j] <= b:
            j += 1
        if i < j and starts[i] >= a and ends[j - 1] <= b:
            return i, j
        return i, i

    cands = list(blocks)
    if overcover:
        # 把同一 /16 下的碎片合并成整段：1 条换多条，代价是多排除 /16 里非 CN 的地址
        seen = {}
        for n in blocks:
            if n.prefixlen <= 16:
                continue
            p = n.supernet(new_prefix=16)
            seen[int(p.network_address)] = p
        for p in seen.values():
            i, j = span(p)
            if i != j:
                cands.append(p)

    uniq = {str(c): c for c in cands}
    scored = []
    for c in uniq.values():
        i, j = span(c)
        scored.append((sum(sizes[i:j]), i, j, c))
    scored.sort(key=lambda t: -t[0])

    covered = [False] * len(blocks)
    routes, covered_cn, excluded_total = [], 0, 0
    for _, i, j, c in scored:
        if len(routes) >= limit:
            break
        gain, fresh = 0, []
        for k in range(i, j):
            if not covered[k]:
                gain += sizes[k]
                fresh.append(k)
        if gain == 0:
            continue
        routes.append(c)
        excluded_total += c.num_addresses
        for k in fresh:
            covered[k] = True
        covered_cn += gain

    routes.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    return routes, covered_cn, excluded_total, total_cn


def api_call(method, url, body=None):
    """调 Cloudflare API，返回 (status, text)"""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    global TOKEN
    TOKEN = env("CF_API_TOKEN")
    account = env("CF_ACCOUNT_ID")
    profile = env("CF_PROFILE_ID")
    mode = env("MODE", "exclude").lower()
    limit = int(env("MAX_RULES", "1000"))
    overcover = env("OVERCOVER", "0") == "1"
    dry_run = env("DRY_RUN", "0") == "1"

    if mode not in ("exclude", "include"):
        sys.exit("MODE 只能是 exclude 或 include，当前 = %r" % mode)

    print("🔄 拉取 CN IP 段 ...")
    blocks = load_blocks(fetch_text(IP_URL))
    print("   数据源：%d 段" % len(blocks))

    routes, covered_cn, excluded_total, total_cn = build_routes(blocks, limit, overcover)
    over = excluded_total - covered_cn
    print("   %-8s 条目=%d | CN 覆盖=%.2f%% (%d/%d) | 排除地址=%.1fM | 误伤非 CN=%.2fM"
          % ("max" if overcover else "tight", len(routes), covered_cn / total_cn * 100,
             covered_cn, total_cn, excluded_total / 1e6, over / 1e6))
    print("   首条=%s 末条=%s" % (routes[0], routes[-1]))

    payload = [{"address": str(r), "description": "CN IP"} for r in routes]

    if dry_run:
        print("🧪 DRY_RUN=1，不写线上。样例前 5 条：")
        for r in routes[:5]:
            print("   ", r)
        return

    if not TOKEN or not account:
        sys.exit("缺少 CF_API_TOKEN 或 CF_ACCOUNT_ID（可用 DRY_RUN=1 先试算）")

    base = "https://api.cloudflare.com/client/v4/accounts/%s/devices/policy" % account
    url = "%s/%s/%s" % (base, profile, mode) if profile else "%s/%s" % (base, mode)

    print("📤 PUT %s (%d 条) ..." % (url, len(payload)))
    status, text = api_call("PUT", url, payload)
    if status not in (200, 204):
        sys.exit("❌ 写入失败 %s: %s" % (status, text[:800]))
    if text.strip() and "\"success\": false" in text:
        sys.exit("❌ API 返回 success=false: %s" % text[:800])
    print("✅ 写入成功")

    # 回读校验：确认线上条数真的变了，而不是只信 PUT 的 200
    status, text = api_call("GET", url)
    if status != 200:
        print("⚠️ 回读失败 %s: %s" % (status, text[:300]))
        return
    try:
        got = json.loads(text).get("result") or []
        print("🔎 回读：线上 %d 条 | 首=%s 末=%s"
              % (len(got), got[0].get("host") or got[0].get("address") if got else "-",
                 got[-1].get("host") or got[-1].get("address") if got else "-"))
    except Exception as e:  # 回读失败不影响主流程，但必须响
        print("⚠️ 回读解析失败：%s" % e)

    print("⏳ 客户端最长 10 分钟同步；之后用 warp-cli settings / Find-NetRoute 复测")


if __name__ == "__main__":
    main()
