#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cf-zt-cn-split v3 —— 把中国大陆 IP 段写进 Cloudflare Zero Trust 的 Split Tunnels

v3 相对 v2 的关键改动（2026-11-26）：
  v2 只写「按覆盖地址数贪心取前 MAX_RULES 条纯 IPv4 CIDR」，
  但本项目在 v2 之后又手工补过三组条目（CN IPv6 / 局域网私网段 / 微软世纪互联 CN 节点），
  而 Actions 每次运行都是**整表 PUT 覆盖**，于是这些补丁每周被冲掉一次：
      2026-11-22 Actions 跑完，线上只剩 1000 条纯 IPv4，24 条 CN IPv6 全没了
      → 国内大站的 AAAA（IPv6）流量全部进隧道 → 「能打开但极慢」
  v3 把这些补丁**焊进脚本**，并增加「保留线上手工条目」逻辑，让 Actions 每周跑完
  线上依然是完整集合（CN IPv4 + CN IPv6 + 局域网 + bing 补丁）。

v1 → v2 → v3 覆盖度对比：
  v1: 按文件顺序取 800 IP + 200 随机域名，只覆盖 27.33%
  v2: 按覆盖地址数贪心取 1000 条 CIDR → 98.06%（tight）/ 99.05%（overcover，但误伤 4.57M）
  v3: v2 + 29 条常驻补丁，IPv6 与局域网不再被覆盖冲掉

环境变量：
  CF_API_TOKEN   必填，Cloudflare API Token（Account -> Zero Trust: Edit）
  CF_ACCOUNT_ID  必填，账号 ID
  CF_PROFILE_ID  可选，设备配置 profile 的 ID；不填则用默认策略
  MODE           exclude（默认，列出的直连）/ include（列出的走隧道）
  MAX_RULES      CN IPv4 CIDR 条目上限，默认 1000
                 （实测 CF API 接受 2000 条，官方文档写的「1000 条硬上限」不成立；
                  常驻补丁另外算，所以总条数会略大于 1000）
  OVERCOVER      1 = 允许把稀疏 /16 整段并入（会多排除少量非 CN 地址），默认 0
  ALL_PROFILES   1（默认）= 给账号下所有设备 profile 写同一份列表（PC/手机保持一致）；0 = 只写一个
  EXTRAS         1（默认）= 写入常驻补丁（CN IPv6 / 局域网 / bing）；0 = 不写
  PRESERVE       1（默认）= 保留线上「手工加的」条目（描述不以 'CN IP' 开头的），
                 防止有人临时加的排除项被 Actions 冲掉；0 = 只写脚本算出的集合
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

# ---------------------------------------------------------------------------
# 常驻补丁（v3 新增）：每次写入都跟着走，Actions 覆盖也冲不掉
# ---------------------------------------------------------------------------

# 中国 IPv6 段（运营商主干 + CNNIC/教育网/科技网，覆盖国内绝大多数 IPv6 出口）
# 实测依据：国内大站全部有 AAAA，缺 IPv6 排除时 IPv6 流量全进隧道 → 极慢
CN_V6 = [
    ('2409::/16', 'CN IPv6 移动'),
    ('2408:8000::/20', 'CN IPv6 联通'),
    ('2408::/16', 'CN IPv6 联通'),
    ('2400:da00::/32', 'CN IPv6 联通'),
    ('240e::/16', 'CN IPv6 电信'),
    ('2001:250::/35', 'CN IPv6 教育网'),
    ('2001:251::/35', 'CN IPv6 科技网'),
    ('2001:da8::/32', 'CN IPv6 CERNET'),
    ('2001:cc0::/32', 'CN IPv6 CNNIC'),
    ('2400:3200::/32', 'CN IPv6 阿里云DNS'),
    ('2401:380::/32', 'CN IPv6 腾讯云'),
    ('2402:4e00::/32', 'CN IPv6 腾讯云'),
    ('2401::/16', 'CN IPv6 块'),
    ('2402::/16', 'CN IPv6 块'),
    ('2403::/16', 'CN IPv6 块'),
    ('2404::/16', 'CN IPv6 块'),
    ('2405::/16', 'CN IPv6 块'),
    ('2406::/16', 'CN IPv6 块'),
    ('2407::/16', 'CN IPv6 块'),
    ('240a::/16', 'CN IPv6 块'),
    ('240b::/16', 'CN IPv6 块'),
    ('240c::/16', 'CN IPv6 块'),
    ('240d::/16', 'CN IPv6 块'),
    ('240f::/16', 'CN IPv6 块'),
]

# 局域网私网段：加进排除列表后，局域网流量不进隧道
# 注意：绝不含 172.16.0.0/12 —— WARP 隧道自身接口就用 172.16.0.2，加了会断隧道
LAN_RANGES = [
    ('10.0.0.0/8', 'LAN 10.x'),
    ('192.168.0.0/16', 'LAN 192.168.x'),
    ('169.254.0.0/16', 'LAN link-local'),
    ('192.168.1.0/24', 'LAN home wifi'),
]

# 微软世纪互联 CN 节点：cn.bing.com 解析到 202.89.233.100/101，
# 不在 GeoIP2-CN 表里 → 走隧道 736ms，补上后转直连 20ms
EXTRA_SINGLE = [
    ('202.89.233.0/24', 'CN 微软世纪互联'),
]

# 脚本自动生成的 IPv4 条目统一用这个描述前缀，PRESERVE 靠它区分「手工条目」
AUTO_DESC_PREFIX = 'CN IP'


def env(key, default=""):
    """读环境变量并去掉首尾空白"""
    return os.environ.get(key, default).strip()


def fetch_text(url):
    """下载文本；本机 python 走 OpenSSL，能通 github（curl 的 schannel 不行）"""
    req = urllib.request.Request(url, headers={"User-Agent": "cf-zt-cn-split/3.0"})
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


def api_call(method, url, body=None, token=""):
    """调 Cloudflare API，返回 (status, text)"""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def policy_endpoints(base, pols):
    """
    列出 (显示名, exclude 端点 URL)。
    默认 profile 不带 ID（/devices/policy/exclude），
    具名 profile 带 policy_id 单数路径（/devices/policy/{policy_id}/exclude）。
    """
    out = []
    for p in pols:
        if p.get("default"):
            out.append((p.get("name") or "(默认)", "%s/policy/exclude" % base))
        else:
            out.append((p.get("name") or "(默认)", "%s/policy/%s/exclude" % (base, p.get("policy_id"))))
    return out


def merge_entries(auto_routes, live_entries, use_extras, preserve):
    """
    合并成最终要 PUT 的列表：
      auto_routes   脚本算出的 CN IPv4 网段
      live_entries 线上现有条目（用于保留手工加的）
      use_extras    是否加常驻补丁（CN IPv6 / 局域网 / bing）
      preserve      是否保留线上「描述不以 'CN IP' 开头」的手工条目
    按 address 去重，先自动条目后补丁后保留条目。
    """
    payload = []
    seen = set()

    def push(addr, desc):
        if addr in seen:
            return
        seen.add(addr)
        payload.append({"address": addr, "description": desc})

    for r in auto_routes:
        push(str(r), AUTO_DESC_PREFIX)

    if use_extras:
        for a, d in CN_V6 + LAN_RANGES + EXTRA_SINGLE:
            push(a, d)

    if preserve:
        for e in live_entries or []:
            addr = e.get("address")
            desc = e.get("description") or ""
            if not addr or desc.startswith(AUTO_DESC_PREFIX):
                continue
            push(addr, desc)

    return payload


def main():
    token = env("CF_API_TOKEN")
    account = env("CF_ACCOUNT_ID")
    profile = env("CF_PROFILE_ID")
    mode = env("MODE", "exclude").lower()
    limit = int(env("MAX_RULES", "1000"))
    overcover = env("OVERCOVER", "0") == "1"
    dry_run = env("DRY_RUN", "0") == "1"
    all_profiles = env("ALL_PROFILES", "1") == "1"
    use_extras = env("EXTRAS", "1") == "1"
    preserve = env("PRESERVE", "1") == "1"

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

    if dry_run:
        print("🧪 DRY_RUN=1，不写线上。样例前 5 条：")
        for r in routes[:5]:
            print("   ", r)
        print("   常驻补丁：CN IPv6 %d 条 / 局域网 %d 条 / 其他 %d 条"
              % (len(CN_V6), len(LAN_RANGES), len(EXTRA_SINGLE)))
        return

    if not token or not account:
        sys.exit("缺少 CF_API_TOKEN 或 CF_ACCOUNT_ID（可用 DRY_RUN=1 先试算）")

    base = "https://api.cloudflare.com/client/v4/accounts/%s/devices" % account

    # 取 profile 列表
    if all_profiles:
        st, txt = api_call("GET", base + "/policies", token=token)
        if st != 200:
            sys.exit("❌ 取 profile 列表失败 %s: %s" % (st, txt[:400]))
        pols = json.loads(txt).get("result") or []
        targets = policy_endpoints(base, pols)
    else:
        if profile:
            targets = [("指定 profile", "%s/policy/%s/%s" % (base, profile, mode))]
        else:
            targets = [("默认 profile", "%s/policy/%s" % (base, mode))]

    ok = 0
    for pname, purl in targets:
        # 先读线上现有条目（PRESERVE 要用）
        st, txt = api_call("GET", purl, token=token)
        live = []
        if st == 200:
            try:
                live = json.loads(txt).get("result") or []
            except Exception:
                live = []

        payload = merge_entries(routes, live, use_extras, preserve)
        v4 = sum(1 for e in payload if ":" not in e["address"])
        v6 = len(payload) - v4

        st, txt = api_call("PUT", purl, payload, token=token)
        if st not in (200, 204):
            print("❌ %s 写入失败 %s: %s" % (pname, st, txt[:300]))
            continue
        st, txt = api_call("GET", purl, token=token)
        got = (json.loads(txt).get("result") or []) if st == 200 else []
        got_v6 = sum(1 for e in got if ":" in (e.get("address") or ""))
        print("✅ %-14s 写入 %d 条（v4 %d / v6 %d）→ 回读线上 %d 条（IPv6 %d 条）"
              % (pname, len(payload), v4, v6, len(got), got_v6))
        ok += 1

    print("🎯 共 %d/%d 个 profile 写入成功" % (ok, len(targets)))
    print("⏳ 客户端最长 10 分钟同步；之后用 warp-cli settings / Find-NetRoute 复测")


if __name__ == "__main__":
    main()
