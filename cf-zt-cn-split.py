import requests
import os
import re

# 1. 读取环境变量（只认这两个！）
CF_API_TOKEN = os.getenv("CF_API_TOKEN")
ACCOUNT_ID   = os.getenv("CF_ACCOUNT_ID")

if not all([CF_API_TOKEN, ACCOUNT_ID]):
    raise ValueError("缺少环境变量！请在 GitHub Secrets 设置 CF_API_TOKEN、CF_ACCOUNT_ID")

HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json"
}

MAX_RULES       = 1000
TARGET_DOMAIN_N = 200

# 合法域名正则
VALID_DOMAIN_RE = re.compile(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

DOMAIN_URL = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/direct.txt"
IP_URL = "https://raw.githubusercontent.com/soffchen/GeoIP2-CN/release/CN-ip-cidr.txt"

def get_cn_cidrs():
    r = requests.get(IP_URL, timeout=30)
    r.raise_for_status()
    cidrs = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith('#')]
    print(f"   IP 数据源获取到 {len(cidrs)} 条 CIDR")
    return cidrs

def get_cn_domains():
    r = requests.get(DOMAIN_URL, timeout=30)
    r.raise_for_status()
    domains = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('DOMAIN-SUFFIX,'):
            line = line.replace('DOMAIN-SUFFIX,', '').strip()
        line = line.lstrip('.')
        if line and VALID_DOMAIN_RE.match(line):
            domains.append(f"*.{line}")
    unique = list(set(domains))
    print(f"   域名数据源获取到 {len(unique)} 条域名")
    return unique

def update_split_tunnels(cidrs, domains):
    max_domains = min(TARGET_DOMAIN_N, len(domains))
    max_ips     = min(MAX_RULES - max_domains, len(cidrs))

    domain_entries = [{"host":    d,    "description": "CN Domain"} for d    in domains[:max_domains]]
    ip_entries     = [{"address": cidr, "description": "CN IP"}     for cidr in cidrs[:max_ips]]
    routes = domain_entries + ip_entries

    print(f"   域名规则：{len(domain_entries)} 条 | IP 规则：{len(ip_entries)} 条 | 合计：{len(routes)} 条")

    # ==========================================
    # 核心：直接请求默认策略的排除列表（不带任何前缀或 ID）
    # ==========================================
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/devices/policy/exclude"
    
    # 发送 PUT 请求
    resp = requests.put(url, json=routes, headers=HEADERS)
    
    if resp.status_code in (200, 204):
        print(f"✅ 同步成功！{len(routes)} 条路由已写入 Cloudflare。")
    else:
        print(f"❌ 失败 {resp.status_code}: Cloudflare API 返回错误。")
        print(resp.text) # 如果还报错，把打印出的这行发给我
        resp.raise_for_status()

if __name__ == "__main__":
    print("🔄 拉取最新 CN geo 数据...")
    cidrs   = get_cn_cidrs()
    domains = get_cn_domains()
    update_split_tunnels(cidrs, domains)
