# -*- coding: utf-8 -*-
"""全局配置。"""
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 说明：本服务已全面改走「小红书 App 端协议 + 完全离线签名」（见 xhs_client.py），
# 不再依赖 Spider_XHS 的 web SDK 目录，原先的 SDK_DIR 配置已移除。

DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "xhs_admin.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# 后台默认密码（首次启动写入，可在系统设置里改；可用环境变量覆盖）
DEFAULT_PASSWORD = os.environ.get("XHS_ADMIN_PASSWORD") or "admin123"

# 对外访问地址（用于生成笔记的可点击链接）。部署后设为你实际访问的域名/IP，
# 例如 https://xhs.example.com。留空则链接为相对路径
# （仅在后台页面内可点击，推送到 IM 时需配置）。
PUBLIC_BASE_URL = (os.environ.get("XHS_PUBLIC_BASE_URL") or "").rstrip("/")


def public_note_url(note_id: str, note_type: str = "normal") -> str:
    """笔记的外部可访问链接（http 跳转页）。

    小红书网页版链接必须带 xsec_token（接口被风控拿不到），但 App 直达
    deeplink（xhsdiscover://）不需要 token。这里把 deeplink 包成 http 跳转页：
    任何 IM/浏览器都能点击 → 落地页自动唤起小红书 App 打开笔记。
    """
    t = "video" if note_type == "video" else "normal"
    path = f"/jump/{note_id}?type={t}"
    return PUBLIC_BASE_URL + path if PUBLIC_BASE_URL else path

# 登录 token 有效期（秒），0 表示不过期（直到服务重启）
TOKEN_TTL = int(os.environ.get("XHS_ADMIN_TOKEN_TTL") or 0)

# 调度器检查间隔（秒）：每隔这么久扫一遍是否到点
SCHEDULER_INTERVAL = int(os.environ.get("XHS_ADMIN_SCHEDULER_INTERVAL") or 20)

# 每轮最多抓取的博主数（错峰限流）。可用 XHS_ADMIN_MAX_PER_ROUND 覆盖。
# 实测（单账号 37 博主，充分冷却后复测）：并发 1~20 全成，无风控；但并发↑单请求延迟线性上升
# （4→3.2s、8→6.2s、16→10.8s），吞吐在 16 见顶后 20 反降。延迟最优=4，吞吐峰值=16。
# 默认取 4（延迟/安全平衡点）；要更高吞吐可提 6~8。调度器另有「风控自适应退避」兜底。
MAX_PER_ROUND = int(os.environ.get("XHS_ADMIN_MAX_PER_ROUND") or 4)

# 账号轮询切换间隔（分钟）：每过这么久自动切换到下一个健康账号继续监控。
# 可用 XHS_ADMIN_ACCOUNT_SWITCH_MINUTES 覆盖，也可在后台「系统设置」里改。
ACCOUNT_SWITCH_MINUTES = int(os.environ.get("XHS_ADMIN_ACCOUNT_SWITCH_MINUTES") or 10)

# 密码加盐（本机后台，固定盐即可；可用环境变量覆盖）
SALT = os.environ.get("XHS_ADMIN_SALT") or "xhs-admin-local-2026"

# 风控关键词：抓笔记接口命中这些字样即视为账号被风控（300011「账号异常」等）。
# scheduler 的自适应退避、账号检测接口都引用同一份。
RATE_LIMIT_KEYWORDS = ("账号异常", "稍后重试", "300011", "风控", "操作频繁")

# 登录失效关键词：笔记探测（get_user_note_info）在 cookie 失效/过期时返回这些字样
# （实测 web_session 过期返回「登录已过期，code -100」）。检测接口据此区分「失效」与「风控」。
EXPIRY_KEYWORDS = ("登录已过期", "未登录", "登录态无效", "登录态失效", "登录信息",
                   "must contain a1", "cookie 为空", "缺少 user_id")

# 每次抓取拉取的最新笔记条数（增量抓取：只取最新 N 条，不再每次拉 30 条重复处理旧笔记）。
# 可用 XHS_ADMIN_CRAWL_NUM 覆盖，也可在后台「系统设置」里改。
CRAWL_NUM = int(os.environ.get("XHS_ADMIN_CRAWL_NUM") or 5)

# 首次抓取（添加博主那一刻建基线）拉取的条数。默认 1：只取最新 1 条非置顶笔记。
FIRST_CRAWL_NUM = int(os.environ.get("XHS_ADMIN_FIRST_CRAWL_NUM") or 1)

# 推送时效窗口（毫秒）：新笔记的发布时间距「当前抓取时刻」超过该时长就不推送。
# 用于避免把「监控停摆期间漏抓的旧笔记」当成新笔记补推。默认 30 分钟，可用
# XHS_ADMIN_PUSH_MAX_AGE_MS 覆盖（单位毫秒），也可在后台「系统设置」里改。
PUSH_MAX_AGE_MS = int(os.environ.get("XHS_ADMIN_PUSH_MAX_AGE_MS") or 30 * 60 * 1000)

# 抓取博主间隔（毫秒）：同一轮里相邻两个博主的抓取启动时间错开这么久，
# 把并发请求在时间轴上打散、降低瞬时风控压力。默认 0 = 不错开（保持原并发行为）。
# 可用 XHS_ADMIN_CRAWL_INTERVAL_MS 覆盖，也可在后台「系统设置」里改。
CRAWL_INTERVAL_MS = int(os.environ.get("XHS_ADMIN_CRAWL_INTERVAL_MS") or 0)


# ---------- 运行时可调参数（后台「系统设置」可改，存 Setting 表，环境变量为兜底默认） ----------

TUNABLES_KEY = "tunables"

# 可调参数的合法范围（save_tunables 用；get_tunables 兜底越界值）
_TUNABLES_RANGE = {
    "crawl_num": (1, 30),
    "first_crawl_num": (1, 30),
    "max_per_round": (0, 20),  # 0 = 暂停抓取（不并发）
    "push_max_age_minutes": (0, 24 * 60),  # 0 表示不限制时效
    "account_switch_minutes": (1, 24 * 60),  # 账号轮询切换间隔
    "crawl_interval_ms": (0, 60000),  # 相邻博主抓取启动间隔（毫秒），0 = 不错开
}


def _default_tunables() -> dict:
    return {
        "crawl_num": CRAWL_NUM,
        "first_crawl_num": FIRST_CRAWL_NUM,
        "max_per_round": MAX_PER_ROUND,
        "push_max_age_minutes": PUSH_MAX_AGE_MS // 60000,
        "account_switch_minutes": ACCOUNT_SWITCH_MINUTES,
        "crawl_interval_ms": CRAWL_INTERVAL_MS,
    }


def get_tunables(db) -> dict:
    """读取可调参数。Setting 表里的值覆盖环境变量默认值；越界/非法回退默认。"""
    from db import Setting
    cfg = _default_tunables()
    try:
        s = db.get(Setting, TUNABLES_KEY)
        if s and s.value:
            data = json.loads(s.value)
            if isinstance(data, dict):
                for k, (lo, hi) in _TUNABLES_RANGE.items():
                    v = data.get(k)
                    if isinstance(v, int) and lo <= v <= hi:
                        cfg[k] = v
    except Exception:  # noqa: BLE001
        pass
    return cfg


def save_tunables(db, data: dict) -> dict:
    """保存可调参数（只接受合法字段与范围），返回归一化后的完整配置。"""
    from db import Setting
    cfg = _default_tunables()
    try:
        s = db.get(Setting, TUNABLES_KEY)
        if s and s.value:
            loaded = json.loads(s.value)
            if isinstance(loaded, dict):
                for k, (lo, hi) in _TUNABLES_RANGE.items():
                    v = loaded.get(k)
                    if isinstance(v, int) and lo <= v <= hi:
                        cfg[k] = v
    except Exception:  # noqa: BLE001
        pass
    for k, (lo, hi) in _TUNABLES_RANGE.items():
        if k in data and data[k] is not None:
            try:
                v = int(data[k])
            except (TypeError, ValueError):
                continue
            if lo <= v <= hi:
                cfg[k] = v
    s = db.get(Setting, TUNABLES_KEY)
    value = json.dumps(cfg, ensure_ascii=False)
    if s:
        s.value = value
    else:
        db.add(Setting(key=TUNABLES_KEY, value=value))
    db.commit()
    return cfg


def hash_password(pwd: str) -> str:
    import hashlib
    return hashlib.sha256((SALT + pwd).encode("utf-8")).hexdigest()
