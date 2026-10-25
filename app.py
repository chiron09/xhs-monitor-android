# -*- coding: utf-8 -*-
"""小红书博主监控管理后台 —— FastAPI 主应用。"""
import os
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update

import json

import covers
import device_factory
import notifier
import scheduler
import xhs_client
from config import DEFAULT_PASSWORD, STATIC_DIR, TOKEN_TTL, get_tunables, hash_password, save_tunables
from db import Device, AuthToken, Blogger, Note, SessionLocal, Setting

# ---- 登录 token（持久化到 auth_tokens 表，重启后台不掉登录） ----
# TOKEN_TTL: 0 表示永不过期；>0 则登录后该秒数内有效。


def _token_expires_at() -> str:
    """按 TOKEN_TTL 计算过期时间；0 表示永不过期（空字符串）。"""
    if not TOKEN_TTL:
        return ""
    from datetime import timedelta
    return (datetime.now() + timedelta(seconds=TOKEN_TTL)).strftime("%Y-%m-%d %H:%M:%S")


def _is_expired(expires_at: str) -> bool:
    if not expires_at:
        return False
    try:
        return datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S") < datetime.now()
    except Exception:  # noqa: BLE001
        return True  # 时间格式异常一律视为过期，避免误放行


def _purge_expired_tokens(db) -> None:
    """清理已过期 token（启动与校验时顺带清理）。"""
    rows = db.query(AuthToken).filter(AuthToken.expires_at != "").all()
    dead = [r.token for r in rows if _is_expired(r.expires_at)]
    if dead:
        db.query(AuthToken).filter(AuthToken.token.in_(dead)).delete(synchronize_session=False)
        db.commit()


def _get_password_hash() -> str:
    db = SessionLocal()
    try:
        s = db.get(Setting, "admin_password")
        if s and s.value:
            return s.value
        h = hash_password(DEFAULT_PASSWORD)
        db.add(Setting(key="admin_password", value=h))
        db.commit()
        return h
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    _get_password_hash()  # 确保默认密码已写入
    db = SessionLocal()
    try:
        _purge_expired_tokens(db)  # 启动时清理过期 token
    finally:
        db.close()
    scheduler.start_scheduler()
    warm_direct_ip()  # 后台预热直连出口 IP（代理测试对照用）
    yield
    scheduler.stop_scheduler()


app = FastAPI(title="小红书博主监控后台", lifespan=lifespan)

# 封面图静态服务：目录保留、但当前抓取链路**不做本地化**（scheduler 里已改为
# 直接用笔记原 CDN 链接）。这里保留挂载是为了兼容历史数据里可能存在的 /covers/xxx
# 路径 —— 删掉会让老记录 404，所以只留机制不加逻辑。
os.makedirs(covers.COVERS_DIR, exist_ok=True)
app.mount("/covers", StaticFiles(directory=covers.COVERS_DIR), name="covers")

# 前端依赖本地化（vendor/ 放 vue / element-plus 等），避免依赖公网 CDN。
# 挂载在 /vendor 下，与 index.html 里的引用路径一致。
_VENDOR_DIR = os.path.join(STATIC_DIR, "vendor")
os.makedirs(_VENDOR_DIR, exist_ok=True)
app.mount("/vendor", StaticFiles(directory=_VENDOR_DIR), name="vendor")


# 最近活跃时间写库节流：同一 token 60 秒内只 commit 一次。
# 前端进页面会并发发 6 个请求，原来每个都 commit 一次 last_seen_at，
# 在 SQLite 上是纯写放大 + 写锁竞争（调度器同时在写库）。
_SEEN_LOCK = threading.Lock()
_SEEN_CACHE: dict = {}          # token -> 上次写库的 epoch 秒
_SEEN_INTERVAL = 60


def _touch_token(db, row) -> None:
    """按节流窗口更新 last_seen_at（仅用于排查「token 最近何时用过」）。"""
    now = time.time()
    with _SEEN_LOCK:
        if now - _SEEN_CACHE.get(row.token, 0) < _SEEN_INTERVAL:
            return
        _SEEN_CACHE[row.token] = now
        if len(_SEEN_CACHE) > 1000:      # 防无界增长：清掉早已过窗的条目
            for k, v in list(_SEEN_CACHE.items()):
                if now - v > _SEEN_INTERVAL * 10:
                    _SEEN_CACHE.pop(k, None)
    row.last_seen_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.commit()


def require_auth(authorization: str = Header(default="")):
    token = authorization.replace("Bearer", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="未登录")
    db = SessionLocal()
    try:
        row = db.get(AuthToken, token)
        if not row:
            raise HTTPException(status_code=401, detail="未登录")
        if _is_expired(row.expires_at):
            db.delete(row)
            db.commit()
            _SEEN_CACHE.pop(token, None)
            raise HTTPException(status_code=401, detail="登录已过期")
        _touch_token(db, row)
        return token
    finally:
        db.close()


# ---------- 登录失败限流（进程内，按来源 IP） ----------
# 窗口 5 分钟、容错 5 次、锁 5 分钟。反代场景取 X-Forwarded-For 首个地址。
_LOGIN_MAX_FAILS = 5
_LOGIN_WINDOW = 300
_LOGIN_LOCK_SECONDS = 300
_LOGIN_LOCK = threading.Lock()
_LOGIN_FAILS: dict = {}      # ip -> [失败 epoch 秒, ...]
_LOGIN_BANNED: dict = {}     # ip -> 解锁 epoch 秒


def _client_ip(request: Request) -> str:
    """真实来源 IP：优先 X-Forwarded-For 首个（nginx 反代），否则直连地址。"""
    fwd = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
    if fwd:
        return fwd
    return request.client.host if request.client else ""


def _login_guard(ip: str) -> None:
    """被锁期间直接 429，不再比对密码。"""
    if not ip:
        return
    now = time.time()
    with _LOGIN_LOCK:
        until = _LOGIN_BANNED.get(ip, 0)
        if until > now:
            raise HTTPException(
                status_code=429,
                detail=f"密码错误次数过多，请 {int(until - now)} 秒后再试")
        if until:
            _LOGIN_BANNED.pop(ip, None)     # 已解锁，清掉标记


def _login_fail(ip: str) -> None:
    if not ip:
        return
    now = time.time()
    with _LOGIN_LOCK:
        arr = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < _LOGIN_WINDOW]
        arr.append(now)
        _LOGIN_FAILS[ip] = arr
        if len(arr) >= _LOGIN_MAX_FAILS:
            _LOGIN_BANNED[ip] = now + _LOGIN_LOCK_SECONDS
            _LOGIN_FAILS[ip] = []
        # 顺手清理过期条目，避免长期运行后字典膨胀
        if len(_LOGIN_FAILS) > 500:
            for k in [k for k, v in _LOGIN_FAILS.items() if not v or now - v[-1] > _LOGIN_WINDOW]:
                _LOGIN_FAILS.pop(k, None)


def _login_ok(ip: str) -> None:
    if not ip:
        return
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(ip, None)
        _LOGIN_BANNED.pop(ip, None)


# ---------- 请求模型 ----------
class LoginRequest(BaseModel):
    password: str


class PasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=4, max_length=64)


class DeviceCreate(BaseModel):
    name: str = ""
    payload: str = ""          # mode=import 时：设备材料 JSON 字符串
    mode: str = "import"       # import | generate
    ssaid: str = ""            # mode=generate 时：16 位 hex，留空随机
    proxy: str = ""            # 可选：该设备的出口代理（http(s):// / socks5://）


class DeviceUpdate(BaseModel):
    """编辑设备：名称/机型/状态/payload/代理 均为可选，未传的字段保持不变。"""
    name: str | None = None
    label: str | None = None
    status: str | None = None
    payload: str | None = None
    proxy: str | None = None


class BloggerCreate(BaseModel):
    name: str = ""
    url: str = Field(min_length=1)
    monitor_start: str = ""
    monitor_end: str = ""


class BloggerUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    monitor_start: str | None = None
    monitor_end: str | None = None
    status: str | None = None


class NotesDelete(BaseModel):
    ids: list[int]


class FollowingsListRequest(BaseModel):
    device_id: int


class ImportFollowingsRequest(BaseModel):
    device_id: int
    items: list[dict]
    monitor_start: str = ""
    monitor_end: str = ""


class NotesClear(BaseModel):
    blogger_id: int | None = None


class BatchUpdateRequest(BaseModel):
    ids: list[int]
    # 只更新显式传入的字段：批量弹窗里没填的项保持原值不动
    monitor_start: str | None = None
    monitor_end: str | None = None
    clear_window: bool = False


_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _norm_hhmm(value: str | None) -> str:
    """把 'HH:MM' 规整成 'HH:MM'（补零）；空 → ''；非法 → 抛 400。"""
    v = (value or "").strip()
    if not v:
        return ""
    parts = v.split(":")
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail=f"时间格式应为 HH:MM，收到「{value}」")
    try:
        h, m = int(parts[0]), int(parts[1])
    except ValueError:
        raise HTTPException(status_code=400, detail=f"时间格式应为 HH:MM，收到「{value}」")
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise HTTPException(status_code=400, detail=f"时间超出范围（00:00-23:59）：「{value}」")
    return f"{h:02d}:{m:02d}"


def _blogger_uid(url_or_id: str) -> str:
    """从博主主页链接或裸 user_id 提取 24 位 id。"""
    v = (url_or_id or "").strip()
    if re.fullmatch(r"[0-9a-f]{24}", v):
        return v
    m = re.search(r"/user/profile/([0-9a-f]{24})", v)
    if m:
        return m.group(1)
    try:
        from urllib.parse import urlparse
        path = urlparse(v).path.rstrip("/")
        tail = path.split("/")[-1]
        return tail if re.fullmatch(r"[0-9a-f]{24}", tail) else ""
    except Exception:
        return ""


def _check_window(start: str, end: str) -> None:
    """时段合法性：单端可空；两端相同视为无意义配置，直接拒绝。"""
    if start and end and start == end:
        raise HTTPException(status_code=400, detail="监控时段的开始与结束时间不能相同（如需全天监控请都留空）")


# ---------- 页面 ----------
@app.api_route("/", methods=["GET", "HEAD"])
def index():
    # no-cache：HTML 每次都向服务器校验（ETag/Last-Modified），改版后浏览器不会
    # 拿旧缓存白屏或用旧样式。vendor 静态资源走 StaticFiles 自带的 ETag 校验。
    # 同时支持 HEAD（健康检查/浏览器预检不再 405）。
    return FileResponse(os.path.join(STATIC_DIR, "index.html"),
                        headers={"Cache-Control": "no-cache"})


@app.get("/jump/{note_id}")
def jump_note(note_id: str, type: str = "normal"):
    """笔记跳转页：把 App deeplink 包装成 http 链接。

    手机浏览器打开本页 → 自动唤起小红书 App 打开对应笔记（不需要 xsec_token）。
    用于推送/后台里"能点击的链接"——http 链接各 IM 都识别，落地后转 deeplink。
    """
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9]{16,32}", note_id or ""):
        raise HTTPException(status_code=400, detail="note_id 不合法")
    scheme = (f"xhsdiscover://video_feed/{note_id}" if type == "video"
              else f"xhsdiscover://item/{note_id}")
    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>正在打开小红书…</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;
       background:#f7f7f9;color:#333}}
  .box{{text-align:center;padding:32px;max-width:340px}}
  .sp{{width:34px;height:34px;border:3px solid #ff2e4d;border-top-color:transparent;
      border-radius:50%;animation:r 0.8s linear infinite;margin:0 auto 18px}}
  @keyframes r{{to{{transform:rotate(360deg)}}}}
  .tip{{display:none;margin-top:14px;font-size:14px;color:#888;line-height:1.7}}
  a{{color:#ff2e4d;text-decoration:none}}
</style>
</head>
<body>
<div class="box">
  <div class="sp"></div>
  <div>正在尝试打开小红书 App…</div>
  <div class="tip" id="tip">
    未能自动唤起 App。<br>
    请确认已安装小红书；<br>
    或在手机浏览器地址栏粘贴：<br>
    <a href="{scheme}">{scheme}</a>
  </div>
</div>
<script>
  var scheme = {scheme!r};
  window.location.href = scheme;
  setTimeout(function(){{ document.getElementById('tip').style.display = 'block'; }}, 1600);
</script>
</body>
</html>"""
    return HTMLResponse(html)


# ---------- 认证 ----------
@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request):
    # 失败次数限流：同一来源 5 分钟内错 5 次 → 锁 5 分钟。
    # 原来没有任何限制，admin123 这种默认密码可被无限次暴力试。
    ip = _client_ip(request)
    _login_guard(ip)
    if hash_password(req.password) != _get_password_hash():
        _login_fail(ip)
        raise HTTPException(status_code=401, detail="密码错误")
    _login_ok(ip)
    token = secrets.token_hex(32)
    db = SessionLocal()
    try:
        db.add(AuthToken(
            token=token,
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            expires_at=_token_expires_at(),
            last_seen_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user_agent=(request.headers.get("user-agent") or "")[:256],
            remote_addr=(request.client.host if request.client else "")[:64],
        ))
        db.commit()
    finally:
        db.close()
    return {"token": token, "expires_in": TOKEN_TTL}


@app.post("/api/auth/logout")
def logout(authorization: str = Header(default="")):
    token = authorization.replace("Bearer", "").strip()
    if token:
        db = SessionLocal()
        try:
            row = db.get(AuthToken, token)
            if row:
                db.delete(row)
                db.commit()
        finally:
            db.close()
    return {"ok": True}


@app.get("/api/auth/status")
def auth_status(authorization: str = Header(default="")):
    token = authorization.replace("Bearer", "").strip()
    if not token:
        return {"authed": False}
    db = SessionLocal()
    try:
        row = db.get(AuthToken, token)
        if not row:
            return {"authed": False}
        if _is_expired(row.expires_at):
            db.delete(row)
            db.commit()
            return {"authed": False}
        return {"authed": True}
    finally:
        db.close()


@app.post("/api/auth/password")
def change_password(req: PasswordRequest, _=Depends(require_auth)):
    if hash_password(req.old_password) != _get_password_hash():
        raise HTTPException(status_code=401, detail="旧密码错误")
    db = SessionLocal()
    try:
        s = db.get(Setting, "admin_password")
        new_hash = hash_password(req.new_password)
        if s:
            s.value = new_hash
        else:
            # 兜底：Setting 行缺失（例如库被手工清过）时直接补建，不再 AttributeError
            db.add(Setting(key="admin_password", value=new_hash))
        db.commit()
    finally:
        db.close()
    # 改密后强制重新登录：清空所有 token
    db = SessionLocal()
    try:
        db.query(AuthToken).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    return {"ok": True}


# ---------- 监控参数（后台可调） ----------
@app.get("/api/settings/tunables")
def get_tunables_api(_=Depends(require_auth)):
    db = SessionLocal()
    try:
        return get_tunables(db)
    finally:
        db.close()


@app.post("/api/settings/tunables")
def save_tunables_api(req: dict, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        cfg = save_tunables(db, req or {})
        return {"ok": True, "config": cfg}
    finally:
        db.close()


# ---------- 账号管理 ----------
@app.get("/api/devices/material_audit")
def devices_material_audit(_=Depends(require_auth)):
    """设备材料一致性体检（只读）。problems 为空 = 合格。

    查的是服务端真的会校验的几条（已确证）：
      · UA 的 Version/x Build/y ↔ cp.versionName / cp.build ↔ platform_info.build
      · mua 头 v ↔ 材料版本（9.49.1→2.10.1，9.19.2→2.9.55）
      · cp.cpu_abi（9.49.1 必须是 armeabi-v7a，官方只发 v7a）
      · 必需字段 device_id / did / hmac / key64 / mua0 / cp / platform_info / user_agent

    存量 9.19.2 设备（payload 无 ver）只查内部一致性，不会被误判。
    """
    db = SessionLocal()
    try:
        ok, bad = [], []
        for d in db.query(Device).order_by(Device.id.asc()).all():
            p = d.payload_dict()
            probs = device_factory.verify_material(p)
            item = {"id": d.id, "name": d.name, "status": d.status,
                    "ver": p.get("ver") or "(存量)",
                    "problems": probs}
            (ok if not probs else bad).append(item)
        return {"ok": True, "total": len(ok) + len(bad),
                "consistent": len(ok), "with_problems": len(bad),
                "ok_devices": ok, "bad_devices": bad,
                "rule": "UA Version/Build ↔ cp versionName/build ↔ platform_info build；"
                        "mua_v ↔ ver；cpu_abi=armeabi-v7a(9.49.1)；必需字段齐全"}
    finally:
        db.close()


@app.get("/api/reverse/selftest")
def reverse_selftest(_=Depends(require_auth)):
    """逆向成果自检（**纯离线，不发任何网络请求**）。

    覆盖：盾构造 / perm8 / s1 / SIG / 材料一致性规则。
    部署后或改签名相关代码后跑一次，比人工敲 python 靠得住。
    """
    import base64 as _b64
    import json as _json
    import xhs_core
    import xhs_perm
    import device_factory as _df

    checks = []

    def ck(name, fn):
        try:
            checks.append({"check": name, "ok": True, "detail": str(fn())})
        except Exception as e:  # noqa: BLE001
            checks.append({"check": name, "ok": False,
                           "detail": "%s: %s" % (type(e).__name__, str(e)[:120])})

    DEV = '0123456789abcdef0123456789abcdef'
    CP = 'app_id=ECFAAF01&versionName=9.49.1&build=9491803&deviceId=' + DEV
    PI = 'platform=android&build=9491803&deviceId=' + DEV

    def _shield():
        sh = _df._make_shield_no_hmac('/api/sns/v6/homefeed', 'num=1', DEV, CP, PI, 'fs=0&point=601')
        assert isinstance(sh, str) and sh.startswith('XY'), 'shield 前缀不对: %r' % sh[:6]
        assert len(sh) > 80, 'shield 太短: %d' % len(sh)
        return 'len=%d 前缀=%s' % (len(sh), sh[:10])

    def _perm8():
        assert xhs_perm._self_test() is True, 'perm8 自检失败'
        got = xhs_perm.make_perm8_zero(1792754000)
        assert got == [7, 6, 3, 1, 0, 2, 5, 4], 'perm8 基准值不符: %s' % got
        assert xhs_perm.make_perm8_zero(1792754001) != got, 'perm8 不随 ts 变化'
        return 'ts=1792754000 → %s' % got

    def _s1():
        ts = 1792754000
        p8, p4 = xhs_perm.make_perm8_zero(ts), xhs_perm.make_perm4_zero(ts)
        real = xhs_core.make_s1(b'canon', 1, ts, p8, p4)
        ident = xhs_core.make_s1(b'canon', 1, ts, list(range(8)), list(range(4)))
        assert real != ident, 's1 没接上真 perm8/perm4（与恒等输出相同）'
        assert len(real) > 60, 's1 太短: %d' % len(real)
        return 'len=%d perm8=%s perm4=%s 与恒等不同=是' % (len(real), p8, p4)

    def _perm4():
        # perm4 2026-10-26 破解基准值（363/363 真实 s1 样本反推）
        assert xhs_perm.make_perm4(1792754000) == [2, 1, 3, 4], \
            'perm4 基准值不符: %s' % xhs_perm.make_perm4(1792754000)
        assert xhs_perm.make_perm4(1792069748) == [2, 3, 4, 1], \
            'perm4 基准值不符: %s' % xhs_perm.make_perm4(1792069748)
        assert xhs_perm.make_perm4(1791636050) == [3, 1, 2, 4], \
            'perm4 基准值不符: %s' % xhs_perm.make_perm4(1791636050)
        assert xhs_perm.make_perm4_zero(1792754000) == [1, 0, 2, 3], 'perm4 0-based 换算错'
        return 'ts=1792754000 → %s' % xhs_perm.make_perm4(1792754000)

    def _sig():
        sig = xhs_core.compute_sig(b'canon')
        assert isinstance(sig, str) and len(sig) == 64, 'sig 长度不对: %r' % (len(sig) if sig else None)
        return 'len=64'

    def _mat_rule():
        mk = lambda v: _b64.urlsafe_b64encode(
            _json.dumps({'v': v, 'c': 1}).encode()).decode().rstrip('=')
        good = {'device_id': 'x' * 8, 'did': 'd' * 8, 'hmac': 'h', 'key64': 'k' * 8,
                'user_agent': 'X Version/9.49.1 Build/9491803 Y',
                'cp': 'versionName=9.49.1&cpu_abi=armeabi-v7a&build=9491803',
                'platform_info': 'platform=android&build=9491803&deviceId=x',
                'mua0': mk('2.10.1') + '.b.s', 'ver': '9.49.1'}
        assert _df.verify_material(good) == [], '合格材料被误判: %s' % _df.verify_material(good)
        bad = dict(good)
        bad['cp'] = bad['cp'].replace('build=9491803', 'build=9192809')
        assert _df.verify_material(bad), '坏材料没被检出'
        return '合格样本通过、坏样本被拦（%d 条问题）' % len(_df.verify_material(bad))

    ck('shield', _shield)
    ck('perm8', _perm8)
    ck('perm4', _perm4)
    ck('s1', _s1)
    ck('sig', _sig)
    ck('material_rule', _mat_rule)

    passed = sum(1 for c in checks if c["ok"])
    return {"ok": passed == len(checks), "passed": passed,
            "total": len(checks), "checks": checks}


# ============ 逆向资产库（只读查询，不改抓取逻辑） ============
# 数据来自 9.51.0 APK 全部 22 个 dex 的静态提取：1644 条 path / 124 个头 / 62 个命令号
# 存放目录：data/reverse/（缺文件时返回空集，不影响主流程）


@app.get("/api/reverse/assets")
def reverse_assets(_=Depends(require_auth)):
    """资产总览：接口数 / 头数 / 命令号数 / 业务族分布 / 吃额度的接口数。"""
    from xhs_assets import assets
    return {"ok": True, **assets.summary()}


@app.get("/api/reverse/classify")
def reverse_classify(path: str, _=Depends(require_auth)):
    """给一条 path，返回业务族 + 额度级别 + 是否在已知全集里。

    例：/api/reverse/classify?path=/api/sns/v6/homefeed
    """
    from xhs_assets import assets
    kind = assets.quota_kind(path)
    return {"ok": True, "path": path, "family": assets.classify(path),
            "quota_kind": kind, "is_quota": kind != 'normal',
            "quota_desc": assets.quota_desc(path), "known": assets.exists(path)}


@app.get("/api/reverse/quota")
def reverse_quota(_=Depends(require_auth)):
    """列出所有吃内容额度的接口（抓取调度参考：别按名字猜额度）。"""
    from xhs_assets import assets
    rows = assets.quota_paths()
    return {"ok": True, "total": len(rows),
            "items": [{"path": p, "kind": k, "desc": assets.quota_desc(p)} for p, k in rows]}


@app.get("/api/reverse/cmd")
def reverse_cmd(name: str = "sign", _=Depends(require_auth)):
    """查 libtiny 命令号。name 支持 sign / sign951 / init / cfg，或直接给 hex。"""
    from xhs_assets import assets
    info = assets.cmd(name)
    if not info:
        raise HTTPException(status_code=404, detail="未找到命令号: %s" % name)
    return {"ok": True, **info}


@app.get("/api/devices")
def list_devices(_=Depends(require_auth)):
    db = SessionLocal()
    try:
        items = [d.to_dict(with_payload=True) for d in db.query(Device).order_by(Device.id.asc()).all()]
        return {"items": items}
    finally:
        db.close()


def _db_device_count() -> int:
    db = SessionLocal()
    try:
        return db.query(Device).count()
    finally:
        db.close()


def _persist_device(payload_json: str, name: str = "", proxy: str = "") -> dict:
    """校验设备材料并落库；同一小红书号（xhs_user_id）已存在时更新而非新建。

    proxy：来自「添加设备」表单的可选出口代理。非空时覆盖 payload 里的 proxy。
    """
    import json as _json
    try:
        payload = _json.loads(payload_json)
        if not isinstance(payload, dict):
            raise ValueError("payload 须为 JSON 对象")
    except Exception as e:
        return {"ok": False, "error": f"payload 解析失败: {e}", "item": None}
    if proxy:
        payload['proxy'] = proxy
    # 代理格式校验（可选字段）
    proxy = str(payload.get('proxy') or '').strip()
    if proxy and not re.match(r'^(https?|socks5)://', proxy):
        return {"ok": False, "error": "代理格式不合法（须 http:// 或 socks5:// 开头）", "item": None}
    ok, nickname, uid, st, err = xhs_client.check_device(payload)
    if not ok and not proxy:
        return {"ok": False, "error": err or "设备登录态校验未通过", "item": None}
    if not ok:
        # 带代理的设备：上游可能暂时连不通（代理失效），仍允许落库但标记状态
        st = st or 'unknown'
        if st == 'unknown':
            err = err or '经代理检测失败（代理可能不可用）'
    db = SessionLocal()
    try:
        dev = None
        if uid:
            dev = db.query(Device).filter(Device.xhs_user_id == uid).first()
        if dev is None and name:
            dev = db.query(Device).filter(Device.name == name).first()
        if dev is None:
            dev = Device(
                name=name or nickname or "未命名设备",
                label=payload.get("label") or name or "",
                payload=_json.dumps(payload, ensure_ascii=False),
                nickname=nickname,
                xhs_user_id=uid,
                status="active",
                last_checked_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            db.add(dev)
            updated = False
        else:
            dev.payload = _json.dumps(payload, ensure_ascii=False)
            dev.nickname = nickname or dev.nickname
            dev.xhs_user_id = uid or dev.xhs_user_id
            dev.status = "active"
            dev.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if name:
                dev.name = name
            updated = True
        db.commit()
        db.refresh(dev)
        return {"ok": True, "error": "", "item": dev.to_dict(with_payload=True), "updated": updated}
    finally:
        db.close()


@app.post("/api/devices")
def create_device(req: DeviceCreate, _=Depends(require_auth)):
    proxy = (req.proxy or "").strip()
    if proxy and not re.match(r'^(https?|socks5)://', proxy):
        return {"ok": False, "error": "代理格式不合法（须 http:// 或 socks5:// 开头）", "item": None}
    if req.mode == "generate":
        return _generate_device(req.ssaid, req.name, proxy)
    return _persist_device(req.payload, req.name, proxy)


def _generate_device(ssaid: str, name: str = "", proxy: str = "") -> dict:
    """零模板离线生成设备：SSAID → device_id + 服务端下发 hmac → 全套材料落库。

    新设备未登录（无 sid），status 置 expired 表示「待登录」。
    proxy 非空时：取 hmac 的那一步也走代理，并把它写进 payload —— 之后该设备的所有
    抓取请求都会走这个代理。
    """
    import json as _json
    try:
        r = device_factory.generate_offline(
            new_ssaid=(ssaid or "").strip() or None,
            proxy=proxy,
        )
    except device_factory.DeviceFactoryError as e:
        return {"ok": False, "error": f"生成失败: {e}", "item": None}
    except Exception as e:
        return {"ok": False, "error": f"生成异常: {e}", "item": None}

    payload = {
        "did": r["device_id"],
        # device_id 与 did 同值，两个键都留：did 是签名器/历史材料用的名字，
        # device_id 是 verify_material 体检与 platform_info 用的名字。
        # 原来只写了 did，导致 material_audit 把新设备全判成「缺字段 device_id」。
        "device_id": r["device_id"],
        "hmac": r["hmac"],
        "key64": r["key64"],
        "ssaid": r["ssaid"],
        "user_agent": r["user_agent"],
        "gid": r["gid"],
        "mua0": r["mua0"],
        "cp": r["cp"],
        "platform_info": r["platform_info"],
        "scene": r["scene"],
        "local_did": r.get("did", ""),
        "oaid": r.get("oaid", ""),
    }
    if proxy:
        payload["proxy"] = proxy
    # 9.49.1 材料升级（2026-10-13：新设备直接产出 9.49.1 材料，双轨签名器按 ver 选择）
    try:
        from xhs_core_9491 import upgrade_payload as _upgrade_9491
        payload = _upgrade_9491(payload)
    except Exception:
        pass
    model = r.get("device_model") or ""
    brand = r.get("device_brand") or ""
    model_label = (brand + " " + model).strip()
    label = r.get("device_model") or model_label
    dev_label = f"{name}-{model}" if (name and model) else (name or model_label or "新设备")

    db = SessionLocal()
    try:
        if _db_device_count() >= 200:
            return {"ok": False, "error": "设备数量已达上限（200）", "item": None}
        dev = Device(
            name=dev_label,
            label=label,
            payload=_json.dumps(payload, ensure_ascii=False),
            nickname="",
            xhs_user_id="",
            status="expired",       # 未登录，待走登录链路
            last_checked_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        db.add(dev)
        db.commit()
        db.refresh(dev)
        return {"ok": True, "error": "", "item": dev.to_dict(with_payload=True), "updated": False,
                "generate": {"ssaid": r["ssaid"], "device_id": r["device_id"],
                             "did": r.get("did", ""), "model": model_label}}
    finally:
        db.close()


@app.put("/api/devices/{device_id}")
def update_device(device_id: int, req: DeviceUpdate, _=Depends(require_auth)):
    """编辑设备。payload 填了才走完整校验；只改 name/status/proxy 时快速更新。"""
    import json as _json
    db = SessionLocal()
    try:
        dev = db.get(Device, device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="设备不存在")
        changed_payload = False
        if req.name is not None:
            dev.name = req.name.strip()
        if req.label is not None:
            dev.label = req.label.strip()
        if req.status is not None:
            dev.status = req.status
        # proxy 与 payload 同级处理：proxy 传了就合并进现有 payload（不触发设备检测）
        if req.proxy is not None:
            proxy = req.proxy.strip()
            if proxy and not re.match(r'^(https?|socks5)://', proxy):
                return {"ok": False, "error": "代理格式不合法（须 http:// 或 socks5:// 开头）"}
            pj = dev.payload_dict()
            if proxy:
                pj['proxy'] = proxy
            else:
                pj.pop('proxy', None)
            dev.payload = _json.dumps(pj, ensure_ascii=False)
            changed_payload = True
        if req.payload is not None and req.payload.strip():
            try:
                pj = _json.loads(req.payload)
                if not isinstance(pj, dict):
                    raise ValueError("payload 须为 JSON 对象")
            except Exception as e:
                return {"ok": False, "error": f"payload 解析失败: {e}"}
            # 保留当前 proxy（payload 里没有时）
            if 'proxy' not in pj and dev.payload_dict().get('proxy'):
                pj['proxy'] = dev.payload_dict()['proxy']
            dev.payload = _json.dumps(pj, ensure_ascii=False)
            changed_payload = True
        if changed_payload:
            dev.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.commit()
        db.refresh(dev)
        return {"ok": True, "item": dev.to_dict(with_payload=True)}
    finally:
        db.close()


# ---------- 代理测试 ----------
# 出口 IP 探测端点（依序尝试）：优先国内可达的纯文本端点，海外 JSON 端点兜底。
# 返回格式：key=None 表示纯文本 IP；否则为 JSON 里取该字段。
# 出口 IP 探测端点（2026-10-26 按老板要求收敛：只用 3322 + 网易，其余删除）
#   (url, 解析方式)
#     None      → 响应正文本身就是 IP（纯文本）
#     "js:ip"   → 从 `var ip = '1.2.3.4';` 这类 JS 赋值里抽
#     "json:key"→ 从 JSON 里取字段
# 3322 是主接口（两个域名互为容错），网易 info.js 作备用。
_PROXY_IP_ENDPOINTS = [
    ("http://ip.3322.net", None),
    ("http://members.3322.org/dyndns/getip", None),
    ("https://only.nstool.netease.com/info.js", "js:ip"),
]
_PROXY_TEST_TIMEOUT = 10  # 秒

_IPV4_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')


def _extract_ip(text: str, mode: str | None = None) -> str:
    """从响应正文里抽出口 IP。

    先按端点声明的格式结构化解析（js / json），失败再退回「正文里第一个 IPv4」。
    实测样本：
      http://ip.3322.net            → '124.228.64.59\\n'（纯文本）
      .../info.js (网易)            → "var ip = '124.228.64.59';\\nvar dns = '...';..."（GBK 页面，ASCII 部分完好）
    """
    text = text or ''
    if mode == 'js:ip':
        m = re.search(r"var\s+ip\s*=\s*['\"]([0-9.]+)['\"]", text)
        if m:
            return m.group(1)
    elif mode and mode.startswith('json:'):
        try:
            return str((json.loads(text) or {}).get(mode[5:], '') or '')
        except Exception:  # noqa: BLE001
            pass
    m = _IPV4_RE.search(text)
    return m.group(0) if m else ''

# 直连出口 IP 缓存（启动时后台探测，代理测试时作对照）
_DIRECT_IP_CACHE = {}


class ProxyTestRequest(BaseModel):
    proxy: str | None = None


def _http_get_ip_text(proxy_url: str | None):
    """经（可选）代理请求出口 IP 探测端点，返回 (ip, latency_ms)。

    proxy_url 为空表示直连。任一端点成功即返回；全部失败抛 RuntimeError。
    用 requests（而非签名链的 tls_client）：IP 探测无需伪装指纹，requests 对
    http/https/socks5 代理支持更稳，也避免 tls_client 自定义 JA3 的兼容问题。
    """
    import requests
    # trust_env=False：**不读** HTTP_PROXY / HTTPS_PROXY 环境变量。
    # 否则 proxy_url 为空（取直连 IP）时 requests 会偷偷走环境里的代理，
    # 让「直连 IP」其实是代理出口 IP → ip_changed 对照直接失真。
    sess = requests.Session()
    sess.trust_env = False
    proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
    last_err = "所有出口 IP 探测端点均不可达"
    for url, mode in _PROXY_IP_ENDPOINTS:
        try:
            t0 = time.time()
            r = sess.get(url, proxies=proxies, timeout=_PROXY_TEST_TIMEOUT,
                         headers={'User-Agent': 'curl/8.0'})
            latency = int((time.time() - t0) * 1000)
            if r.status_code != 200:
                last_err = f'{url} → HTTP {r.status_code}'
                continue
            # 用 content 手动按 charset 解码：网易 info.js 是 GBK 页面，
            # 但我们只取 ASCII 的 `var ip = '...'`，utf-8 容错解码即可。
            try:
                body = r.content.decode(r.encoding or 'utf-8', 'replace')
            except Exception:  # noqa: BLE001
                body = r.text or ''
            ip = _extract_ip(body, mode)
            if ip:
                return ip, latency
            last_err = f'{url} → 空响应'
        except Exception as e:  # noqa: BLE001
            last_err = f'{url} → {e}'
    raise RuntimeError(last_err)


@app.post("/api/proxy/test")
def proxy_test_any(req: ProxyTestRequest, _=Depends(require_auth)):
    """代理连通性测试（**不依赖设备**）。

    专供「添加设备」表单用：设备还没创建时也要能先验证代理通不通，
    免得填了坏代理 → 生成阶段请求 homefeed 直接失败。
    返回出口 IP、延迟，以及是否与直连 IP 不同（不同 = 代理确实生效）。
    """
    proxy = (req.proxy or "").strip()
    if not proxy:
        return {"ok": False, "error": "请填写代理地址"}
    if not re.match(r'^(https?|socks5)://', proxy):
        return {"ok": False, "error": "代理格式不合法（须 http:// 或 socks5:// 开头）"}
    try:
        exit_ip, latency = _http_get_ip_text(proxy)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"代理不通: {e}", "proxy": proxy}
    direct_ip = _get_direct_ip()
    return {"ok": True, "proxy": proxy, "exit_ip": exit_ip, "latency_ms": latency,
            "direct_ip": direct_ip,
            "ip_changed": bool(exit_ip) and bool(direct_ip) and exit_ip != direct_ip}


@app.post("/api/devices/{device_id}/proxy_test")
def device_proxy_test(device_id: int, req: ProxyTestRequest, _=Depends(require_auth)):
    """代理连通性测试：经代理探测出口 IP，与直连 IP 对照判断代理是否生效。

    body 可传 proxy（测试尚未保存的输入值）；不传则读设备已保存的代理。
    """
    db = SessionLocal()
    try:
        dev = db.get(Device, device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="设备不存在")
        payload = dev.payload_dict()
        proxy = str(req.proxy if req.proxy is not None else (payload.get('proxy') or '')).strip()
        if not proxy:
            return {"ok": False, "error": "该设备未配置代理"}
        try:
            exit_ip, latency = _http_get_ip_text(proxy)
        except Exception as e:
            return {"ok": False, "error": f"代理不通: {e}", "proxy": proxy}
        direct_ip = _get_direct_ip()
        ip_changed = bool(exit_ip) and bool(direct_ip) and exit_ip != direct_ip
        return {"ok": True, "proxy": proxy, "exit_ip": exit_ip,
                "direct_ip": direct_ip, "latency_ms": latency, "ip_changed": ip_changed}
    finally:
        db.close()


_DIRECT_IP_LOCK = threading.Lock()


def _get_direct_ip() -> str:
    """返回直连出口 IP（惰性探测 + 线程安全缓存，避免启动事件不触发时为空）。"""
    if _DIRECT_IP_CACHE.get('ip'):
        return _DIRECT_IP_CACHE['ip']
    with _DIRECT_IP_LOCK:
        if _DIRECT_IP_CACHE.get('ip'):
            return _DIRECT_IP_CACHE['ip']
        try:
            ip, _ = _http_get_ip_text(None)
            _DIRECT_IP_CACHE['ip'] = ip
        except Exception:
            pass
        return _DIRECT_IP_CACHE.get('ip', '')


def warm_direct_ip():
    """后台预热直连 IP（不阻塞启动，失败静默，代理测试时再惰性兜底）。"""
    def _job():
        try:
            _get_direct_ip()
        except Exception:
            pass
    threading.Thread(target=_job, daemon=True).start()


@app.delete("/api/devices/{device_id}")
def delete_device(device_id: int, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        dev = db.get(Device, device_id)
        if dev:
            db.delete(dev)
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@app.post("/api/devices/{device_id}/check")
def check_device_api(device_id: int, _=Depends(require_auth)):
    """检测设备登录态并回写状态/昵称/user_id。"""
    db = SessionLocal()
    try:
        dev = db.get(Device, device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="设备不存在")
        ok, nickname, uid, kind, err = xhs_client.check_device(dev.payload_dict())
        dev.status = kind
        dev.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if ok:
            if nickname:
                dev.nickname = nickname
            if uid:
                dev.xhs_user_id = uid
        db.commit()
        return {
            "ok": ok,
            "error": err,
            "account_status": kind,
            "rate_limited": kind == "anomaly",
            "rate_limit_msg": err if kind == "anomaly" else "",
            "item": dev.to_dict(with_payload=True),
        }
    finally:
        db.close()


@app.get("/api/bloggers")
def list_bloggers(_=Depends(require_auth)):
    db = SessionLocal()
    try:
        items = [b.to_dict() for b in db.query(Blogger).order_by(Blogger.id.asc()).all()]
        return {"items": items}
    finally:
        db.close()


@app.post("/api/bloggers")
def create_blogger(req: BloggerCreate, _=Depends(require_auth)):
    uid = _blogger_uid(req.url)
    if not uid:
        raise HTTPException(status_code=400, detail="链接无效：无法解析 user_id（支持主页链接或直接填 24 位 id）")
    db = SessionLocal()
    try:
        # 防重复添加：按 user_id 判断是否已存在（拉黑/未拉黑都拦截）
        existing = db.query(Blogger).filter(Blogger.xhs_user_id == uid).first()
        if existing:
            if existing.status == "blocked":
                raise HTTPException(status_code=400, detail="该博主已被拉黑，请先取消拉黑")
            raise HTTPException(status_code=400, detail="该博主已存在，请勿重复添加")
        m_start = _norm_hhmm(req.monitor_start)
        m_end = _norm_hhmm(req.monitor_end)
        _check_window(m_start, m_end)
        b = Blogger(
            name=req.name or uid,
            url=req.url.strip(),
            xhs_user_id=uid,
            monitor_start=m_start,
            monitor_end=m_end,
            status="active",
            monitor_since=int(datetime.now().timestamp() * 1000),
        )
        db.add(b)
        db.commit()
        db.refresh(b)
        r = scheduler.refresh_blogger(db, b.id, establish_baseline=True)
        db.refresh(b)
        # 博主名自动获取：优先抓取昵称 → user/info 兜底 → user_id
        nickname = r.get("nickname") or ""
        if not nickname and not req.name:
            try:
                account = None
                # 找一个健康设备调 user/info
                from db import Device as _Dev
                for d in db.query(_Dev).filter(_Dev.status == "active").all():
                    account = d.payload_dict()
                    break
                if account:
                    _ok, info, _err = xhs_client.fetch_user_info(account, uid)
                    nickname = (info or {}).get("nickname") or ""
            except Exception:
                pass
        if nickname:
            b.name = nickname
        elif not req.name:
            b.name = uid
        db.commit()
        db.refresh(b)
        return {"ok": r["ok"], "error": r.get("error", ""), "item": b.to_dict()}
    finally:
        db.close()


@app.put("/api/bloggers/{blogger_id}")
def update_blogger(blogger_id: int, req: BloggerUpdate, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        b = db.get(Blogger, blogger_id)
        if not b:
            raise HTTPException(status_code=404, detail="博主不存在")
        if req.name is not None:
            b.name = req.name
        if req.url is not None:
            # 用本模块的 _blogger_uid（与 create_blogger 同一套解析器）：
            # 支持主页链接、/user/profile/<id> 与直接填 24 位 id。
            # 原写法调的是 xhs_client.extract_user_id —— 该函数并不存在，改链接必 500。
            uid = _blogger_uid(req.url)
            if not uid:
                raise HTTPException(status_code=400, detail="链接无效：无法解析 user_id")
            # 防重复：与 create_blogger 同口径；排除自己（重复保存同一链接不该报错）。
            # 不加这层的话，A 的链接改成 B 已占用的 uid 会留下两条同 uid 博主，
            # 调度对同一个号抓两遍、推两遍。
            dup = (db.query(Blogger)
                   .filter(Blogger.xhs_user_id == uid, Blogger.id != blogger_id)
                   .first())
            if dup:
                raise HTTPException(
                    status_code=400,
                    detail="该博主已存在（%s），请勿重复" % (dup.name or dup.xhs_user_id))
            b.url = req.url.strip()
            b.xhs_user_id = uid
        if req.monitor_start is not None or req.monitor_end is not None:
            m_start = _norm_hhmm(req.monitor_start if req.monitor_start is not None else b.monitor_start)
            m_end = _norm_hhmm(req.monitor_end if req.monitor_end is not None else b.monitor_end)
            _check_window(m_start, m_end)
            b.monitor_start = m_start
            b.monitor_end = m_end
        if req.status is not None:
            if req.status not in ("active", "paused", "blocked"):
                raise HTTPException(status_code=400, detail="状态不合法（仅支持 active/paused/blocked）")
            b.status = req.status
        db.commit()
        db.refresh(b)
        return {"ok": True, "item": b.to_dict()}
    finally:
        db.close()


@app.delete("/api/bloggers/{blogger_id}")
def delete_blogger(blogger_id: int, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        db.execute(sa_delete(Note).where(Note.blogger_id == blogger_id))
        b = db.get(Blogger, blogger_id)
        if b:
            db.delete(b)
        db.commit()
        return {"ok": True}
    finally:
        db.close()


@app.post("/api/bloggers/{blogger_id}/refresh")
def refresh_blogger_api(blogger_id: int, force: bool = False, _=Depends(require_auth)):
    """手动抓取：用户主动触发，不受监控时段限制（force=true），抓到新笔记照常推送。"""
    db = SessionLocal()
    try:
        r = scheduler.refresh_blogger(db, blogger_id, force=force)
        b = db.get(Blogger, blogger_id)
        return {
            "ok": r["ok"],
            "error": r.get("error", ""),
            "skipped_by_window": r.get("skipped_by_window", False),
            "new_count": r.get("new_count", 0),
            "pushed": r.get("pushed", False),
            "item": b.to_dict() if b else None,
        }
    finally:
        db.close()


# ---------- 关注列表导入 ----------

# ---------- 关注列表导入 ----------
@app.post("/api/followings/list")
def list_followings(req: FollowingsListRequest, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        dev = db.get(Device, req.device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="设备不存在")
        payload = dev.payload_dict()
        uid = dev.xhs_user_id
        if not uid:
            ok, nickname, uid2, kind, err = xhs_client.check_device(payload)
            if not ok:
                raise HTTPException(status_code=400, detail="设备登录态无效，请先检测设备")
            uid = uid2
            dev.xhs_user_id = uid
            db.commit()
        ok, users, err = xhs_client.fetch_all_followings(payload, uid)
        if not ok:
            raise HTTPException(status_code=400, detail="获取关注列表失败：" + err)
        existing = {b.xhs_user_id for b in db.query(Blogger).all()}
        blocked = {b.xhs_user_id for b in db.query(Blogger).filter(Blogger.status == "blocked").all()}
        items = []
        for u in users:
            uid2 = str(u.get("user_id") or u.get("userid") or "")
            if not uid2:
                continue
            items.append({
                "user_id": uid2,
                "nickname": u.get("nickname") or u.get("nick_name") or uid2,
                "url": f"https://www.xiaohongshu.com/user/profile/{uid2}",
                "already": uid2 in existing,
                "blocked": uid2 in blocked,
            })
        return {"items": items, "total": len(items), "account_name": dev.name or dev.nickname}
    finally:
        db.close()


@app.post("/api/bloggers/import-followings")
def import_followings(req: ImportFollowingsRequest, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        m_start = _norm_hhmm(req.monitor_start)
        m_end = _norm_hhmm(req.monitor_end)
        _check_window(m_start, m_end)
        existing = {b.xhs_user_id for b in db.query(Blogger).all()}
        blocked = {b.xhs_user_id for b in db.query(Blogger).filter(Blogger.status == "blocked").all()}
        imported = 0
        skipped = 0
        skipped_blocked = 0
        for it in req.items:
            uid = str(it.get("user_id") or "").strip()
            if not uid or uid in existing:
                skipped += 1
                if uid in blocked:
                    skipped_blocked += 1
                continue
            db.add(Blogger(
                name=it.get("nickname") or uid,
                url=it.get("url") or f"https://www.xiaohongshu.com/user/profile/{uid}",
                xhs_user_id=uid,
                monitor_start=m_start,
                monitor_end=m_end,
                status="active",
                monitor_since=int(datetime.now().timestamp() * 1000),
            ))
            existing.add(uid)
            imported += 1
        db.commit()
        return {"ok": True, "imported": imported, "skipped": skipped, "skipped_blocked": skipped_blocked}
    finally:
        db.close()


@app.post("/api/bloggers/batch-update")
def batch_update_bloggers(req: BatchUpdateRequest, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        if not req.ids:
            raise HTTPException(status_code=400, detail="未选择博主")
        values = {}
        if req.clear_window:
            values["monitor_start"] = ""
            values["monitor_end"] = ""
        elif req.monitor_start is not None or req.monitor_end is not None:
            m_start = _norm_hhmm(req.monitor_start)
            m_end = _norm_hhmm(req.monitor_end)
            _check_window(m_start, m_end)
            values["monitor_start"] = m_start
            values["monitor_end"] = m_end
        if not values:
            return {"ok": True, "updated": 0}
        result = db.execute(
            sa_update(Blogger).where(Blogger.id.in_(req.ids)).values(**values)
        )
        db.commit()
        return {"ok": True, "updated": result.rowcount}
    finally:
        db.close()




# ---------- 设备登录/注册（手机验证码，9.19.2 App 协议） ----------
from urllib.parse import urlencode as _urlencode, unquote as _unquote


def _login_device_params(device_payload: dict, phone: str, zone: str) -> dict:
    """构造登录/注册的上游 form 参数（从设备 payload 提取 + 兜底）。"""
    cp = device_payload.get('cp') or ''
    channel = ''
    for p in cp.split('&'):
        if p.startswith('channel='):
            channel = _unquote(p.split('=', 1)[1])
            break
    android_id = device_payload.get('android_id') or '1a80b18b5662a428'
    return {
        'zone': zone, 'phone': phone,
        'idfa': '', 'idfv': '',
        'android_id': android_id,
        'channel': channel,
        'gaid': '', 'oaid': '', 'pasteboard': '', 'category': '',
        'android_version': '14', 'mac': '', 'attribution_id': '',
        'imei_encrypted': '', 'ruleId': 0, 'after_register': 'false',
        'acct_group_id': '', 'source': '',
    }


@app.post("/api/devices/{device_id}/login/send_code")
def device_login_send_code(device_id: int, req: dict, _=Depends(require_auth)):
    """发短信验证码。471 撞图形验证时返回 need_captcha + 题目（picList/theme）。"""
    db = SessionLocal()
    try:
        dev = db.get(Device, device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="设备不存在")
        payload = dev.payload_dict()
        try:
            signer = xhs_client._signer(payload)   # 走设备已配置的代理（用户要求：设置代理必须走代理）
        except xhs_client.ClientError as e:
            return {"ok": False, "error": str(e)}
        phone = str(req.get('phone') or '').strip()
        zone = str(req.get('zone') or '86').strip()
        typ = str(req.get('type') or 'login').strip()
        if not phone:
            return {"ok": False, "error": "phone 必填"}
        # 若前端带了图形验证答案，先过 captcha_check 再发码。
        # 原来这里完全不读 captcha，导致「撞 471 → 用户选图 → 重新发送」永远还是 471，
        # 前端陷入死循环（submit 那条路径早就这么做了，send_code 漏了）。
        captcha = req.get('captcha') or {}
        if captcha:
            cform = _urlencode({k: v for k, v in captcha.items()}).encode('utf-8')
            try:
                cs, ct = signer.fetch(
                    xhs_client.UPSTREAM + '/api/sns/redcaptcha/v2/captcha/app/check',
                    'POST', cform, content_type='application/x-www-form-urlencoded')
            except Exception as e:
                return {"ok": False, "error": f"图形验证失败: {e}"}
            try:
                cj = json.loads(ct)
            except Exception:
                return {"ok": False, "error": f"图形验证返回异常（HTTP {cs}）"}
            if cj.get('code') != 0:
                return {"ok": False, "need_captcha": True, "captcha": cj,
                        "error": "图形验证未通过，请重选"}
        qs = _urlencode({'phone': phone, 'zone': zone, 'type': typ})
        try:
            status, text = signer.fetch(xhs_client.UPSTREAM + '/api/sns/v1/system_service/vfc_code?' + qs, 'GET', b'')
        except Exception as e:
            return {"ok": False, "error": f"网络失败: {e}"}
        try:
            parsed = json.loads(text)
        except Exception:
            return {"ok": False, "error": f"上游响应异常（HTTP {status}）"}
        # 471 图形验证：透传题目
        if status == 471:
            return {"ok": False, "need_captcha": True, "captcha": parsed,
                    "error": "需要图形验证"}
        if parsed.get('code') != 0:
            return {"ok": False, "error": f"{parsed.get('msg')} (code {parsed.get('code')})"}
        return {"ok": True, "body": parsed}
    finally:
        db.close()


@app.post("/api/devices/{device_id}/login/submit")
def device_login_submit(device_id: int, req: dict, _=Depends(require_auth)):
    """一体化登录/注册：check_code → exists? login/code : register。成功回写登录态。"""
    db = SessionLocal()
    try:
        dev = db.get(Device, device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="设备不存在")
        payload = dev.payload_dict()
        try:
            signer = xhs_client._signer(payload)   # 走设备已配置的代理
        except xhs_client.ClientError as e:
            return {"ok": False, "error": str(e)}
        phone = str(req.get('phone') or '').strip()
        zone = str(req.get('zone') or '86').strip()
        code = str(req.get('code') or '').strip()
        typ = str(req.get('type') or 'login').strip()
        captcha = req.get('captcha') or {}
        if not phone or not code:
            return {"ok": False, "error": "phone/code 必填"}

        # 1. check_code（若带了图形验证答案，先过 captcha_check）
        if captcha:
            cform = _urlencode({k: v for k, v in captcha.items()}).encode('utf-8')
            try:
                cs, ct = signer.fetch(xhs_client.UPSTREAM + '/api/sns/redcaptcha/v2/captcha/app/check',
                                      'POST', cform, content_type='application/x-www-form-urlencoded')
            except Exception as e:
                return {"ok": False, "error": f"图形验证失败: {e}"}
            try:
                cj = json.loads(ct)
            except Exception:
                return {"ok": False, "error": f"图形验证返回异常（HTTP {cs}）"}
            if cj.get('code') != 0:
                return {"ok": False, "need_captcha": True, "captcha": cj, "error": "图形验证未通过，请重选"}

        qs = _urlencode({'phone': phone, 'zone': zone, 'code': code, 'type': typ})
        try:
            status, text = signer.fetch(xhs_client.UPSTREAM + '/api/sns/v1/system_service/check_code?' + qs, 'GET', b'')
        except Exception as e:
            return {"ok": False, "error": f"网络失败: {e}"}
        try:
            ck = json.loads(text)
        except Exception:
            return {"ok": False, "error": f"check_code 非 JSON（HTTP {status}）"}
        if ck.get('code') != 0:
            # 471 图形验证发生在 check_code 阶段
            if status == 471:
                return {"ok": False, "need_captcha": True, "captcha": ck, "error": "需要图形验证"}
            return {"ok": False, "error": f"{ck.get('msg')} (code {ck.get('code')})", "body": ck}
        mobile_token = (ck.get('data') or {}).get('token')
        if not mobile_token:
            # code=0 但未下发 mobile_token：验证码错误/已过期/已使用，或代理 IP 被风控静默拦截。
            # 透传原始响应便于诊断 token 的真实结构/归属（字段名/层级可能随版本变化）。
            return {"ok": False,
                    "error": "验证码校验未下发登录凭证(token)。常见原因：验证码错误/已过期/已使用，或代理 IP 被风控。",
                    "body": ck}
        exists = bool(ck['data'].get('exists'))

        # 2. login/code 或 register
        params = _login_device_params(payload, phone, zone)
        params['mobile_token'] = mobile_token
        if exists:
            params.pop('channel', None)
            path = '/api/sns/v4/user/login/code'
        else:
            path = '/api/sns/v4/user/register'
        form = _urlencode(params).encode('utf-8')
        try:
            status2, text2 = signer.fetch(xhs_client.UPSTREAM + path, 'POST', form,
                                          content_type='application/x-www-form-urlencoded')
        except Exception as e:
            return {"ok": False, "error": f"网络失败: {e}"}
        try:
            parsed = json.loads(text2)
        except Exception:
            return {"ok": False, "error": f"login 非 JSON（HTTP {status2}）"}
        if status2 != 200 or parsed.get('code') != 0:
            return {"ok": False, "error": f"{parsed.get('msg')} (code {parsed.get('code')})",
                    "body": parsed}

        # 3. 登录成功：回写 payload 登录态
        data = parsed.get('data') or {}
        session = data.get('session')
        if not session:
            # code=0 但未下发 session：登录未真正成功（账号需绑定/二次验证/被限制，或代理风控）。
            return {"ok": False,
                    "error": "接口返回成功但未下发登录态(session)。账号可能需要额外验证或被限制，或代理 IP 被风控。",
                    "body": parsed}
        userid = str(data.get('userid') or '')
        id_token = (data.get('user_extra_info') or {}).get('id_token')
        if session:
            payload['sid'] = 'session.' + session if not str(session).startswith('session.') else str(session)
        if userid:
            payload['user_id'] = userid
        if id_token:
            payload['id_token'] = id_token
        # 记录本次登录手机号，便于下次登录时默认预填
        if phone:
            payload['login_phone'] = phone
            payload['login_zone'] = zone or '86'
        dev.payload = json.dumps(payload, ensure_ascii=False)
        dev.status = "active"
        dev.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 4. user/me 拿昵称
        nickname = ""
        try:
            ok, nickname, uid, kind, err = xhs_client.check_device(payload)
            if ok:
                dev.nickname = nickname or dev.nickname
                dev.xhs_user_id = uid or dev.xhs_user_id
                dev.status = "active"
        except Exception:
            pass
        db.commit()
        db.refresh(dev)
        return {"ok": True, "exists": exists, "nickname": dev.nickname,
                "user_id": dev.xhs_user_id, "item": dev.to_dict()}
    finally:
        db.close()


@app.post("/api/devices/{device_id}/login/captcha")
def device_login_captcha(device_id: int, req: dict, _=Depends(require_auth)):
    """图形验证码独立提交（重试场景）。"""
    db = SessionLocal()
    try:
        dev = db.get(Device, device_id)
        if not dev:
            raise HTTPException(status_code=404, detail="设备不存在")
        signer = xhs_client._signer(dev.payload_dict())   # 走设备已配置的代理
        form = _urlencode({k: v for k, v in req.items()}).encode('utf-8')
        status, text = signer.fetch(xhs_client.UPSTREAM + '/api/sns/redcaptcha/v2/captcha/app/check',
                                    'POST', form, content_type='application/x-www-form-urlencoded')
        try:
            parsed = json.loads(text)
        except Exception:
            return {"ok": False, "error": f"非 JSON（HTTP {status}）"}
        return {"ok": parsed.get('code') == 0, "body": parsed}
    finally:
        db.close()


# ---------- 笔记记录 ----------

@app.get("/api/notes")
def list_notes(
    blogger_id: int | None = None,
    limit: int = 500,
    offset: int = 0,
    _=Depends(require_auth),
):
    db = SessionLocal()
    try:
        # 钳制分页参数：limit=-1 在 SQLite 里等价于「不限制」，会一次吐出全表
        limit = max(1, min(int(limit or 500), 2000))
        offset = max(0, int(offset or 0))
        q = db.query(Note)
        if blogger_id:
            q = q.filter(Note.blogger_id == blogger_id)
        total = q.count()
        rows = q.order_by(Note.publish_time.desc()).offset(offset).limit(limit).all()
        names = {b.id: b.name for b in db.query(Blogger).all()}
        items = []
        for n in rows:
            d = n.to_dict()
            d["blogger_name"] = names.get(n.blogger_id, "")
            items.append(d)
        return {"total": total, "items": items}
    finally:
        db.close()


@app.delete("/api/notes/clear")
def clear_notes(req: NotesClear, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        stmt = sa_delete(Note)
        if req.blogger_id is not None:
            stmt = stmt.where(Note.blogger_id == req.blogger_id)
        result = db.execute(stmt)
        db.commit()
        return {"ok": True, "deleted": result.rowcount}
    finally:
        db.close()


@app.post("/api/notes/delete")
def delete_notes(req: NotesDelete, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        result = db.execute(sa_delete(Note).where(Note.id.in_(req.ids)))
        db.commit()
        return {"ok": True, "deleted": result.rowcount}
    finally:
        db.close()


# ---------- 新笔记推送 ----------
@app.get("/api/notify/config")
def get_notify_config(_=Depends(require_auth)):
    db = SessionLocal()
    try:
        return notifier.get_config(db)
    finally:
        db.close()


@app.post("/api/notify/config")
def save_notify_config(cfg: dict, _=Depends(require_auth)):
    db = SessionLocal()
    try:
        notifier.save_config(db, cfg)
        return {"ok": True}
    finally:
        db.close()


@app.post("/api/notify/test")
def test_notify(cfg: dict, _=Depends(require_auth)):
    return notifier.send_test(cfg)


