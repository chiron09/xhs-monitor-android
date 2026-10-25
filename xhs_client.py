# -*- coding: utf-8 -*-
"""小红书 App 端接口客户端（替代 Spider_XHS web SDK）。

签名引擎（双轨，2026-10-13 起）：
  - ver='9.49.1' 的设备 → xhs_core_9491.XhsSigner9491（9.49.1 三段式 shield）
  - 其余设备          → xhs_core.XhsSigner（9.19.2，存量兼容）
两者均为完全离线签名，无 Cookie 依赖。

⚠️ 9.49.1 材料要求（实测）：
  - mua 载荷 v 必须为 2.10.1（否则内容接口 461 风控"账号异常"）
  - direction/bandwidth/networktype 三字段参与 shield source（升级脚本自动补）
  - 登录态设备无需 main_ssk（70B 无票据 shield 可通过全部接口）

能力映射（2026-10-12 实测校验矩阵）：
  ✅ 宽松接口（虚拟设备可直接用）：
     user/me / user/info / v4/user/posted / v5/note/comment/list / homefeed / videofeed
  ❌ 严格接口（校验 mua 载荷，虚拟设备不可用）：
     v10/search/notes / v1/imagefeed —— 本模块不提供，避免打废账号
"""
import json
import re
import urllib.parse

import xhs_core
from xhs_core import XhsSigner
from config import public_note_url

UPSTREAM = 'https://edith.xiaohongshu.com'


class ClientError(RuntimeError):
    """上游业务错误（msg 已提取，含 code）。"""


def _signer(device_payload: dict):
    """从设备 payload 构建签名器（双轨：9.49.1 / 9.19.2）。

    构造阶段抛的任何异常（hmac 不是合法 base64、key64 派生失败、算法资产缺失…）
    统一转成 ClientError：否则会以 500 冒到接口层 —— 导入一份坏材料时必现。
    转成 ClientError 后，check_device / fetch_* 现有的 except 分支即可正常接住，
    表现为「设备校验不通过」而不是「服务器崩了」。
    """
    missing = [k for k in ('did', 'hmac') if not (device_payload or {}).get(k)]
    if missing:
        raise ClientError(f'设备材料缺失: {", ".join(missing)}（请先在设备管理导入/生成设备）')
    ver = (device_payload or {}).get('ver')
    try:
        if ver == '9.49.1':
            from xhs_core_9491 import XhsSigner9491
            return XhsSigner9491(device_payload)
        return XhsSigner(device_payload)
    except ClientError:
        raise
    except Exception as e:  # noqa: BLE001
        raise ClientError(
            f'设备材料无法初始化签名器（{type(e).__name__}: {str(e)[:80]}）'
            ' —— 常见原因：hmac 不是合法 base64 / key64 派生失败 / 算法资产缺失')


def _call(signer: XhsSigner, path: str, params: dict = None):
    """GET 请求上游并解析 JSON。业务 code!=0 时抛 ClientError（msg 含 code）。"""
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v != '' and v is not None})
    url = UPSTREAM + path + (('?' + qs) if qs else '')
    status, text = signer.fetch(url, 'GET', b'')
    try:
        j = json.loads(text)
    except Exception:
        raise ClientError(f'上游返回非 JSON（HTTP {status}）: {text[:80]}')
    code = j.get('code')
    if code != 0:
        raise ClientError(f"{j.get('msg') or '未知错误'} (code {code})")
    return j.get('data') or {}


# ---------- 账号（设备）检测 ----------

def check_device(device_payload: dict):
    """检测设备登录态与账号信息。返回 (ok, nickname, user_id, account_status, error)。

    account_status 判定同 xhs-console checkup：
      active / kicked(sid 被踢) / expired(登录过期) / anomaly(风控) / unknown
    """
    try:
        signer = _signer(device_payload)
    except ClientError as e:
        return False, '', '', 'unknown', str(e)
    try:
        status, text = signer.fetch(UPSTREAM + '/api/sns/v3/user/me', 'GET', b'')
    except Exception as e:
        return False, '', '', 'unknown', f'网络失败: {e}'
    try:
        j = json.loads(text)
    except Exception:
        return False, '', '', 'unknown', f'上游返回非 JSON（HTTP {status}）'
    code = j.get('code')
    msg = str(j.get('msg') or '')
    data = j.get('data') or {}
    if code == 0:
        return True, data.get('nickname', ''), str(data.get('userid') or data.get('user_id') or ''), 'active', ''
    if code == 300011 or status == 461:
        return False, '', '', 'anomaly', msg or '账号风控异常'
    if code == -1 and 'viewerUserId' in msg:
        return False, '', '', 'kicked', 'sid 已被服务端踢下线，需重新登录'
    if code == -100:
        return False, '', '', 'expired', msg or '登录已过期'
    return False, '', '', 'unknown', f'code={code} {msg[:40]}'


# ---------- 博主笔记抓取 ----------

def fetch_user_notes(device_payload: dict, user_id: str, num: int = 5, cursor: str = ''):
    """抓博主笔记列表（v4/user/posted，宽松接口）。

    返回 (ok, notes_normalized, nickname, error)。
    """
    try:
        signer = _signer(device_payload)
        data = _call(signer, '/api/sns/v4/note/user/posted',
                     {'user_id': user_id, 'num': str(num), 'cursor': cursor})
    except ClientError as e:
        return False, [], '', str(e)
    raw = data.get('notes') or []
    nickname = ''
    notes = []
    for n in raw:
        if not isinstance(n, dict):
            continue
        note_id = n.get('id') or ''
        if not note_id:
            continue
        user = n.get('user') or {}
        nickname = nickname or user.get('nickname') or ''
        notes.append(normalize_note(n))
    return True, notes, nickname, ''


def is_pinned(note_raw: dict) -> bool:
    """app 端置顶判定：note.sticky 布尔字段（实测确认）。"""
    return bool((note_raw or {}).get('sticky'))


def normalize_note(n: dict) -> dict:
    """app 端 posted 笔记 → 标准字段（与原 web SDK 字段对齐）。"""
    note_id = n.get('id') or ''
    imgs = n.get('images_list') or []
    cover_url = ''
    if imgs and isinstance(imgs[0], dict):
        cover_url = imgs[0].get('url') or imgs[0].get('original') or ''
        # app 端封面默认 HEIF 格式（浏览器 <img> 不显示），改为 jpg
        if 'format/heif' in cover_url:
            cover_url = cover_url.replace('format/heif', 'format/jpg')
    # create_time 秒级时间戳 → 毫秒
    ct = n.get('create_time') or 0
    publish_ms = int(ct) * 1000 if ct and int(ct) < 10**12 else int(ct or 0)
    note_type = n.get('type') or 'normal'
    # 笔记链接 = 外部可访问的 http 跳转页（内部转 App deeplink）：
    # 网页版链接缺 xsec_token 打不开（接口被风控拿不到 token），deeplink 不需要 token，
    # 但 deeplink 在 IM/PC 里不可点击——包成 http 跳转页两全。
    note_url = public_note_url(note_id, note_type)
    return {
        'note_id': note_id,
        'title': n.get('display_title') or n.get('title') or '',
        'cover_url': cover_url,
        'note_url': note_url,
        'publish_time': publish_ms,
        'liked_count': int(n.get('likes') or 0),
        'type': note_type,
    }


def fetch_user_info(device_payload: dict, user_id: str):
    """用户主页信息（宽松接口）。返回 (ok, info, error)。"""
    try:
        signer = _signer(device_payload)
        data = _call(signer, '/api/sns/v3/user/info', {'user_id': user_id})
    except ClientError as e:
        return False, {}, str(e)
    # app 端昵称在顶层 data.nickname；basic_info 为空 dict
    info = data if data.get('nickname') else (data.get('basic_info') or data)
    return True, info, ''


def fetch_notes_page(device_payload: dict, user_id: str, num: int = 5, cursor: str = ''):
    """抓博主笔记（scheduler 用别名）。返回 (ok, notes_raw, nickname, error)。

    注意：与 fetch_user_notes 相同，但返回**原始 app 字段**（scheduler 里
    is_pinned/normalize_note 需要原始结构做置顶过滤）。
    """
    try:
        signer = _signer(device_payload)
        data = _call(signer, '/api/sns/v4/note/user/posted',
                     {'user_id': user_id, 'num': str(num), 'cursor': cursor})
    except ClientError as e:
        return False, [], '', str(e)
    raw = data.get('notes') or []
    nickname = ''
    for n in raw:
        if isinstance(n, dict):
            nickname = nickname or (n.get('user') or {}).get('nickname') or ''
    return True, raw, nickname, ''


def fetch_note_share_link(device_payload: dict, note_id: str):
    """拿笔记的官方分享链接（带 xsec_token，点击直达笔记详情页）。

    走 imagefeed 详情接口——响应 note_list[0].share_info.link 携带 xsec_token。
    返回 (ok, url, error)。url 为标准 explore 链接（token 的 = 已编码为 %3D，
    实测该格式手机点击可直接唤起 App 并定位到笔记）。
    失败时 ok=False，调用方应降级到默认链接（public_note_url 跳转页）。
    """
    try:
        signer = _signer(device_payload)
        extra = json.dumps({
            'co_author_id': '', 'is_out_of_china': 0, 'longtext_collection': 0,
            'screen_height': 2400, 'screen_width': 1080, 'track_info': '',
        }, separators=(',', ':'))
        data = _call(signer, '/api/sns/v1/note/imagefeed', {
            'note_id': note_id, 'page': '1', 'has_ads_tag': 'false', 'num': '5',
            'fetch_mode': '1', 'from_rec_local': 'false', 'extra_params': extra,
        })
    except ClientError as e:
        return False, '', str(e)
    items = data if isinstance(data, list) else []
    for item in items:
        if not isinstance(item, dict):
            continue
        for n in (item.get('note_list') or []):
            if not isinstance(n, dict):
                continue
            link = ((n.get('share_info') or {}).get('link')) or ''
            m = re.search(r'xsec_token=([^&]+)', link)
            if m:
                token = urllib.parse.quote(m.group(1), safe='')
                url = ('https://www.xiaohongshu.com/explore/' + note_id +
                       '?xsec_token=' + token + '&xsec_source=pc_feed')
                return True, url, ''
    return False, '', '响应未携带 xsec_token'


def fetch_all_followings(device_payload: dict, user_id: str, num: int = 30, max_pages: int = 100):
    """拉取账号全部关注列表（sns/v1/user/followings）。

    返回 (ok, users, error)。users 每项含 user_id/nickname。
    注意：该接口受设备风控影响，被内容降权的设备会返回 461 空数据（ok=True 但 users=[]）。
    """
    try:
        signer = _signer(device_payload)
    except ClientError as e:
        return False, [], str(e)
    all_users = []
    cursor = ''
    for _ in range(max_pages):
        try:
            data = _call(signer, '/api/sns/v1/user/followings',
                         {'user_id': user_id, 'num': str(num), 'cursor': cursor})
        except ClientError as e:
            # 461 code=0 空响应不会抛（code=0），走到这里是真错误
            return False, [], str(e)
        users = data.get('users') or []
        all_users.extend(users)
        cursor = str(data.get('cursor') or '')
        has_more = bool(data.get('has_more'))
        if not has_more or not cursor:
            break
    return True, all_users, ''
