# -*- coding: utf-8 -*-
"""虚拟多设备生成器（纯离线，不依赖真机）。

原理（详见 xhs-shield-reverse-9192 skill 的 references/device-identity.md）：
  1. device_id = UUID5(SSAID) = MD5-based UUID v3（本地算法，逐字节命中）
  2. 用「无 hmac 的 shield(flag=1)」PC 直连发 homefeed
     → 服务端 406 + 响应 header `Xy-Ter-Str` = 新 main_hmac（96B base64）
  3. key64 = 白盒 AES-CBC 解密(hmac, device_id)（复用 xhs_core.get_key64）

产出：新设备身份（ssaid / device_id / hmac / key64），配「登录 sid」即可用 XhsSigner 取数。

不依赖 adb / 真机 / frida，一条 HTTP 请求秒级完成。
"""
import re
import time
import json
import uuid
import base64
import random
import hashlib
import secrets
import struct

from xhs_core import (get_key64, hmac_md5, rc4, b64url, b64url_dec,
                      RC4_KEY, SHIELD_HDR, S_APP_ID, BUILD_ID, canonical_str,
                      compute_sig, JA3)


class DeviceFactoryError(RuntimeError):
    """虚拟多设备生成失败。"""


def gen_ssaid(n=16):
    return ''.join(random.choice('0123456789abcdef') for _ in range(n))


def uuid5(ssaid):
    """device_id = UUID.nameUUIDFromBytes(SSAID)，MD5-based UUID v3。"""
    md5 = hashlib.md5(ssaid.encode()).digest()
    b = bytearray(md5)
    b[6] = (b[6] & 0x0f) | 0x30
    b[8] = (b[8] & 0x3f) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


# ---- 第一档随机化：UA + gid（均不参与任何签名，零风险）----

# 2026 年度在售机型池：(brand小写, model, android版本, build_id, 分辨率, cpu)
# 说明：
#   - 全部为 2026 年发布/开售机型（S26 系列 2026-03、iQOO 15 Ultra 2026-02、
#     vivo X500 2026-09-29、Find X10 2026-09-24、Magic9 2026-09-28、小米18 2026-09-23…）
#   - model 为 Build.MODEL（国行型号代码）；带"推定"注释的按品牌命名规则补齐，
#     不影响签名（服务端不校验 UA/cp 内容）
#   - cpu 用于 cp 的 cpu_name 字段，与机型平台对齐
DEVICE_POOL = [
    # ---- 三星 Galaxy S26 系列（2026-02-25 发布 / 03-11 开售，Android 16）----
    ('samsung', 'SM-S9420', '16', 'BP2A.250705.008', '1080*2340', 'SM8850-AC'),   # S26
    ('samsung', 'SM-S9470', '16', 'BP2A.250705.008', '1440*3120', 'SM8850-AC'),   # S26+
    ('samsung', 'SM-S9480', '16', 'BP2A.250705.008', '1440*3120', 'SM8850-AC'),   # S26 Ultra
    # ---- 小米 18 系列（2026-09-23，Android 17 / HyperOS 4）----
    ('xiaomi', '26091PN0CC', '17', 'BP3A.260105.001', '1120*2436', 'SM8950'),     # 18 Pro（国行已核验）
    ('xiaomi', '2611FPNFAI', '17', 'BP3A.260105.001', '1120*2436', 'SM8950'),     # 18 Pro Max
    ('xiaomi', '2612FPN0CC', '17', 'BP3A.260105.001', '1220*2656', 'SM8950'),     # 18（推定型号）
    # ---- vivo X500 系列（2026-09-21 发布 / 09-29 开售，Android 17 / OriginOS 7）----
    ('vivo', 'V2608A', '17', 'BP3A.260105.001', '1216*2660', 'MT9600'),           # X500 Pro（国行已核验）
    ('vivo', 'V2609A', '17', 'BP3A.260105.001', '1216*2660', 'MT9600'),           # X500（推定）
    ('vivo', 'V2610A', '17', 'BP3A.260105.001', '1272*2772', 'MT9600'),           # X500 Pro Max（推定）
    # ---- OPPO Find X10 系列（2026-09-22 发布 / 09-24 开售，Android 17 / ColorOS 17）----
    ('oppo', 'PJZ120', '17', 'BP3A.260105.001', '1272*2772', 'MT9600'),           # Find X10 Pro Max（推定）
    ('oppo', 'PJZ121', '17', 'BP3A.260105.001', '1272*2772', 'MT9600'),           # Find X10（推定）
    ('oppo', 'PJZ122', '17', 'BP3A.260105.001', '1216*2660', 'MT9600'),           # Find X10 E（推定）
    # ---- 荣耀 Magic9 系列（2026-09-28，Android 17 / MagicOS 11）----
    ('honor', 'BVL-AN25', '17', 'BP3A.260105.001', '1216*2660', 'SM8950'),        # Magic9（推定）
    ('honor', 'BVL-AN26', '17', 'BP3A.260105.001', '1256*2808', 'SM8950-AC'),     # Magic9 Pro（推定）
    ('honor', 'BVL-AN27', '17', 'BP3A.260105.001', '1312*2880', 'SM8950-AC'),     # Magic9 Pro Max（推定）
    ('honor', 'BRP-AN00', '16', 'BP2A.250705.008', '1200*2664', 'MT8500'),        # Power2（2026-01-05，推定）
    # ---- iQOO 15 Ultra（2026-02-04 发布 / 02-06 开售，Android 16）----
    ('iqoo', 'V2602A', '16', 'BP2A.250705.008', '1440*3168', 'SM8850-AC'),        # 推定型号
    # ---- 一加 Turbo 6（2026-01-08，Android 16）----
    ('oneplus', 'PLF110', '16', 'BP2A.250705.008', '1272*2772', 'SM8735'),        # 推定型号
    # ---- 荣耀 Magic V6 折叠（2026-03-01 发布 / 03-13 国行开售，Android 16）----
    ('honor', 'FCP-AN10', '16', 'BP2A.250705.008', '2104*2344', 'SM8850-AC'),     # Magic V6（推定型号）
    # ---- 荣耀 600 Pro（2026-04-21 全球发布，Android 16 / MagicOS 10）----
    ('honor', 'BRP-NX1', '16', 'BP2A.250705.008', '1280*2800', 'SM8750'),         # 600 Pro（推定型号）
    # ---- vivo S60 系列（2026-05-29 发布 / 06-03 开售，Android 16 / OriginOS 6）----
    ('vivo', 'V2513A', '16', 'BP2A.250705.008', '1260*2750', 'SM8635'),           # S60（推定型号）
    ('vivo', 'V2514A', '16', 'BP2A.250705.008', '1260*2750', 'MT7500'),           # S60 元气版（推定型号）
    # ---- OPPO Reno16 系列（2026 下半年，Android 16 / ColorOS 16）----
    ('oppo', 'PKD140', '16', 'BP2A.250705.008', '1260*2800', 'MT9500'),           # Reno16 Pro（推定）
    ('oppo', 'PKD141', '16', 'BP2A.250705.008', '1260*2800', 'MT9500'),           # Reno16（推定）
    # ---- 红米 Redmi（2026 年）----
    ('redmi', '2602BRT18C', '16', 'BP2A.250705.008', '1220*2712', 'MT8500'),      # Turbo 5（2026-01-23 发布 / 01-29 开售，型号已核验）
    ('redmi', '2608RK10C', '16', 'BP2A.250705.008', '1200*2608', 'SM8850-AC'),    # K100 Pro Max（2026-08，推定型号）
    ('redmi', '2608RK20C', '16', 'BP2A.250705.008', '1220*2712', 'SM8850-AC'),    # K100 Pro（2026-08，推定型号）
    # ---- 真我 realme（2026-09 发布 / 10 首销，Android 17）----
    ('realme', 'RMX5300', '17', 'BP3A.260105.001', '1440*3136', 'SM8950-AC'),     # GT9（推定型号）
    ('realme', 'RMX5301', '17', 'BP3A.260105.001', '1440*3136', 'SM8950-AC'),     # GT9 Pro（推定型号）
    # ---- 摩托罗拉 moto（中国发售，2026 年）----
    ('motorola', 'XT2651-1', '16', 'BP2A.250705.008', '1224*2992', 'SM8850-AC'),  # razr 70 Ultra（2026-05-19 国行发布，推定型号）
    ('motorola', 'XT2551-1', '16', 'BP2A.250705.008', '1920*2200', 'SM8850-AC'),  # razr fold（2026-03 MWC，官方确认登陆中国，推定型号）
    # ---- 红魔 11S Pro（2026-05-18，Android 16）----
    ('nubia', 'NX789J', '16', 'BP2A.250705.008', '1216*2688', 'SM8850-AC'),       # 推定型号
]


def random_device_profile():
    """随机选一台 2026 年度机型，返回完整画像（UA 由画像派生）。

    画像同时喂给 UA、cp、platform_info 与 tiny_mua 的 d 明文，保证
    「mua 自述的机型/系统/分辨率」与 UA/cp 自洽（2026-10-17 的 300014 教训：
    mua 内 channel 与 cp 不一致会直接被判设备异常）。
    """
    brand, model, aver, build_id, res, cpu = random.choice(DEVICE_POOL)
    ua = (f'Dalvik/2.1.0 (Linux; U; Android {aver}; {model} Build/{build_id}) '
          f'Resolution/{res} Version/9.49.1 Build/9491803 '
          f'Device/({brand};{model}) discover/9.49.1 NetType/WiFi')
    return {'brand': brand, 'model': model, 'android': aver, 'build_id': build_id,
            'resolution': res, 'cpu': cpu, 'user_agent': ua}


def random_device():
    """随机选一台 2026 年度机型，返回 (brand, model, user_agent, cpu)。"""
    p = random_device_profile()
    return p['brand'], p['model'], p['user_agent'], p['cpu']


# 便利函数（当前 generate_offline 内部走 random_device，不经过这里）。保留给外部脚本/测试用
def random_user_agent():
    """随机选一台主流机型，构造 xhs UA（Version/9.49.1 + Build/9491803，与 mua v2.10.1 自洽）。"""
    return random_device()[2]


def random_gid():
    """随机生成 gid（56 hex = 28 字节）。

    保持固定骨架不变，只随机 14 字节变化段（变化段经实测为 SecureRandom 纯随机，
    与时间戳/device_id 简单哈希均不命中）：
        7f7d ____ 5748b527 __ 6a14b7ea83d6 __ 4735 ______
    """
    def rb(n):
        return bytes(random.getrandbits(8) for _ in range(n))
    return ('7f7d' + rb(4).hex() + '5748b527' + rb(2).hex()
            + '6a14b7ea83d6' + rb(2).hex() + '4735' + rb(6).hex())


def random_mua0():
    """凭空生成完全独立的 mua0（零模板）。

    2026-10-12 实测：服务端不校验 mua 的任何部分——
    head 的 k/s/u 随机、载荷随机/为空/非法，user/me 均 code=0。
    载荷在真实 App 里是 ECDH 协商密钥加密的本地数据（pm clear 后全新生成，
    与旧安装零重合），所以随机载荷 = 拟真。
    head 固定字段为 9.49.1 的版本标识（a=ECFAAF01/p=a/v=2.10.1），c 从 1 起步。
    """
    hj = {
        'a': 'ECFAAF01', 'c': 1, 'p': 'a',
        'k': secrets.token_hex(32),
        's': secrets.token_hex(64),
        'u': '00000000' + secrets.token_hex(16),
        'v': '2.10.1',
    }
    order = ['a', 'c', 'k', 'p', 's', 't', 'u', 'v']
    new_head = b64url(json.dumps(
        {k: hj[k] for k in order if k in hj}, separators=(',', ':')).encode())
    # 载荷量级对齐真实 App（首笔请求 1088 字符左右，随会话演进增长）
    payload = base64.urlsafe_b64encode(secrets.token_bytes(816)).decode().rstrip('=')
    return new_head + '.' + payload + '.'


# cp 固定骨架：9.49.1 的静态公共字段（App 版本/渠道/语言等，与设备无关的常量）。
# 设备相关字段（did/deviceId/gid/launch_id/sid/t）由 independent_cp() 动态生成。
CP_SKELETON_FIELDS = [
    ('fid', ''), ('device_model', 'phone'), ('tz', 'Asia%2FShanghai'),
    ('channel', 'YingYongBao'), ('versionName', '9.49.1'),
    # cpu_abi / nqe_score 由 independent_cp() 按机型平台动态覆盖：
    #   2026-10-17 真机 9.49.1 冷启动实测 cpu_abi=arm64-v8a、nqe_score=90，
    #   旧骨架写死 armeabi-v7a/86 与旗舰机型自相矛盾，已改为动态值。
    ('platform', 'android'), ('identifier_flag', '4'), ('cpu_abi', 'arm64-v8a'),
    ('nqe_score', '90'), ('project_id', 'ECFAAF'), ('x_trace_page_current', 'explore_feed'),
    ('lang', 'zh-Hans'), ('app_id', 'ECFAAF01'), ('uis', 'light'), ('teenager', '0'),
    ('active_ctry', 'CN'), ('device_level', '3'), ('origin_channel', 'YingYongBao'),
    ('overseas_channel', '0'), ('mlanguage', 'zh_cn'), ('folder_type', 'none'),
    ('auto_trans', '0'), ('build', '9491803'), ('holder_ctry', 'CN'),
    ('SUE', '1'), ('dlang', 'zh'), ('data_ctry', 'CN'),
]


# 机型平台 → nqe_score 区间（性能分随芯片档位走，避免旗舰机型上报低分）
# 依据：真机 9.49.1 冷启动实测 nqe_score=90（天玑 700 机型，属中端档）
CPU_TIER = {
    # 旗舰
    'SM8950': (90, 96), 'SM8950-AC': (90, 96), 'SM8850-AC': (90, 96),
    'MT9600': (89, 95), 'SM8750': (88, 94),
    # 次旗舰 / 高端
    'SM8735': (85, 90), 'SM8635': (84, 89), 'MT9500': (84, 89), 'MT8500': (83, 88),
    # 中端
    'MT7500': (78, 84),
}
NQE_DEFAULT = (86, 91)


def nqe_for_cpu(cpu):
    """按芯片平台给 nqe_score（档位内随机，避免所有设备同分）。"""
    lo, hi = CPU_TIER.get(cpu or '', NQE_DEFAULT)
    return str(random.randint(lo, hi))


# scene 抖动池：权重按真机/历史抓包中的出现频次分布（Android 9.49.1 实测样本）
# fs=0&point=601 为首页推荐（占绝大多数），其余为搜索/详情/分享等页面。
SCENE_POOL = [
    ('fs=0&point=601', 70),
    ('fs=0&point=2565', 10),
    ('fs=0&point=4714', 8),
    ('fs=0&point=1954', 7),
    ('fs=0&point=1185', 5),
]


def random_scene():
    total = sum(w for _, w in SCENE_POOL)
    r = random.uniform(0, total)
    acc = 0.0
    for s, w in SCENE_POOL:
        acc += w
        if r <= acc:
            return s
    return SCENE_POOL[0][0]


def random_launch_id():
    """launch_id = 秒级时间戳，向过去抖 0~179 秒。

    真机 launch_id 是 10 位秒级时间戳（实测 1791891155），不能加毫秒否则位数不对；
    批量生成时向过去抖动可避免同秒撞号，且始终是「刚启动过」的合理值。
    """
    return str(int(time.time()) - random.randint(0, 179))


def independent_cp(model=None, cpu=None):
    """凭空生成完全独立的 cp（零模板）。

    did 派生公式（2026-10-12 从 classes21.dex s22/b 逆向 + 实测命中）：
        did = MD5(clean(硬件ID) + 来源后缀).hex()
        clean = 去掉 '-' 和 '_' 后小写；后缀按优先级 oaid>imei>gid>deviceid>androidid
        真机命中：MD5(OAID去横线小写+'oaid') = 97efcf29...（与真机完全一致）
    其余动态字段：
        deviceId= 新 device_id（与 platform_info 一致）
        gid=     随机 gid
        launch_id= 当前时间戳（真实 App 每次冷启动都变）
        cpu_name= 从机型池带出（与 UA 机型一致）
        cpu_abi=  arm64-v8a（2026 机型均为 64 位，旧骨架 32 位与实际矛盾已修）
        nqe_score= 按芯片档位在区间内随机（见 CPU_TIER）
        launch_id= 秒级时间戳向过去抖 0~179s（避免批量同秒）
        t=       签名时由 XhsSigner.get_cp() 动态替换
        sid=     空（未登录新设备）

    返回 (cp, did, oaid)：oaid 一并返回以便落库追溯（did 由 oaid 单向派生）。
    """
    oaid = secrets.token_hex(32)   # 新设备的「OAID」——本地造
    new_did = hashlib.md5((oaid + 'oaid').encode()).hexdigest()
    cpu_name = cpu or 'MT6833V%2FZA'   # 与机型平台对齐（2026 池按机型带入）
    kv = {k: v for k, v in CP_SKELETON_FIELDS}
    kv['cpu_name'] = cpu_name
    kv['nqe_score'] = nqe_for_cpu(cpu_name)
    kv['cpu_abi'] = 'arm64-v8a'
    kv['did'] = new_did
    kv['launch_id'] = random_launch_id()
    # 顺序对齐真实抓包顺序（deviceId 在 versionName 后、gid 在最前）
    ordered = ['gid', 'fid', 'device_model', 'tz', 'channel', 'versionName',
               'deviceId', 'platform', 'sid', 'identifier_flag', 'cpu_abi',
               'nqe_score', 'project_id', 'x_trace_page_current', 'lang',
               'app_id', 'uis', 'teenager', 'active_ctry', 'cpu_name', 'dlang',
               'data_ctry', 'SUE', 'launch_id', 'id_token', 'device_level',
               'origin_channel', 'overseas_channel', 'mlanguage', 'folder_type',
               'auto_trans', 't', 'build', 'holder_ctry', 'did']
    parts = []
    for k in ordered:
        parts.append(k + '=' + kv.get(k, ''))
    return '&'.join(parts), new_did, oaid


def independent_cp_full(device_id, gid, model=None, cpu=None):
    """生成含 deviceId 的完整独立 cp（零模板）。device_id 由 UUID5(SSAID) 得出。

    返回 (cp, did, oaid)。
    """
    cp, did, oaid = independent_cp(model, cpu)
    cp = cp.replace('deviceId=&', 'deviceId=' + device_id + '&')
    cp = cp.replace('gid=&', 'gid=' + gid + '&')
    return cp, did, oaid


def _make_shield_no_hmac(path, query, device_id, cp, platform_info, scene, body=b''):
    """构造「无 hmac」的 shield（flag=1，key64 用 64 字节全 0）。
    这是新设备首次请求时的形态：客户端尚无 hmac，用 flag=1 发请求，
    服务端据此返回 406 + Xy-Ter-Str（新 hmac）。
    """
    cp_sign = re.sub(r'did=([0-9a-f]{32})', lambda m: 'did=' + m.group(1) + '6', cp)
    body_text = body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body)
    sign_str = path + query + cp_sign + platform_info + scene + body_text
    empty_key64 = b'\x00' * 64
    md5_res = hmac_md5(empty_key64, sign_str.encode('utf-8'))
    b = struct.pack('>I', 1)                       # version
    b += struct.pack('>I', S_APP_ID & 0xffffffff)  # s_app_id
    b += struct.pack('>I', 1)                      # flag=1（无 hmac）
    b += struct.pack('>I', len(BUILD_ID))
    b += struct.pack('>I', len(device_id))
    b += struct.pack('>I', 16)
    b += (BUILD_ID + device_id).encode()
    b += md5_res
    encrypted = rc4(b, RC4_KEY)
    return 'XY' + base64.b64encode(SHIELD_HDR + encrypted).decode()


def _next_mua(mua0):
    """递增 x-mini-mua 的 counter。"""
    parts = mua0.split('.')
    hj = json.loads(b64url_dec(parts[0]))
    hj['c'] = hj.get('c', 0) + 1
    order = ['a', 'c', 'k', 'p', 's', 't', 'u', 'v']
    new_head = b64url(json.dumps({k: hj[k] for k in order if k in hj}, separators=(',', ':')).encode())
    return new_head + '.' + parts[1] + '.', hj['c']


def _make_session(proxy: str = ""):
    """构造 TLS 会话。proxy 非空时整条请求走该代理（设备绑定代理时，生成阶段也要走）。"""
    import tls_client
    order = ['referer', 'shield', 'user-agent', 'x-b3-traceid', 'x-legacy-did',
             'x-legacy-fid', 'x-legacy-sid', 'x-mini-gid', 'x-mini-mua',
             'x-mini-sig', 'x-xray-traceid', 'xy-common-params', 'xy-direction',
             'xy-platform-info', 'xy-scene']
    session = tls_client.Session(
        client_identifier=None, ja3_string=JA3,
        supported_versions=['1.3', '1.2'],
        supported_signature_algorithms=['ECDSAWithP256AndSHA256', 'PSSWithSHA256', 'PKCS1WithSHA256',
                                        'ECDSAWithP384AndSHA384', 'PSSWithSHA384', 'PKCS1WithSHA384',
                                        'PSSWithSHA512', 'PKCS1WithSHA512', 'PKCS1WithSHA1'],
        key_share_curves=['X25519'], alpn_protocols=['h2', 'http/1.1'],
        pseudo_header_order=[':method', ':authority', ':scheme', ':path'],
        header_order=order,
    )
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    return session


# 默认 homefeed 请求（触发 406 下发 hmac 用）
HOMEFEED_PATH = '/api/sns/v6/homefeed'
HOMEFEED_QUERY = ('oid=homefeed_recommend&cursor_score=&geo=eyJsYXRpdHVkZSI6MC4wMDAwMDAsImxvbmcgIjowLjAwMDAwMCwiaG9yaXpvbnRhbF9hY2N1cmFjeSI6MC4wMDAwMDB9'
                  '&page_size=20&refresh_type=1&last_note_id=&unread_begin_note_id=&unread_end_note_id=&unread_note_count=0'
                  '&category=homefeed_recommend&session_id=0&recommend_enhance=true&publish_ts=0'
                  '&personal_recommend_source=explore_trending_recommend&need_ab=0&bottom_refresh=0')


def _make_homefeed_headers(device_id, template, mua_counter=None):
    """构造「无 hmac 新设备」发 homefeed 所需的完整请求头。返回 (url, hdrs, counter)。"""
    mua0 = template['mua0']
    cp = template['cp']
    platform_info = 'platform=android&build=9491803&deviceId=' + device_id
    scene = template['scene']
    user_agent = template['user_agent']
    gid = template['gid']
    sid = template.get('sid', '')

    new_mua, counter = _next_mua(mua0)
    if mua_counter is not None:
        counter = mua_counter

    url = f'https://rec.xiaohongshu.com{HOMEFEED_PATH}?{HOMEFEED_QUERY}'
    shield = _make_shield_no_hmac(HOMEFEED_PATH, HOMEFEED_QUERY, device_id, cp, platform_info, scene)
    canon = canonical_str('GET', HOMEFEED_PATH, HOMEFEED_QUERY, b'', new_mua)
    sig = compute_sig(canon)
    # ★ 不发 x-mini-s1：dex 全量里没有这个请求头（62B s1 的真名是 x-mini-sig），
    #   服务端也不校验。此处与 XhsSigner9491.sign() 保持同一口径。

    hdrs = {
        'Accept-Encoding': 'gzip',
        'Connection': 'Keep-Alive',
        'Referer': 'https://app.xhs.cn/',
        'shield': shield,
        'User-Agent': user_agent,
        'X-B3-TraceId': ''.join(random.choice('0123456789abcdef') for _ in range(16)),
        'x-legacy-did': device_id,
        'x-legacy-fid': '',
        'x-legacy-sid': sid,
        'x-mini-gid': gid,
        'x-mini-mua': new_mua,
        'x-mini-sig': sig,
        'x-xray-traceid': ''.join(random.choice('0123456789abcdef') for _ in range(32)),
        'xy-common-params': cp,
        'xy-direction': '6',
        'xy-platform-info': platform_info,
        'xy-scene': scene,
    }
    return url, hdrs, counter


def tune_cp(cp):
    """把 cp 里仍"一刀切"的骨架常量对齐真机基准（服务器设备#1 honor BRP-NX1）：

      cpu_abi   : arm64-v8a → armeabi-v7a（真机实测值）
      nqe_score : 固定值 → 84~88 随机（真机 86）
      channel   : 保持出厂 YingYongBao，**不再强改 Guanfang**（真机就是 YingYongBao）

    不动项（与真机逐字段一致）：device_model=phone / x_trace_page_current=explore_feed /
    device_level=3 / identifier_flag=4 / project_id=ECFAAF / SUE=1 …
    依据：2026-10-21 i24 报告（真机 cp 35 字段逐项对比）。
    """
    import random as _r
    import re as _re
    cp = _re.sub(r'(^|&)cpu_abi=[^&]*', r'\1cpu_abi=armeabi-v7a', cp)
    cp = _re.sub(r'(^|&)nqe_score=[^&]*', r'\1nqe_score=%d' % _r.randint(84, 88), cp)
    return cp


def generate_offline(new_ssaid=None, template=None, progress=None, proxy: str = ""):
    """纯离线生成一套新设备身份（不依赖真机）。

    原理（2026-10-12 破解）：
      1. device_id = UUID5(SSAID)（本地算法）
      2. 用「无 hmac 的 shield(flag=1)」PC 直连发 homefeed → 服务端 406 + Xy-Ter-Str 下发新 hmac
      3. key64 = 白盒AES-CBC解密(hmac, device_id)（复用 xhs_core.get_key64）

    template: 兼容参数，已不使用（保留签名避免破坏调用方）。
      全套材料本地生成、零模板依赖：UA/gid/mua0/cp/platform_info/scene 全部凭空构造。

    proxy: 可选。填了则**取 hmac 的这一步也走代理**（设备要绑代理时，
      直连 IP 可能已被风控，必须一并走）。代理不通会直接报错并指明是代理问题。

    返回 dict：{ssaid, device_id, device_id_ok, hmac, key64, mua0, cp, did, ...}
    """
    def _p(stage, msg):
        if progress:
            try:
                progress(stage, msg)
            except Exception:
                pass

    if new_ssaid is None:
        new_ssaid = gen_ssaid()
    if not re.fullmatch(r'[0-9a-f]{16}', new_ssaid or ''):
        raise DeviceFactoryError('SSAID 必须是 16 位小写 hex')

    device_id = uuid5(new_ssaid)

    # 完全独立设备材料（2026-10-12 破解：服务端不校验任何血统字段的真实性）：
    # - UA/gid 随机（不参与签名）
    # - mua0：head 全随机 + 载荷随机（服务端连载荷都不看）
    # - cp：did= 用逆向公式（MD5(硬件ID+'oaid')）本地派生，静态字段为内置骨架
    # - platform_info/scene：本地构造
    # 零模板、零真机依赖。
    brand, model, ua, cpu = random_device()
    gid = random_gid()
    # mua：优先用 tiny 真离线生成（k=X25519(priv,9)、d=AES-128-CBC(zlib(设备自述JSON))），
    # 失败回落到「head 随机 + 载荷随机冒充」的老路，保证生成链不中断。
    prof = random_device_profile()
    prof.update({'brand': brand, 'model': model, 'user_agent': ua, 'cpu': cpu})
    mua_source = 'random'
    try:
        from tiny_mua import build_mua
        mua0, _mua_builder = build_mua(prof)
        mua_source = 'tiny'
    except Exception as _e:      # noqa: BLE001
        mua0 = random_mua0()
        mua_source = 'random(%s)' % _e
    cp, local_did, oaid = independent_cp_full(device_id, gid, model, cpu)
    cp = tune_cp(cp)
    platform_info = 'platform=android&build=9491803&deviceId=' + device_id
    scene = random_scene()
    tpl = {
        'mua0': mua0, 'cp': cp, 'platform_info': platform_info,
        'scene': scene, 'user_agent': ua, 'gid': gid, 'sid': '',
    }

    _p(1, f'本地算 device_id = UUID5({new_ssaid})，did = MD5(oaid+oaid) = {local_did[:16]}...')
    _p(2, ('经代理 %s ' % proxy if proxy else 'PC 直连') + '发 homefeed（无 hmac shield）触发服务端下发 ...')

    url, hdrs, _ = _make_homefeed_headers(device_id, tpl)

    s = _make_session(proxy)
    try:
        resp = s.get(url, headers=hdrs)
    except Exception as e:  # noqa: BLE001
        via = ('经代理 %s ' % proxy) if proxy else '直连'
        raise DeviceFactoryError(f'{via}请求 homefeed 失败（代理可能不通）：{e}') from e

    hmac = resp.headers.get('Xy-Ter-Str') or resp.headers.get('xy-ter-str') or ''
    if not hmac:
        raise DeviceFactoryError(f'响应无 Xy-Ter-Str（HTTP {resp.status_code}），无法下发 hmac')

    _p(3, '服务端已下发新 hmac，解密 key64 ...')
    key64 = get_key64(hmac, device_id)

    dev = {
        'ssaid': new_ssaid,
        'device_id': device_id,
        'device_id_ok': True,
        'hmac': hmac,
        'key64': key64.hex(),
        'user_agent': ua,
        'device_model': model,
        'device_brand': brand,
        'gid': gid,
        'mua0': mua0,
        'cp': cp,
        'platform_info': platform_info,
        'scene': scene,
        'did': local_did,
        'oaid': oaid,
        'mua_source': mua_source,
        'source': 'offline',
        'ver': '9.49.1',          # ★ 材料版本标记：_signer 据此走 XhsSigner9491（2026-10-26）
    }

    # ★ 生成后自检：材料不自洽就当场报错，不让坏材料入库（2026-10-26）
    _probs = verify_material(dev)
    if _probs:
        raise DeviceFactoryError('材料自检不通过：' + '；'.join(_probs))

    return dev



# ============ 材料一致性校验（2026-10-26，依据已确证的服务端规则）============
# 服务端会校验「跨材料一致性」，任一处对不上就容易吃 461 / 300011：
#   · UA 的 Version/x Build/y  ↔  cp.versionName / cp.build  ↔  platform_info.build
#   · mua 头 v  ↔  材料版本（9.49.1 → 2.10.1；9.19.2 → 2.9.55）
#   · cp.cpu_abi  ↔  mua x21 首位（9.49.1 官方只发 v7a，故必须是 armeabi-v7a）

_EXPECT_MUA_V = {'9.49.1': '2.10.1', '9.19.2': '2.9.55'}


def verify_material(payload):
    """检查一套设备材料是否自洽。返回问题列表（空列表 = 合格）。

    对 9.19.2 存量设备（payload 无 ver）只查内部一致性，不查版本对应关系，
    避免把历史设备误判成坏材料。
    """
    probs = []
    if not isinstance(payload, dict):
        return ['payload 不是 dict']

    # 1) 必需字段
    #    device_id 与 did 同值（did 是签名器沿用的历史命名）。存量「导入」的设备材料
    #    往往只有 did，所以两者取其一即可 —— 否则老设备会被误判成「缺字段」而上报红。
    for k in ('did', 'hmac', 'key64', 'mua0', 'cp', 'platform_info', 'user_agent'):
        if not payload.get(k):
            probs.append('缺字段 %s' % k)
    if not (payload.get('device_id') or payload.get('did')):
        probs.append('缺字段 device_id/did')
    if probs:
        return probs       # 字段都不全，后面没法查

    ua = payload.get('user_agent') or ''
    cp = payload.get('cp') or ''
    pi = payload.get('platform_info') or ''
    ver = payload.get('ver')

    def _g(s, key):
        import re as _re
        mm = _re.search(r'(?:^|&)' + key + r'=([^&]*)', s)
        return mm.group(1) if mm else None

    # 2) UA ↔ cp ↔ platform_info
    import re as _re
    m_ua = _re.search(r'Version/([\d.]+)\s+Build/([\w.]+)', ua)
    ua_ver, ua_build = (m_ua.group(1), m_ua.group(2)) if m_ua else (None, None)
    cp_ver, cp_build, cp_abi = _g(cp, 'versionName'), _g(cp, 'build'), _g(cp, 'cpu_abi')
    pi_build = _g(pi, 'build')
    if ua_ver and cp_ver and ua_ver != cp_ver:
        probs.append('版本不一致 UA=%s cp=%s' % (ua_ver, cp_ver))
    if ua_build and cp_build and ua_build != cp_build:
        probs.append('build 不一致 UA=%s cp=%s' % (ua_build, cp_build))
    if cp_build and pi_build and cp_build != pi_build:
        probs.append('build 不一致 cp=%s platform_info=%s' % (cp_build, pi_build))

    # 3) mua 头 v ↔ 材料版本
    try:
        import base64 as _b64
        import json as _json
        head_b64 = (payload.get('mua0') or '').split('.')[0]
        head = _json.loads(_b64.urlsafe_b64decode(head_b64 + '=' * (-len(head_b64) % 4)).decode())
        mua_v = head.get('v')
        if ver in _EXPECT_MUA_V and mua_v != _EXPECT_MUA_V[ver]:
            probs.append('mua 版本不匹配 ver=%s 期望 v=%s 实际 v=%s'
                         % (ver, _EXPECT_MUA_V[ver], mua_v))
    except Exception as e:
        probs.append('mua0 头部无法解析: %s' % str(e)[:40])

    # 4) cpu_abi
    if ver == '9.49.1' and cp_abi and cp_abi != 'armeabi-v7a':
        probs.append('cpu_abi 应为 armeabi-v7a（9.49.1 只发 v7a），实际 %s' % cp_abi)

    return probs


def generate(new_ssaid=None, template=None, progress=None):
    """生成一套新设备身份（纯离线，统一入口）。

    template 参数已废弃（兼容保留），生成完全不依赖模板。
    """
    return generate_offline(new_ssaid=new_ssaid, template=template, progress=progress)


if __name__ == '__main__':
    # 从会话模板生成（模板需含 mua0/cp/scene/user_agent/gid/sid）
    import sys as _sys
    _tpl_path = _sys.argv[1] if len(_sys.argv) > 1 else None
    if not _tpl_path:
        print('用法: python device_factory.py <template.json> [ssaid]')
        _sys.exit(1)
    _sess = json.load(open(_tpl_path, encoding='utf-8'))
    _entry = _sess[0] if isinstance(_sess, list) else _sess
    _tpl = {}
    for _h in _entry.get('headers', []):
        _k = _h.get('k'); _v = _h.get('v'); _v = _v[0] if isinstance(_v, list) else _v
        if _k == 'x-mini-mua': _tpl['mua0'] = _v
        elif _k == 'xy-common-params': _tpl['cp'] = _v
        elif _k == 'xy-platform-info': _tpl['platform_info'] = _v
        elif _k == 'xy-scene': _tpl['scene'] = _v
        elif _k == 'User-Agent': _tpl['user_agent'] = _v
        elif _k == 'x-mini-gid': _tpl['gid'] = _v
        elif _k == 'x-legacy-sid': _tpl['sid'] = _v
    _ssaid = _sys.argv[2] if len(_sys.argv) > 2 else None
    r = generate_offline(_ssaid, _tpl, progress=lambda s, m: print(f'[{s}/3] {m}'))
    print(json.dumps(r, indent=2, ensure_ascii=False))
