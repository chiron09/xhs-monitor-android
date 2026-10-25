# -*- coding: utf-8 -*-
"""小红书 9.49.1 完全离线签名核心（xhs-monitor 双轨版）

与 9.19.2（xhs_core.py）的差异：
  1. BUILD_ID  = '9491803'（UA/platform_info 同步改）
  2. SIG 矩阵  = sig_matrix_9491.json（与 9.19.2 的 sig_final.json 不同！）
  3. shield    = RC4 三段式（54B 设备段 + 48B 票据段【跳 stream[54:68]】+ sid 段），
                 附 SSK proof（登录后）或 70B 无票据版（未登录/activate）
  4. 登录态    = sid + main_ssk（X25519+AES-GCM 自举，activate 端点）
  5. UA/cp     = 9.49.1（versionName=9.49.1/build=9491803）

MD5 变体 / hmac_md5 / rc4 / S1 算法与 9.19.2 完全一致（已对比 algo 参数一致），
直接从 xhs_core 复用，避免重复维护。
"""
import json, struct, base64, hashlib, time, random, threading, sys, os
from urllib.parse import urlsplit, urlencode

from xhs_perm import make_perm8_zero, make_perm4_zero   # s1 的真 perm8/perm4

# 复用 9.19.2 的纯算法层（MD5 变体/hmac/rc4/S1/canonical/get_key64 依赖 shield_sdk）
from xhs_core import (hmac_md5, rc4, b64url, b64url_dec,
                      canonical_str, make_s1, JA3 as _JA3_9192)

# ============ 常量（9.49.1） ============
BUILD_ID = '9491803'
RC4_KEY = '逆向违法，即刻停止！Reverse engineering is illegal. Cease now!'.encode()
MASK36 = bytes.fromhex('606b39fd3c39443008502297d736827cf3903c05d0e77e0737f77066f77460435bd69068')
MASK16 = bytes.fromhex('b3661b2425c8d1cf9674e8218b30b91a')
SHIELD_HDR = bytes.fromhex('8dfe000655699e8aa6d7a545949cf962')
S_APP_ID = 0xECFAAF01
JA3 = _JA3_9192  # TLS 指纹相同
UPSTREAM = 'https://edith.xiaohongshu.com'

BASE = os.environ.get('XHS_ALGO_BASE') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'vendor_algo')
if BASE not in sys.path:
    sys.path.insert(0, BASE)

# SIG 矩阵（9.49.1 专用！与 9.19.2 不同）
# ★ 延迟加载：原来在模块级 open()，只要 XHS_ALGO_BASE 不对（或资产没同步）整个模块
#   import 就抛异常。而本模块是 xhs_client._signer() 里按需 import 的 ——
#   只用 9.19.2 设备的部署不该被 9491 资产缺失牵连，改成首次用到才加载。
_SIG_LOCK = threading.Lock()
_SIG_TABLES = None


def _sig_tables():
    """返回 (const, coef[128])；加载失败抛 RuntimeError，并打出实际查找路径。"""
    global _SIG_TABLES
    if _SIG_TABLES is None:
        with _SIG_LOCK:
            if _SIG_TABLES is None:
                path = os.path.join(BASE, 'sig_matrix_9491.json')
                try:
                    with open(path, encoding='utf-8') as f:
                        sig = json.load(f)
                    _SIG_TABLES = (sig['const'], [sig['coef'][j] for j in range(128)])
                except Exception as e:  # noqa: BLE001
                    raise RuntimeError(
                        '9.49.1 SIG 矩阵加载失败: %s'
                        '（检查 XHS_ALGO_BASE 环境变量，当前 BASE=%s）: %s'
                        % (path, BASE, e)) from e
    return _SIG_TABLES

SSK_SERVER_PUB = bytes.fromhex('2abd22ca0b02bb78a760935708be24e09bb369843669f235c5bc1cec11fab26f')


def _gf2(digest16):
    const, coef = _sig_tables()
    v = int.from_bytes(digest16, 'big') | (1 << 128)
    y = const
    for j in range(128):
        if (v >> j) & 1:
            y ^= coef[j]
    return y.to_bytes(16, 'big')


def compute_sig(canon):
    if isinstance(canon, str):
        canon = canon.encode()
    d = hashlib.sha256(canon).digest()
    return (_gf2(d[:16]) + d[16:]).hex()


def get_key64(main_hmac, device_id):
    """白盒 AES 派生 key64（同 9.19.2 算法，build_id=9491803）。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location('shield_sdk', BASE + '/shield_sdk.py')
    m = importlib.util.module_from_spec(spec)
    sys.modules['shield_sdk'] = m
    spec.loader.exec_module(m)
    m.GlobalData.build_id = BUILD_ID
    m.GlobalData.device_id = device_id
    m.GlobalData.hmac = main_hmac
    m.GlobalData.xor_byte = list(m.ShieldSdk._XOR_BYTE_DEFAULT)
    m.GlobalData.s_app_id = S_APP_ID
    xy = m.XYAes()
    xy.key_expansion(); xy.aes_init()
    hmac_hex = bytes.hex(base64.b64decode(main_hmac.encode()))
    res = []
    for i in range(6):
        h1 = hmac_hex[i*32:(i+1)*32]
        out = xy.aes_decrypt(h1)
        for j in range(16):
            res.append(out[j] ^ m.GlobalData.xor_byte[j])
            m.GlobalData.xor_byte[j] = int(h1[j*2:j*2+2], 16)
    return bytes(res[16:80])


class XhsSigner9491:
    """9.49.1 设备签名器（sid + main_ssk 票据体系）。

    device payload 需含：did/hmac/mua0/cp/gid/platform_info/scene/user_agent（同 9.19.2）
    + main_ssk（base64，登录后由 activate 下发；未登录为空）
    """

    def __init__(self, device: dict):
        self.did = device['did']
        self.hmac = device['hmac']
        self.sid = (device.get('sid') or '').strip()
        if self.sid and not self.sid.startswith('session.'):
            self.sid = 'session.' + self.sid
        self.gid = device.get('gid') or ''
        self.mua0 = device.get('mua0') or ''
        self.cp_tmpl = device.get('cp') or ''
        self.platform_info = device.get('platform_info') or ''
        self.scene = device.get('scene') or ''
        self.user_agent = device.get('user_agent') or ''
        self.proxy = device.get('proxy') or ''
        # 9.49.1 新增：会话票据
        self.main_ssk_b64 = device.get('main_ssk') or device.get('main_ssk_b64') or ''
        # 9.49.1 网络特征头（参与 shield source 组成，真机必带）
        self.direction = device.get('direction') or '76'
        self.bandwidth = device.get('bandwidth') or ''
        self.networktype = device.get('networktype') or ''
        # 真机的 X-XHS-Ext-* 头（DNS 优化头，服务端可能用于识别真机客户端）
        self.ext_ip_list = device.get('ext_ip_list') or ''
        self.ext_dns_tag = device.get('ext_dns_tag') or ''
        self.ext_failover = device.get('ext_failover') or ''

        self.key64 = get_key64(self.hmac, self.did)
        try:
            self.counter = json.loads(b64url_dec(self.mua0.split('.')[0]))['c']
        except Exception:
            self.counter = 0
        self._lock = threading.Lock()

    # ---- 会话材料 ----
    def next_mua(self):
        with self._lock:
            self.counter += 1
            parts = self.mua0.split('.')
            hj = json.loads(b64url_dec(parts[0]))
            hj['c'] = self.counter
            order = ['a', 'c', 'k', 'p', 's', 't', 'u', 'v']
            new_head = b64url(json.dumps(
                {k: hj[k] for k in order if k in hj}, separators=(',', ':')).encode())
            return new_head + '.' + parts[1] + '.', self.counter

    def get_cp(self):
        ts = str(int(time.time()))
        parts = self.cp_tmpl.split('&')
        out = []
        for part in parts:
            if part.startswith('t='):
                out.append('t=' + ts)
            elif part.startswith('sid='):
                out.append('sid=' + self.sid)
            else:
                out.append(part)
        return '&'.join(out)

    # ---- shield（9.49.1 三段式）----
    def make_shield(self, path, query, req_body=b''):
        cp = self.get_cp()
        body_text = req_body.decode('utf-8', 'replace') if isinstance(req_body, bytes) else str(req_body)
        platform = self.platform_info
        # 9.49.1 真机 source（frida 实测 2026-10-13）：
        # path + query + cp(原样，含 &did=32chars) + direction + bandwidth + networktype
        # + platform段 + scene段 + body
        # ⚠️ 2026-10-15 修复：scene 段必须用 self.scene（与 xy-scene 头一致）！
        # 服务端用请求头 xy-scene 的值重建 source 校验；硬编码 'fs=0&point=601'
        # 只在设备 scene==601 时巧合正确，其他 scene（如 1185）会 406。
        scene_seg = self.scene or 'fs=0&point=601'
        source = (path + query + cp + self.direction + self.bandwidth + self.networktype
                  + platform + scene_seg + body_text)
        request_hmac = hmac_md5(self.key64, source.encode('utf-8'))
        tail = bytes(a ^ b for a, b in zip(request_hmac, MASK16))

        plain54 = bytes([0xC1]) + bytes(a ^ b for a, b in zip(self.did.encode(), MASK36)) \
                  + bytes([0xF4]) + tail

        if self.main_ssk_b64:
            # 完整版：附 SSK proof（登录态）
            nonce4 = struct.pack('<I', random.getrandbits(32))
            ssk_proof24 = nonce4 + hashlib.sha1(self.main_ssk_b64.encode() + nonce4).digest()
            req_proof20 = hashlib.sha1(request_hmac + ssk_proof24).digest()
            plain48 = b'\x04\x14' + req_proof20 + b'\x05\x18' + ssk_proof24
            sid_b = self.sid.encode()
            plain_sid = b'\x06' + bytes([len(sid_b)]) + sid_b
            stream = rc4(b'\x00' * (116 + len(plain_sid)), RC4_KEY)
            raw = SHIELD_HDR
            raw += bytes(a ^ b for a, b in zip(plain54, stream[0:54]))
            raw += bytes(a ^ b for a, b in zip(plain48, stream[68:116]))
            raw += bytes(a ^ b for a, b in zip(plain_sid, stream[116:116 + len(plain_sid)]))
        else:
            # 70B 无票据版（未登录/activate 阶段）
            plain = plain54
            stream = rc4(plain, RC4_KEY)
            raw = SHIELD_HDR + stream
        return 'XY' + base64.b64encode(raw).decode()

    # ---- 完整请求头 ----
    def sign(self, method, url, body=b''):
        p = urlsplit(url)
        path, query = p.path, p.query
        cp = self.get_cp()
        new_mua, counter = self.next_mua()

        shield = self.make_shield(path, query, body)

        canon = canonical_str(method, path, query, body if isinstance(body, bytes) else b'', new_mua)
        sig = compute_sig(canon)
        ts = int(time.time())
        # ★ perm8/perm4 均为真算法（2026-10-26 perm4 也已破解，363/363 验证）
        s1 = make_s1(canon.encode(), counter, ts, make_perm8_zero(ts), make_perm4_zero(ts))

        hdrs = {
            'Accept-Encoding': 'gzip',
            'Connection': 'Keep-Alive',
            'Referer': 'https://app.xhs.cn/',
            'shield': shield,
            'User-Agent': self.user_agent,
            'X-B3-TraceId': ''.join(random.choice('0123456789abcdef') for _ in range(16)),
            'x-legacy-did': self.did,
            'x-legacy-fid': '',
            'x-legacy-sid': self.sid,
            'x-mini-gid': self.gid,
            'x-mini-mua': new_mua,
            # 'x-mini-s1': s1,   # dex 全量无此头（x-mini-sig 才是 62B s1 的真名）；服务端不校验
            'x-mini-sig': sig,
            'x-xray-traceid': ''.join(random.choice('0123456789abcdef') for _ in range(32)),
            'xy-common-params': cp,
            'xy-direction': self.direction,
            'xy-platform-info': self.platform_info,
            'xy-scene': self.scene,
        }
        # 9.49.1 真机必备的 5 个头（X-XHS-Ext-* + xy-live-net-*）
        if self.ext_ip_list:
            hdrs['X-XHS-Ext-CustomIPList'] = self.ext_ip_list
        if self.ext_dns_tag:
            hdrs['X-XHS-Ext-DNSIsolateTag'] = self.ext_dns_tag
        if self.ext_failover:
            hdrs['X-XHS-Ext-Failover'] = self.ext_failover
        if self.bandwidth:
            hdrs['xy-live-net-bandwidth'] = self.bandwidth
        if self.networktype:
            hdrs['xy-live-net-networktype'] = self.networktype
        return hdrs

    # ---- 取数 ----
    def make_session(self):
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
        if self.proxy:
            session.proxies = {'http': self.proxy, 'https': self.proxy}
        return session

    def fetch(self, url, method='GET', body=b'', content_type=None):
        hdrs = self.sign(method, url, body)
        if content_type:
            hdrs['Content-Type'] = content_type
        s = self.make_session()
        if method == 'GET':
            resp = s.get(url, headers=hdrs)
        else:
            resp = s.post(url, headers=hdrs, data=body)
        return resp.status_code, resp.text


# ============ 材料升级（9.19.2 → 9.49.1） ============

def upgrade_payload(p: dict) -> dict:
    """把 9.19.2 设备材料升级为 9.49.1 材料（2026-10-13 实测验证）。

    改动点：
      1. UA/cp/platform_info 版本号 → 9.49.1 / build 9491803
      2. mua 载荷 v → 2.10.1（关键！否则内容接口 461 风控"账号异常"）
      3. 新增 direction='76' / bandwidth / networktype（参与 shield source）
      4. ver='9.49.1' 标记（xhs_client 双轨据此选择签名器）
      5. 保留 sid/登录态；main_ssk 清空（实测 70B 无 ssk 可通过全部接口）
    """
    q = dict(p)
    q['user_agent'] = (q.get('user_agent', '')
                       .replace('Version/9.19.2', 'Version/9.49.1')
                       .replace('Build/9192809', 'Build/9491803')
                       .replace('discover/9.19.2', 'discover/9.49.1'))
    q['cp'] = (q.get('cp', '')
               .replace('versionName=9.19.2', 'versionName=9.49.1')
               .replace('build=9192809', 'build=9491803'))
    q['platform_info'] = q.get('platform_info', '').replace('build=9192809', 'build=9491803')
    # mua 载荷 v → 2.10.1
    parts = q.get('mua0', '').split('.')
    if len(parts) >= 2:
        try:
            head = json.loads(b64url_dec(parts[0]))
            head['v'] = '2.10.1'
            order = ['a', 'c', 'k', 'p', 's', 't', 'u', 'v']
            nh = b64url(json.dumps({k: head[k] for k in order if k in head},
                                   separators=(',', ':')).encode())
            q['mua0'] = nh + '.' + parts[1] + '.' + (parts[2] if len(parts) > 2 else '')
        except Exception:
            pass
    q['direction'] = q.get('direction') or '76'
    q['bandwidth'] = q.get('bandwidth') or '35404151'
    q['networktype'] = q.get('networktype') or 'HighSpeed-MiddleLatency-LowLoss-LowStable'
    q['ver'] = '9.49.1'
    q.pop('main_ssk', None)
    return q


# ============ activate（票据自举） ============
ANDROID_ID = '1a80b18b5662a428'


# 逆向资产：9.49.1 票据自举（X25519+AES-GCM）。当前登录走手机验证码，此处无调用方，
def activate_bootstrap(device: dict):
    """用设备材料发 activate，返回 (main_ssk_b64, new_sid, resp_data)。

    device: 同 XhsSigner9491 的 payload（未登录也可，无 sid 无 main_ssk）。
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    signer = XhsSigner9491(device)
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    client_pub_b64 = base64.b64encode(pub_bytes).decode()

    fields = [
        ('idfa', ''), ('idfv', ''), ('android_id', ANDROID_ID), ('channel', 'Guanfang'),
        ('pasteboard', ''), ('category', ''), ('oaid', ''), ('android_version', '11'),
        ('mac', ''), ('gaid', ''), ('attribution_id', ''), ('imei_encrypted', ''),
        ('install_time', ''), ('install_first_open', 'false'), ('open_url', ''),
        ('after_register', 'false'), ('last_login_user_id', ''), ('extra_data', ''),
        ('client_public_key_base64', client_pub_b64),
    ]
    body = urlencode(fields).encode('utf-8')
    path = '/api/sns/v1/user/activate'

    hdrs = signer.sign('POST', UPSTREAM + path, body)
    hdrs['Content-Type'] = 'application/x-www-form-urlencoded'

    s = signer.make_session()
    resp = s.post(UPSTREAM + path, headers=hdrs, data=body)
    d = resp.json()
    if d.get('code') != 0 or not d.get('success'):
        raise RuntimeError(f'activate 失败: HTTP {resp.status_code} {resp.text[:200]}')
    data = d.get('data') or {}
    ssk = data.get('ssk')
    if not ssk:
        raise RuntimeError(f'响应无 ssk 字段: {sorted(data.keys())}')
    shared = priv.exchange(X25519PublicKey.from_public_bytes(SSK_SERVER_PUB))
    blob = base64.b64decode(ssk)
    iv, ct = blob[:12], blob[12:]
    main_ssk = AESGCM(shared).decrypt(iv, ct, None)
    main_ssk_b64 = base64.b64encode(main_ssk).decode()
    new_sid = 'session.' + str(data.get('session'))
    return main_ssk_b64, new_sid, data
