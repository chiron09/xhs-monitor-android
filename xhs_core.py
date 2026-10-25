# -*- coding: utf-8 -*-
"""小红书 9.19.2 完全离线签名核心（参数化多设备版）

9.19.2 方案相对 9.49.1 的关键差异：
- **无 SSK 扩展 / 无 main_ssk 会话密钥**：登录态 = sid + id_token（登录后持久，直到账号过期/下线），
  没有"会话密钥冷启动会变、需自举刷新"的麻烦。
- shield 封装更简单：RC4 key="std::abort();"，header=`00040004 00000001 00000053 00000053`。
- sign_str = path + query + cp_sign(did加校验位6) + platform_info + scene（无 direction/bandwidth/networktype）。
- SIG 用 sig_final.json，S1 与 9.49.1 相同（xhs_signer.make_s1）。

依赖（本项目内 vendor_algo/）：
- shield_sdk.py  白盒 AES（GlobalData / XYAes）
- xhs_signer.py  canonical_str + compute_sig(sig_final.json) + make_s1
- mini_alg.py    S1 基础原语
- algo_complete.json  MD5 变体参数（K/ROR/g/upd/IV）
- sig_final.json  SIG GF(2) 仿射矩阵（9.19.2）
"""
import os
import sys
import json
import struct
import base64
import importlib.util
import time
import random
import re
import threading

from xhs_perm import make_perm8_zero   # s1 的真 perm8（320/320 验证）
from urllib.parse import urlsplit

# ============ 算法库路径 ============
# 本项目**自包含**：算法资产随仓库放在 vendor_algo/，默认就用它。
# 环境变量 XHS_ALGO_BASE 仍可覆盖（容器里指向 /app/vendor_algo，等价）。
# 原来默认值是开发机的 F:/Workbuddy/xhs-shield-analysis —— 换机器/容器就崩，
# 独立成单体项目后改成「按本文件位置找 vendor_algo」，不再依赖外部目录。
_HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get('XHS_ALGO_BASE') or os.path.join(_HERE, 'vendor_algo')
UPSTREAM_BASE = 'https://edith.xiaohongshu.com'

# ============ 常量（9.19.2） ============
RC4_KEY = b'std::abort();'
SHIELD_HDR = b'\x00\x04\x00\x04' + b'\x00\x00\x00\x01' + b'\x00\x00\x00\x53' + b'\x00\x00\x00\x53'
JA3 = '771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0'
S_APP_ID = 0xECFAAF01
BUILD_ID = '9192809'

# ============ 加载算法资产 ============
def _load_asset(name):
    """读取算法资产，失败时给出可诊断的错误（而不是裸 FileNotFoundError）。

    BASE 默认值是开发机路径，生产靠 XHS_ALGO_BASE 覆盖（compose 里指 /app/vendor_algo）。
    这里的报错会把「当前 BASE 是什么」直接打出来，省掉一轮排查。
    """
    path = os.path.join(BASE, name)
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(
            '算法资产加载失败: %s（检查 XHS_ALGO_BASE 环境变量，当前 BASE=%s）: %s'
            % (path, BASE, e)) from e


_algo = _load_asset('algo_complete.json')
K = _algo['K']
ROR = _algo['ROR']
G = _algo['g']
UPD = _algo['upd']
IV = _algo['IV']


def _load_shield_sdk():
    path = os.path.join(BASE, 'shield_sdk.py')
    if not os.path.isfile(path):
        raise RuntimeError(
            '算法资产缺失: %s（检查 XHS_ALGO_BASE 环境变量，当前 BASE=%s）' % (path, BASE))
    spec = importlib.util.spec_from_file_location('shield_sdk', path)
    m = importlib.util.module_from_spec(spec)
    sys.modules['shield_sdk'] = m
    spec.loader.exec_module(m)
    return m


_shield_sdk = _load_shield_sdk()


def _load_xhs_signer():
    sys.path.insert(0, BASE)  # 让 xhs_signer 的 from mini_alg import 生效
    _old = os.getcwd()
    os.chdir(BASE)  # xhs_signer 模块级 open('sig_final.json') 需 cwd=BASE
    try:
        import xhs_signer as m
        return m
    finally:
        os.chdir(_old)


_xhs_signer = _load_xhs_signer()
canonical_str = _xhs_signer.canonical_str
compute_sig = _xhs_signer.compute_sig
make_s1 = _xhs_signer.make_s1


# ============ MD5 变体 / HMAC / RC4 ============
def _F(b, c, d): return ((b & c) | ((~b) & d)) & 0xffffffff
def _G_(b, c, d): return ((b & d) | (c & (~d))) & 0xffffffff
def _H(b, c, d): return (b ^ c ^ d) & 0xffffffff
def _I(b, c, d): return (c ^ (b | (~d))) & 0xffffffff
def _rol(x, c):
    c %= 32
    return x if c == 0 else ((x << c) | (x >> (32 - c))) & 0xffffffff
def _rf(s):
    return _F if s < 16 else _G_ if s < 32 else _H if s < 48 else _I
def _perm(u, a, b, c, d):
    if u == 0: return (a, b, c, d)
    if u == 1: return (d, a, b, c)
    if u == 2: return (c, d, a, b)
    return (b, c, d, a)


def md5_variant(msg):
    A, B, C, D = IV
    orig = len(msg)
    msg = msg + b'\x80'
    while len(msg) % 64 != 56:
        msg += b'\x00'
    msg += struct.pack('<Q', orig * 8)
    for off in range(0, len(msg), 64):
        M = list(struct.unpack('<16I', msg[off:off + 64]))
        a, b, c, d = A, B, C, D
        for s in range(64):
            f = _rf(s)
            u = UPD[s]
            first, sec, thi, fou = _perm(u, a, b, c, d)
            acc = (first + f(sec, thi, fou) + K[s] + M[G[s]]) & 0xffffffff
            new = (sec + _rol(acc, 32 - ROR[s])) & 0xffffffff
            if u == 0: a = new
            elif u == 1: d = new
            elif u == 2: c = new
            else: b = new
        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff
    return struct.pack('<4I', A, B, C, D)


def hmac_md5(key, msg):
    key = key + b'\x00' * (64 - len(key))
    ip = bytes(x ^ 0x36 for x in key)
    op = bytes(x ^ 0x5c for x in key)
    return md5_variant(op + md5_variant(ip + msg))


def rc4(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) & 0xFF] ^ b)
    return bytes(out)


def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def b64url_dec(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# ============ 白盒 AES：由 hmac + device_id 推导 64 字节 key ============
_key_lock = threading.Lock()


def get_key64(main_hmac, device_id):
    """9.19.2：key = XYAes().main() = generator_result(0x60) = res[16:80]（96字节的中间64字节）。"""
    with _key_lock:
        g = _shield_sdk.GlobalData
        g.build_id = BUILD_ID
        g.device_id = device_id
        g.hmac = main_hmac
        g.xor_byte = list(_shield_sdk.ShieldSdk._XOR_BYTE_DEFAULT)
        g.s_app_id = S_APP_ID
        xy = _shield_sdk.XYAes()
        xy.key_expansion()
        xy.aes_init()
        hmac_hex = bytes.hex(base64.b64decode(main_hmac.encode()))
        res = []
        for i in range(6):
            h1 = hmac_hex[i * 32:(i + 1) * 32]
            out = xy.aes_decrypt(h1)
            for j in range(16):
                res.append(out[j] ^ g.xor_byte[j])
                g.xor_byte[j] = int(h1[j * 2:j * 2 + 2], 16)
        return bytes(res[16:80])


# ============ 设备签名器 ============
class XhsSigner:
    """一台设备的离线签名器（9.19.2 方案，无 main_ssk）。"""

    def __init__(self, device: dict):
        self.did = device['did']                      # x-legacy-did（UUID）
        self.hmac = device['hmac']                    # main_hmac
        self.sid = device.get('sid') or ''            # session.xxx
        if self.sid and not self.sid.startswith('session.'):
            self.sid = 'session.' + self.sid
        self.gid = device.get('gid') or device.get('fingerprint', {}).get('gid', '')
        self.mua0 = device.get('mua0') or ''          # 完整 x-mini-mua
        self.cp_tmpl = device.get('cp') or ''         # 35 字段 xy-common-params
        self.platform_info = device.get('platform_info') or ''
        self.scene = device.get('scene') or ''
        self.user_agent = device.get('user_agent') or ''
        self.proxy = device.get('proxy') or ''   # 可选：设备专属代理 URL

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
        """35 字段 common_params，替换 t= 为当前时间、sid= 为当前会话 sid。"""
        ts = str(int(time.time()))
        sid = self.sid  # 已规范化为 session.xxx（可能为空=未登录）
        parts = self.cp_tmpl.split('&')
        out = []
        for part in parts:
            if part.startswith('t='):
                out.append('t=' + ts)
            elif part.startswith('sid='):
                out.append('sid=' + sid)
            else:
                out.append(part)
        return '&'.join(out)

    # ---- shield（9.19.2 get_shield，无 SSK） ----
    def make_shield(self, path, query, req_body=b''):
        cp = self.get_cp()
        # sign_str 里 did 是 33 位（32 位 + 校验位 '6'），头里是 32 位
        cp_sign = re.sub(r'did=([0-9a-f]{32})', lambda m: 'did=' + m.group(1) + '6', cp)
        # sign_str 末尾必须拼接请求 body 文本（GET/空 body 时为空串）——
        # 9.49.1 的 source 构造同构（path+query+cp+...+scene+body），漏掉 body 会导致写操作 406
        body_text = req_body.decode('utf-8', 'replace') if isinstance(req_body, bytes) else str(req_body)
        sign_str = path + query + cp_sign + self.platform_info + self.scene + body_text
        md5_res = hmac_md5(self.key64, sign_str.encode('utf-8'))
        body = struct.pack('>I', 1)                       # version
        body += struct.pack('>I', S_APP_ID & 0xffffffff)  # s_app_id（big-endian）
        body += struct.pack('>I', 2 if self.hmac else 1)  # flag
        body += struct.pack('>I', len(BUILD_ID))
        body += struct.pack('>I', len(self.did))
        body += struct.pack('>I', 16)
        body += (BUILD_ID + self.did).encode()            # ASCII
        body += md5_res                                   # 16 字节
        encrypted = rc4(body, RC4_KEY)
        return 'XY' + base64.b64encode(SHIELD_HDR + encrypted).decode()

    # ---- 完整请求头 ----
    def sign(self, method, url, body=b''):
        """对任意 URL 生成完整请求头（完全离线，9.19.2）。

        method: GET / POST；body: bytes（同时参与 shield sign_str 和 canonical 的 sha256）
        """
        p = urlsplit(url)
        path, query = p.path, p.query
        cp = self.get_cp()
        new_mua, counter = self.next_mua()

        shield = self.make_shield(path, query, body)

        canon = canonical_str(method, path, query, body if isinstance(body, bytes) else b'', new_mua)
        sig = compute_sig(canon)
        ts = int(time.time())
        perm8 = make_perm8_zero(ts)   # ★ 真算法；perm4 仍恒等（未破解，服务端不校验）
        perm4 = list(range(4))
        s1 = make_s1(canon.encode(), counter, ts, perm8, perm4)

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
            'x-mini-s1': s1,
            'x-mini-sig': sig,
            'x-xray-traceid': ''.join(random.choice('0123456789abcdef') for _ in range(32)),
            'xy-common-params': cp,
            'xy-direction': '6',
            'xy-platform-info': self.platform_info,
            'xy-scene': self.scene,
        }
        return hdrs

    def sign_preview(self, path, method='GET', body=None):
        body_bytes = b''
        if isinstance(body, dict):
            body_bytes = json.dumps(body, separators=(',', ':')).encode('utf-8')
        elif isinstance(body, str):
            body_bytes = body.encode('utf-8')
        elif isinstance(body, bytes):
            body_bytes = body
        url = UPSTREAM_BASE + path
        headers = self.sign(method, url, body_bytes)
        return {'path': path, 'method': method, 'headers': headers}

    # ---- 取数 ----
    def make_session(self):
        import tls_client
        order = ['referer', 'shield', 'user-agent', 'x-b3-traceid', 'x-legacy-did',
                 'x-legacy-fid', 'x-legacy-sid', 'x-mini-gid', 'x-mini-mua', 'x-mini-s1',
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
            # 设备专属代理（http://user:pass@host:port 或 socks5://host:port）
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


# ============ 签名反解（跨版本一致） ============
# 逆向调试工具：当前无生产调用方，保留供人工排查签名材料 / 后续接 /api/reverse 用
def decode_mua(value: str):
    """反解 x-mini-mua 头部：返回头部 JSON 字段（含 s/u = mua_s/mua_u）。"""
    parts = value.split('.')
    if not parts:
        return None
    try:
        head = json.loads(b64url_dec(parts[0]))
    except Exception:
        return None
    result = {
        'kind': 'x-mini-mua',
        'detail': head,
        'note': '头部 base64url JSON 已解出。后半段为 ECDH 协商密钥加密载荷，'
                '头里只有临时公钥无对应私钥，第三方无法解出。',
    }
    if 's' in head:
        result['detail']['mua_s'] = head['s']
    if 'u' in head:
        result['detail']['mua_u'] = head['u']
    if 'c' in head:
        result['detail']['counter'] = head['c']
    return result


# 逆向调试工具：当前无生产调用方，保留供人工排查 cp / platform_info 字段
def decode_query(value: str):
    """反解 xy-common-params / xy-platform-info 为键值对（保持原顺序）。"""
    items = []
    for pair in value.split('&'):
        if not pair:
            continue
        if '=' in pair:
            k, v = pair.split('=', 1)
            try:
                from urllib.parse import unquote
                v = unquote(v)
            except Exception:
                pass
            items.append({'key': k, 'value': v})
        else:
            items.append({'key': pair, 'value': ''})
    return {'kind': 'query', 'detail': items, 'note': '已按原顺序拆分为键值对（顺序本身参与签名）。'}
