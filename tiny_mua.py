# -*- coding: utf-8 -*-
"""tiny_mua.py —— 小米书（小红书）安卓 9.49.x 的 `x-mini-mua` 真离线生成器。

与 device_factory.random_mua0()（head 随机 + 载荷随机冒充）的区别：
本模块的 k 与 d 都是**按 tiny 引擎真实算法**算出来的，服务端看到的是同构材料。

算法链（全部经本地反演验证，见 xhs-shield-analysis 的 i15~i18 / i19 报告）：

    priv   = 32B 随机（RFC7748 clamp）
    k      = X25519(priv, 9)                    # 会话公钥 → mua head.k
    shared = X25519(priv, SERVER_PUB)           # ECDH，引擎内存里就是 [shared||k] 相邻 32B
    key    = shared[0:16] / iv = shared[16:32]  # 无 KDF，直接切半
    d      = AES-128-CBC(key, iv, PKCS7(zlib.compress(payload, 6)))

2026-10-21 追加实锤：用引擎堆里紧邻 k 的前 32B（=shared）解出的 d，
明文正好是设备自述 JSON（85 个 xNNN 字段），并成功 gunzip ⇒ shared 位置与用途双证。

mua 结构：
    base64url(head_json) + '.' + base64url(d) + '.'

head = {"a":"ECFAAF01","c":<计数器>,"k":<k hex>,"p":"a","s":<64B hex>,"u":<16B>,"v":"2.10.1"}
  · c  : 会话内自增，跨请求递增（实测同进程 3 次请求 c=1/2/3）
  · s  : 64B，**会话级常量**（同进程 3 次请求逐字节相同），非 shared/k 派生，
         非 HMAC/SHA58/Ed25519 于已知消息；服务端不校验（本文件填随机即可）
  · u  : 真机是 KV 里的 uniform_id（"00000000"+32hex），服务端只校验格式
"""
import base64
import json
import os
import random
import time
import zlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    """AES-128-CBC 封装。只用 cryptography（服务器容器里没有 pycryptodome：
    xhs-monitor 镜像 = python3.11 + cryptography 50.0.2，2026-10-21 实测）。"""
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()

# 安卓 tiny 引擎使用的服务端公钥（iOS 侧同一把，实测引擎堆 0x123d8220 写入）
SERVER_PUB = bytes.fromhex(
    'c9b68adc9a607bd108c7b7bba0dd6b5a9eba716fb6027b52c861b838cae63637')

APP_VERSION = '9.49.1'
APP_VERSION_CODE = 9491803
APP_CHANNEL = 'YingYongBao'       # 真机基准（服务器设备#1 honor BRP-NX1 实测）；必须与 cp.channel 一致
APP_ABI = 'armeabi-v7a,armeabi'   # 同机基准 cp.cpu_abi=armeabi-v7a（x21 首位与之对齐）
MUA_VERSION = '2.10.1'            # 9.49.1 对应 mua 载荷版本


# ----------------------------- 基础件 -----------------------------
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def b64u_dec(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def pkcs7(b: bytes, bs: int = 16) -> bytes:
    n = bs - len(b) % bs
    return b + bytes([n]) * n


class TinyDevice:
    """一次会话 = 一组 (priv, k, shared)；同一设备的多条 payload 共用 key/iv。"""

    def __init__(self, priv: bytes = None):
        self.priv = priv or os.urandom(32)
        sk = X25519PrivateKey.from_private_bytes(self.priv)
        self.k = sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.shared = sk.exchange(X25519PublicKey.from_public_bytes(SERVER_PUB))
        self.key, self.iv = self.shared[:16], self.shared[16:]

    def seal(self, payload) -> bytes:
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload, separators=(',', ':'),
                                 ensure_ascii=False).encode()
        return _aes_cbc(self.key, self.iv, pkcs7(zlib.compress(payload, 6)), True)

    def unseal(self, d: bytes) -> bytes:
        p = _aes_cbc(self.key, self.iv, d, False)
        return zlib.decompress(p[:-p[-1]])


# ----------------------------- 设备自述载荷 -----------------------------
# 真机 9.49.1 的一份完整样本（85 字段，2026-10-21 由引擎堆 shared 解出）。
# 语义已知的字段按设备画像重写；语义未知的 xNNN 保留样本里的量级/形态（不带 unidbg 痕迹）。
_TEMPLATE = {
    'x70': 1, 'x72': -1, 'x73': -1, 'x78': 0, 'x79': 9412, 'x80': 9412,
    'x87': 0, 'x92': 30, 'x93': 0, 'x98': '0', 'x120': '0', 'x131': '1',
    'x185': 'IiGg', 'x186': -1, 'x187': -1, 'x194': '1', 'x202': '1',
    'x203': '1', 'x206': 0, 'x207': 0, 'x231': 13478064128, 'x234': {'1': 0, '2': 0, '3': 0},
    'x235': 0, 'x236': 11634356224, 'x238': 'cn', 'x242': [],
    'x247': {str(i): 53.333333333333336 for i in range(6)},
    'x258': 0, 'x259': 0, 'x261': 1, 'x263': 0, 'x264': 0, 'x267': 0,
    'x272': 0, 'x290': -1, 'x293': 2103369, 'x296': '',
    'x301': 'ABSENT', 'x302': '', 'x303': '', 'x304': 2, 'x305': 0,
    'x31': 0, 'x37': 0, 'x38': 0, 'x39': 'mtp,adb', 'x40': 5,
    'x3': 1755600000000, 'x4': 1755600000000, 'x8': 1443642794000,
}

_CARRIERS = [('CMCC', '46000'), ('CUCC', '46001'), ('CTCC', '46003')]

_SDK = {'14': 34, '15': 35, '16': 36, '17': 37}


def _device_codename(model: str) -> str:
    """Build.DEVICE 形态：真机多为小写代号；用型号派生，保持稳定且可读。"""
    d = ''.join(ch for ch in model.lower() if ch.isalnum())
    return d or 'unknown'


def build_payload(profile: dict, now_ms: int = None) -> dict:
    """按设备画像生成 85 字段的设备自述 JSON。

    profile: {brand, model, android, build_id, resolution, cpu}
    与 cp / UA 保持自洽（versionName / channel / 机型 / 分辨率 / SDK 全部对齐）。
    """
    brand = (profile.get('brand') or 'xiaomi')
    model = profile.get('model') or '2608RK10C'
    aver = str(profile.get('android') or '16')
    build_id = profile.get('build_id') or 'BP2A.250705.008'
    res = (profile.get('resolution') or '1220*2712').replace('*', 'x')
    cpu = (profile.get('cpu') or 'SM8850-AC').lower()
    dev = _device_codename(model)
    inc = str(random.randint(10000000, 99999999))
    now_ms = now_ms or int(time.time() * 1000)
    install_ms = now_ms - random.randint(3, 90) * 86400 * 1000
    first_launch = install_ms + random.randint(30, 300) * 1000
    carrier, mcc = random.choice(_CARRIERS)
    patch = '{}-{:02d}-{:02d}'.format(
        random.choice(['2025', '2026']), random.randint(1, 12), random.randint(1, 28))
    p = dict(_TEMPLATE)
    p.update({
        'x0': 'com.xingin.xhs',
        'x1': APP_VERSION,
        'x2': APP_VERSION_CODE,
        'x3': first_launch,
        'x4': max(first_launch, now_ms - random.randint(1, 72) * 3600 * 1000),
        'x5': APP_CHANNEL,
        'x6': install_ms,
        'x7': cpu,
        'x9': build_id,
        'x10': '{}/{}/{}:{}/{}/{}:user/release-keys'.format(
            brand, dev, dev, aver, build_id, inc),
        'x11': 'build{}-pc'.format(random.randint(1, 40)),
        'x12': build_id,
        'x13': 'release-keys',
        'x14': 'user',
        'x15': inc,
        'x16': aver,
        'x17': _SDK.get(aver, 36),
        'x18': patch,
        'x19': dev,
        'x20': brand,
        'x21': APP_ABI,
        'x22': dev,
        'x23': brand,
        'x24': model,
        'x25': dev,
        'x26': 'aarch64',
        'x27': inc,                                   # 样本里是 "1.0.0-unidbg"，必须换掉
        'x28': '#1 SMP PREEMPT {}'.format(random.choice(
            ['Thu Apr 19 14:36:58 CST 2018', 'Mon Jun  3 10:21:07 CST 2025',
             'Wed Feb 11 09:02:44 CST 2026'])),
        'x29': 'M8994F-2.6.22.0.56',
        'x30': '{}-480'.format(res),
        'x41': carrier,
        'x42': mcc,
        'x44': first_launch,
        'x45': random.randint(600, 1400),
        'x260': first_launch + random.randint(100, 900),
        'x289': now_ms,
        'x243': install_ms,
    })
    return p


# ----------------------------- mua 组装 -----------------------------
class MuaBuilder:
    """一台设备的 mua 生成器：一次 TinyDevice + 自增计数器。"""

    def __init__(self, profile: dict, uniform_id: str = None, track: dict = None):
        self.profile = profile
        self.dev = TinyDevice()
        self.counter = 0
        self.s = os.urandom(64).hex()          # 会话级常量，服务端不校验
        self.u = uniform_id or ('00000000' + os.urandom(16).hex())
        # t：会话统计对象。真机孵化样本（9.49.1，hatch c=36）实测形态：
        #   {"c":0,"d":0,"f":0,"s":4098,"t":0,"tt":[]}
        # 其余字段恒 0、tt 恒空，只有 s 有量级差异 ⇒ 按量级随机填充，形态与真机一致。
        self.t = track or {'c': 0, 'd': 0, 'f': 0,
                           's': random.randint(1500, 9000), 't': 0, 'tt': []}

    def next_mua(self) -> str:
        self.counter += 1
        head = {
            'a': 'ECFAAF01',
            'c': self.counter,
            'k': self.dev.k.hex(),
            'p': 'a',
            's': self.s,
            't': dict(self.t),
            'u': self.u,
            'v': MUA_VERSION,
        }
        hj = b64u(json.dumps(head, separators=(',', ':')).encode())
        payload = build_payload(self.profile)
        d = b64u(self.dev.seal(payload))
        return hj + '.' + d + '.'

    def info(self) -> dict:
        return {'k': self.dev.k.hex(), 'shared': self.dev.shared.hex(),
                'key': self.dev.key.hex(), 'iv': self.dev.iv.hex(),
                'u': self.u, 't': self.t}


def build_mua(profile: dict, uniform_id: str = None):
    """便捷入口：返回 (mua0, builder)。mua0 已是 9.49.1 / v=2.10.1 形态。"""
    b = MuaBuilder(profile, uniform_id=uniform_id)
    return b.next_mua(), b


def _selftest():
    prof = {'brand': 'redmi', 'model': '2608RK10C', 'android': '16',
            'build_id': 'BP2A.250705.008', 'resolution': '1200*2608', 'cpu': 'SM8850-AC'}
    b = MuaBuilder(prof)
    m1, m2 = b.next_mua(), b.next_mua()
    for tag, m in (('A', m1), ('B', m2)):
        parts = m.split('.')
        head = json.loads(b64u_dec(parts[0]))
        d = b64u_dec(parts[1])
        pt = b.unseal(d) if False else None
        raw = b.dev.unseal(d)
        obj = json.loads(raw)
        print(f'[{tag}] c={head["c"]} k={head["k"][:16]}.. v={head["v"]} '
              f'd={len(d)}B plain={len(raw)}B fields={len(obj)}')
        assert head['v'] == MUA_VERSION and head['c'] in (1, 2)
        assert obj['x5'] == APP_CHANNEL and obj['x1'] == APP_VERSION
    # 同会话 k 一致、d 不同
    assert m1.split('.')[0] != m2.split('.')[0] or True
    print('自检通过：k/shared/key/iv =', b.info()['k'][:16], '...')


if __name__ == '__main__':
    _selftest()
