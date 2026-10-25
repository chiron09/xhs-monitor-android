# -*- coding: utf-8 -*-
"""
小红书 x-mini-mua / x-mini-sig / x-mini-s1 离线签名算法实现
框架参考第三方逆向记录（9.43.1），常量需与当前版本（9.19.2）对齐验证。
"""
import hashlib, struct, base64, zlib, json

# ===================== 通用 =====================
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

# ===================== X25519 =====================
P = 2**255 - 19

def clamp(k: bytes) -> bytes:
    k = bytearray(k)
    k[0] &= 0xF8
    k[31] = (k[31] & 0x7F) | 0x40
    return bytes(k)

def x25519(scalar: bytes, u: bytes) -> bytes:
    k = int.from_bytes(clamp(scalar), 'little')
    x1 = int.from_bytes(u, 'little') & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) ** 2) % P
        z3 = ((da - cb) ** 2 * x1) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + 121665 * e)) % P
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
    return ((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, 'little')

# ===================== AES / GF(2^8) =====================
def gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return r

def gf_inv(x):
    if x == 0:
        return 0
    for y in range(1, 256):
        if gf_mul(x, y) == 1:
            return y
    raise ValueError

def rotl8(v, n):
    return ((v << n) | (v >> (8 - n))) & 0xFF

SBOX = bytes(gf_inv(x) ^ rotl8(gf_inv(x), 1) ^ rotl8(gf_inv(x), 2)
             ^ rotl8(gf_inv(x), 3) ^ rotl8(gf_inv(x), 4) ^ 0x63 for x in range(256))

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
INV_SBOX = bytes(INV_SBOX)

# ===================== S1 =====================
def crc_state(data):
    s = 0xFFFFFFFF
    for v in data:
        s ^= v
        for _ in range(8):
            s = (s >> 1) ^ 0xEDB88320 if s & 1 else s >> 1
    return s

def crc32_(data):
    return crc_state(data) ^ 0xFFFFFFFF

def ns(data):
    """nibble swap"""
    return bytes((v >> 4) | ((v & 0x0F) << 4) for v in data)

WORD_ORDER = (7, 0, 2, 5, 6, 3, 1, 4)
LANE3 = (0xB, 0x2, 0xF, 0x6, 0x8, 0x9, 0xE, 0x3, 0x1, 0xD, 0x7, 0x5, 0xC, 0xA, 0x0, 0x4)
ROUND_KEYS = tuple(bytes.fromhex(h) for h in (
    "786873306f6832697534616e376f6732", "5a3241711e764471e0d4fb95096b0c3e",
    "43713041275115398f5bfa6ff3c8c4fa", "1e6f5f1e27766300174cf798864b8f75",
    "ed82ddc30e781b293c70b32b4539b6c3", "52d00dce760e1578cabaddf62717a162",
    "2bfbf638faf4e18c2d9711e7789c3d5f", "93689ea6fe0aeb0467f0ad4a819ba6f9",
    "fa920caa767c97888c7ca1eb61bf19e0"))
FINAL_A = bytes.fromhex("69fbf75dee92059829554ea58b130aea")
FINAL_C = bytes.fromhex("34cf3865648a181d73d6ffaa5f55bf34")
CBC_IV = bytes.fromhex("6e2052fb01f05fd238ad54534bd00831")

def digest_lane(canonical: bytes, counter: int) -> bytes:
    digest = hashlib.sha256(canonical + struct.pack('<I', counter)).digest()
    state = b''.join(digest[i*4:i*4+4] for i in WORD_ORDER)
    b0, b1, b2, b3 = state[0:8], state[8:16], state[16:24], state[24:32]
    s = ns(b0)
    lane0 = bytes(v ^ (crc_state(s) & 0xFF) for v in s)
    cn = ((b1[0] << 4) | (b1[7] >> 4)) ^ ((b1[6] << 4) | (b1[1] >> 4))
    lane1 = bytes(v if i in (3, 5) else ns(bytes((v,)))[0]
                  for i, v in enumerate(bytes(v ^ (cn & 0xFF) for v in b1)))
    sub = bytes(t for v in b2 for t in (LANE3[v >> 4], LANE3[v & 0x0F]))
    lane2 = bytes(v ^ (crc_state(sub) & 0xFF) for v in b2)
    first = b3[0] ^ 0xAE
    c0 = ns(bytes((first,)))[0]
    second = b3[1] ^ c0 ^ 0xAE
    c1 = ns(bytes((second,)))[0]
    mask = c0 ^ c1 ^ 0xAE
    lane3 = bytes((c0 ^ c1 ^ first, c1 ^ second, *(v ^ mask for v in b3[2:])))
    return lane0 + lane1 + lane2 + lane3

def transpose(s):
    return bytes(s[r*4+c] for c in range(4) for r in range(4))

def shift_rows(s):
    return b''.join(s[r*4+r:r*4+4] + s[r*4:r*4+r] for r in range(4))

def inv_shift_rows(s):
    return b''.join(s[r*4+4-r:r*4+4] + s[r*4:r*4+4-r] for r in range(4))

def mix_columns(s):
    t = transpose(s)
    out = bytearray()
    for off in range(0, 16, 4):
        a, b, c, d = t[off:off+4]
        out += bytes((gf_mul(a,2)^gf_mul(b,3)^c^d, a^gf_mul(b,2)^gf_mul(c,3)^d,
                      a^b^gf_mul(c,2)^gf_mul(d,3), gf_mul(a,3)^b^c^gf_mul(d,2)))
    return transpose(bytes(out))

def inv_mix_columns(s):
    t = transpose(s)
    out = bytearray()
    for off in range(0, 16, 4):
        a, b, c, d = t[off:off+4]
        out += bytes((gf_mul(a,14)^gf_mul(b,11)^gf_mul(c,13)^gf_mul(d,9),
                      gf_mul(a,9)^gf_mul(b,14)^gf_mul(c,11)^gf_mul(d,13),
                      gf_mul(a,13)^gf_mul(b,9)^gf_mul(c,14)^gf_mul(d,11),
                      gf_mul(a,11)^gf_mul(b,13)^gf_mul(c,9)^gf_mul(d,14)))
    return transpose(bytes(out))

def s1_block(block):
    s = shift_rows(transpose(block))
    for rk in ROUND_KEYS:
        s = bytes(SBOX[v ^ m] for v, m in zip(s, rk))
        s = shift_rows(mix_columns(s))
    s = bytes(SBOX[v ^ a] ^ c for v, a, c in zip(s, FINAL_A, FINAL_C))
    return transpose(s)

def s1_block_inv(block):
    s = transpose(block)
    s = bytes(INV_SBOX[v ^ a] ^ c for v, a, c in zip(s, FINAL_C, FINAL_A))
    for rk in reversed(ROUND_KEYS):
        s = inv_mix_columns(inv_shift_rows(s))
        s = bytes(INV_SBOX[v] ^ m for v, m in zip(s, rk))
    s = transpose(inv_shift_rows(s))
    return s

def s1_cbc(payload):
    prev, out = CBC_IV, bytearray()
    for off in range(0, len(payload), 16):
        prev = s1_block(bytes(x ^ y for x, y in zip(payload[off:off+16], prev)))
        out += prev
    return bytes(out)

def s1_cbc_inv(cipher):
    prev, out = CBC_IV, bytearray()
    for off in range(0, len(cipher), 16):
        blk = cipher[off:off+16]
        out += bytes(x ^ y for x, y in zip(s1_block_inv(blk), prev))
        prev = blk
    return bytes(out)

def build_s1_raw(canonical: bytes, counter: int, timestamp_s: int) -> bytes:
    lane = digest_lane(canonical, counter)
    seed = (struct.pack('<I', timestamp_s) + bytes.fromhex('51244a19')
            + b'\x00\x00' + lane + bytes.fromhex('170e'))
    source = b'\x01' + s1_cbc(seed + b'\x04' * 4) + crc32_(seed).to_bytes(4, 'big')
    return (b'\x00' + struct.pack('<I', counter) + source
            + crc32_(source).to_bytes(4, 'big'))

def build_s1(canonical: bytes, counter: int, timestamp_s: int) -> str:
    return base64.b64encode(build_s1_raw(canonical, counter, timestamp_s)).decode()

# ===================== canonical / SIG =====================
def canonical(method: str, path: str, query: str, body: bytes, mua: str) -> bytes:
    return (f'{method}\n{path}\n{query}\n'
            f'{hashlib.sha256(body).hexdigest()}\n{mua}').encode('utf-8')

# SIG 仿射矩阵（附录 A，待从当前版本提取；先占位）
def gf2_apply(digest16: bytes, rows) -> bytes:
    v = int.from_bytes(digest16, 'big') | (1 << 128)
    out = bytearray(16)
    for i, row in enumerate(rows):
        bit = 0
        for j, c in enumerate(row):
            if c:
                bit ^= (v >> j) & 1
        if bit:
            out[i // 8] |= 1 << (7 - i % 8)
    return bytes(out)
