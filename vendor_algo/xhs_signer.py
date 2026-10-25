# -*- coding: utf-8 -*-
"""小红书 x-mini 签名体系完全离线实现（9.19.2）
已破解并 100% 验证：canonical + SIG + S1。
MUA 作为输入（会话材料复用捕获值，X25519 服务端公钥待最终确认）。

用法：
    from xhs_signer import canonical_str, compute_sig, make_s1
    canon = canonical_str('GET', '/api/sns/v6/homefeed', 'oid=...', b'', mua)
    sig = compute_sig(canon)
    s1 = make_s1(canon.encode(), counter, ts, perm8, perm4)
"""
import json, hashlib, struct, base64
from mini_alg import crc_state, ns, LANE3, s1_cbc

# ============ SIG 矩阵 ============
_sig = json.load(open('sig_final.json'))
_SIG_CONST = _sig['const']
_SIG_COEF = _sig['coef']  # 128 个

def _gf2_apply(digest16):
    v = int.from_bytes(digest16, 'big') | (1 << 128)
    y = _SIG_CONST
    for j in range(128):
        if (v >> j) & 1:
            y ^= _SIG_COEF[j]
    return y.to_bytes(16, 'big')

def canonical_str(method, path, query, body, mua):
    return f'{method}\n{path}\n{query}\n{hashlib.sha256(body).hexdigest()}\n{mua}'

def compute_sig(canon):
    """canon: str 或 bytes"""
    if isinstance(canon, str):
        canon = canon.encode()
    d = hashlib.sha256(canon).digest()
    return (_gf2_apply(d[:16]) + d[16:]).hex()

# ============ S1 ============
def dec_seq(m):
    nums = []
    for b in m:
        nums.append(b // 10); nums.append(b % 10)
    return [x - 1 for x in nums]

def enc_seq(seq):
    s = [x + 1 for x in seq]
    return bytes(s[i]*10 + s[i+1] for i in range(0, len(s), 2))

def lane_ident_crc(b):
    mask = crc_state(bytes(t for v in b for t in (LANE3[v >> 4], LANE3[v & 0xF]))) & 0xFF
    return bytes(v ^ mask for v in b)

def lane_ns_crc(b):
    s = ns(b)
    return bytes(v ^ (crc_state(s) & 0xFF) for v in s)

def lane_mixed(b):
    mix = ((b[0] << 4) | (b[7] >> 4)) ^ ((b[6] << 4) | (b[1] >> 4))
    a = bytes(v ^ (mix & 0xFF) for v in b)
    return bytes(a[i] if i in (3, 5) else ns(bytes([a[i]]))[0] for i in range(8))

def lane_ae(b):
    C = 0xAE
    first = b[0] ^ C; c0 = ns(bytes([first]))[0]
    second = b[1] ^ c0 ^ C; c1 = ns(bytes([second]))[0]
    mask = c0 ^ c1 ^ C
    return bytes([c0 ^ c1 ^ first, c1 ^ second]) + bytes(v ^ mask for v in b[2:])

_T = {0: lane_ident_crc, 1: lane_ns_crc, 2: lane_mixed, 3: lane_ae}

def make_lane32(digest, perm8, perm4):
    state = b''.join(digest[i*4:i*4+4] for i in perm8)
    b = [state[0:8], state[8:16], state[16:24], state[24:32]]
    return b''.join(_T[perm4[k]](b[k]) for k in range(4))

def make_s1(canonical, counter, ts, perm8, perm4):
    """canonical: bytes"""
    digest = hashlib.sha256(canonical + struct.pack('<I', counter)).digest()
    lane32 = make_lane32(digest, perm8, perm4)
    seed44 = struct.pack('<I', ts) + enc_seq(perm8) + b'\x00\x00' + lane32 + enc_seq(perm4)
    body48 = s1_cbc(seed44 + b'\x04'*4)
    crc_seed = (crc_state(seed44) ^ 0xFFFFFFFF).to_bytes(4, 'big')
    source53 = b'\x01' + body48 + crc_seed
    crc_src = (crc_state(source53) ^ 0xFFFFFFFF).to_bytes(4, 'big')
    return base64.b64encode(b'\x00' + struct.pack('<I', counter) + source53 + crc_src).decode()

if __name__ == '__main__':
    # 自检：用 samples.json 验证
    samples = json.load(open('samples.json'))
    ok_sig = ok_s1 = 0
    for s in samples:
        canon = canonical_str(s['method'], s['path'], s['query'], b'', s['x-mini-mua'])
        if compute_sig(canon) == s['x-mini-sig']:
            ok_sig += 1
        raw62 = base64.b64decode(s['x-mini-s1'])
        from mini_alg import s1_cbc_inv
        seed44 = s1_cbc_inv(raw62[6:54])[:44]
        counter = struct.unpack('<I', raw62[1:5])[0]
        ts = struct.unpack('<I', seed44[0:4])[0]
        if make_s1(canon.encode(), counter, ts, dec_seq(seed44[4:8]), dec_seq(seed44[42:44])) == s['x-mini-s1']:
            ok_s1 += 1
    print(f'SIG {ok_sig}/{len(samples)}, S1 {ok_s1}/{len(samples)}')
