# -*- coding: utf-8 -*-
"""
xhs_perm.py —— 小红书 s1 里 perm8 的纯 Python 实现（2026-10-25 完整破解）

## 结论

```
seed = ts                       # 只需时间戳（秒），与 URL / query / 设备无关
rng  = bionic random()          # Android libc 的 TYPE_3，31 状态
       ├ state[0] = seed
       ├ state[i] = Schrage(state[i-1])   i = 1..30
       ├ fptr = &state[3], rptr = &state[0]     （滞后 3）
       ├ 预热 310 次
       └ next(): state[f] = (state[f] + state[r]) mod 2^32
                 return (state[f] >> 1) & 0x7FFFFFFF

Q  = [2,4,1,6,7,3,8,5]          # 编译期常量初值

a = Q[:]
for i = 7 downto 1:
    j = rng.next() % (i + 1)
    swap(a[i], a[j])

perm8 = a                       # 1..8 的排列
```

编码成落点字节（enc_seq）：每字节 = `10*A + B`，A、B 是排列里相邻两个数（都 ∈ [1,8] 且 A≠B）。

```
perm8 = [8,7,4,2,1,3,6,5]  ->  (8,7)(4,2)(1,3)(6,5) -> 57 2a 0d 41
```

## 验证

- 171 / 171 个不同 ts 的 perm8 全部逐字节匹配（样本来自 unidbg 引擎实测）
- 7 个中间 rand 值也与引擎内部 `V[29]` 完全一致：
  `1926494335, 714061148, 1966297289, 88613952, 391208084, 2093349217, 645893873`

## 用法

```python
from xhs_perm import make_perm8, make_perm8_bytes, bionic_random_seq

make_perm8(1792754000)        # [8,7,4,2,1,3,6,5]   1-based（enc_seq 用）
make_perm8_zero(1792754000)   # [7,6,3,1,0,2,5,4]   0-based（lane32 索引用）
make_perm8_bytes(1792754000)  # b'\\x57\\x2a\\x0d\\x41'
bionic_random_seq(1792754000, 7)   # 引擎内部用的 7 个原始随机数
```
"""

DEG = 31
SEP = 3
WARMUP = 310

# 写 perm 前先填进数组的固定初值（编译期常量，3 个不同 ts 逐字节相同）
Q = [2, 4, 1, 6, 7, 3, 8, 5]


class BionicRandom:
    """Android bionic 的 random()（TYPE_3 / 31 状态 / 输出 31 位）。"""

    __slots__ = ('st', 'f', 'r')

    def __init__(self, seed, warmup=WARMUP):
        st = [0] * (DEG + 1)          # 索引 1..31 有效，0 不用（bionic 是 randtbl[DEG+1]）
        st[1] = (seed & 0xFFFFFFFF) or 1
        for i in range(2, DEG + 1):
            prev = st[i - 1]
            hi = prev // 127773
            lo = prev % 127773
            w = 16807 * lo - 2836 * hi
            if w < 0:
                w += 2147483647
            st[i] = w & 0xFFFFFFFF
        self.st = st
        self.f = 1 + SEP
        self.r = 1
        for _ in range(warmup):
            self.next()

    def next(self):
        st = self.st
        v = (st[self.f] + st[self.r]) & 0xFFFFFFFF
        st[self.f] = v
        out = (v >> 1) & 0x7FFFFFFF
        self.f = self.f + 1 if self.f < DEG else 1
        self.r = self.r + 1 if self.r < DEG else 1
        return out


def bionic_random_seq(seed, n):
    rng = BionicRandom(seed)
    return [rng.next() for _ in range(n)]


def make_perm8(ts):
    """由 ts（秒）生成 perm8（1..8 的排列）"""
    rng = BionicRandom(ts)
    a = Q[:]
    for i in range(7, 0, -1):
        j = rng.next() % (i + 1)
        a[i], a[j] = a[j], a[i]
    return a


def encode_perm(p):
    """排列 -> enc_seq 字节（每字节 = 10*A + B，A/B 为相邻两个数）"""
    if len(p) % 2 != 0:
        raise ValueError('排列长度必须是偶数')
    out = bytearray()
    for k in range(0, len(p), 2):
        a, b = p[k], p[k + 1]
        if not (1 <= a <= 9 and 1 <= b <= 9):
            raise ValueError('元素必须在 1..9')
        out.append(a * 10 + b)
    return bytes(out)


def decode_perm(raw):
    """enc_seq 字节 -> 排列"""
    out = []
    for byte in raw:
        a, b = byte // 10, byte % 10
        if not (1 <= a <= 9 and 1 <= b <= 9):
            raise ValueError('非法字节 0x%02x' % byte)
        out += [a, b]
    return out


def make_perm8_bytes(ts):
    return encode_perm(make_perm8(ts))


def make_perm8_zero(ts):
    """0-based 版本（给 lane32 那种「按索引取 4 字节」的地方用）"""
    return [x - 1 for x in make_perm8(ts)]


# perm4 的编译期常量初值（与 perm8 的 Q 同源独立；2026-10-26 由 363/363 样本反推确定）
Q4 = [2, 1, 3, 4]


def make_perm4(ts):
    """由 ts 生成 perm4（1..4 的排列）—— 2026-10-26 完全破解。

    与 perm8 完全同构（倒序 Fisher-Yates），唯一差别是：
      ★ **独立新建 rng**（offset=0），不续用 perm8 已消耗的 7 个随机数。

    即 perm8 与 perm4 各用一颗同种子(ts)的新 rng，perm4 取 r[0..2]（模 4/3/2）。

    验证：**363 / 363** —— 9.19.2（320 条）+ 9.49.1 真实请求头（43 条），
    共 37 个不同 ts，seed44[42:44] 逐字节一致；端到端重建整条 s1 也 320/320。
    """
    rng = BionicRandom(ts)
    a = Q4[:]
    for i in range(3, 0, -1):
        j = rng.next() % (i + 1)
        a[i], a[j] = a[j], a[i]
    return a


def make_perm4_zero(ts):
    """0-based 版本（make_s1 里的 perm4 参数用这个）"""
    return [x - 1 for x in make_perm4(ts)]


# ---------------- 自检 ----------------
def _self_test():
    cases = [
        (1792754000, [8, 7, 4, 2, 1, 3, 6, 5], '572a0d41'),
        (1000000000, [8, 2, 3, 7, 1, 4, 5, 6], '52250e38'),
        (1700000000, [6, 4, 8, 3, 7, 2, 1, 5], '4053480f'),
    ]
    ok = True
    for ts, want_perm, want_hex in cases:
        p = make_perm8(ts)
        h = make_perm8_bytes(ts).hex()
        hit = (p == want_perm and h == want_hex)
        ok &= hit
        print('  ts=%-12d perm=%-26s hex=%s  %s' % (ts, p, h, 'OK' if hit else 'FAIL'))
    # 中间 rand 值
    vals = bionic_random_seq(1792754000, 7)
    want = [1926494335, 714061148, 1966297289, 88613952, 391208084, 2093349217, 645893873]
    print('  rand7 %s' % ('OK' if vals == want else 'FAIL'))
    ok &= (vals == want)
    return ok


if __name__ == '__main__':
    print('=== xhs_perm 自检 ===')
    allok = _self_test()
    print('\n结果:', 'ALL PASS' if allok else 'FAILED')
