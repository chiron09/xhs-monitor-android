# -*- coding: utf-8 -*-
"""xhs_assets.py —— 逆向资产只读查询（2026-10-26）

数据全部来自对 9.51.0 APK 全部 22 个 dex 的全量静态提取，以及 libtiny 命令号分析：

    data/reverse/api_paths.txt   1644 条小红书接口 path
    data/reverse/headers.txt     124 个请求头名
    data/reverse/cmd_ids.json     62 个 libtiny 命令号（t.a / k3.a / k3.b / k3.c 族）

设计约束：
  · **只读**，不写任何文件、不改抓取逻辑
  · **无外部依赖**（不用 pandas / requests）
  · 数据缺失时返回空集，不抛异常——不允许因为资产文件没同步把服务带崩
  · 数据可热替换：改 data/reverse/ 下的文件后调 reload() 即可，不用重启

用法：
    from xhs_assets import assets
    assets.summary()                 # 总量 + 业务族分布 + 吃额度接口数
    assets.classify('/api/sns/v6/homefeed')   # '内容详情'
    assets.quota_kind(path)          # 'feed' / 'search' / 'detail' / 'posted' / 'normal'
    assets.cmd('sign')               # {'hex':..., 'dec':100529502, ...}
"""
import json
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))

# 业务族归类：靠关键字，顺序即优先级（先命中者胜）
_FAMILIES = [
    # 注意 '/post/' 带尾斜杠：写成 '/post' 会把读接口 v4/note/user/posted 误判成
    # 「发布/写入」（posted 是用户发布列表，属读操作）。
    ('发布/写入', ('/create', '/publish', '/post/', '/upload', '/draft')),
    ('IM/消息', ('/im/', 'message', '/chat', 'session/')),
    ('直播', ('live',)),
    ('电商/商城', ('mall', 'store', 'goods', 'order', 'cart', 'jpd', 'sku')),
    ('广告/增长', ('splash', 'growth', 'promotion', '/ad/', 'advert')),
    ('红包/营销', ('redpacket', 'coupon', 'wallet', '/red')),
    ('搜索', ('/api/search/',)),
    ('内容详情', ('note', 'feed', 'detail', 'search', 'topics', 'collection')),
    ('用户/关系', ('user', 'follow', 'relation', 'fans', 'contact')),
    ('系统/设备/配置', ('system', 'device', 'config', 'launch', 'setting', 'abtest', 'track')),
    ('客服', ('kefu', 'customer', 'feedback')),
    ('推送', ('push', 'notify')),
]

# 吃内容额度的接口（实测：详情族里只有这几类真的扣额度）
_QUOTA_RULES = [
    (re.compile(r'/homefeed$'), 'feed'),
    (re.compile(r'/note/basic/homefeed$'), 'feed'),
    (re.compile(r'/note/(imagefeed|videofeed|notefeed|feed)$'), 'feed'),
    (re.compile(r'/(imagefeed|videofeed|notefeed)$'), 'feed'),
    (re.compile(r'/search/notes$'), 'search'),
    (re.compile(r'/note/detail(feed)?(/|$)'), 'detail'),
    (re.compile(r'/user/posted$'), 'posted'),
]

_QUOTA_DESC = {
    'feed': '首页/关注流（吃内容额度，实测连续 13 次起降级）',
    'search': '搜索结果（吃内容额度，与 feed 同族）',
    'detail': '笔记详情（吃内容额度）',
    'posted': '用户发布列表（普通额度，不扣内容）',
    'normal': '不吃内容额度（配置类/引导类接口）',
}

# 命令号语义（来自 dex 调用点：n7c/f.i 与 p9c/f.i，以及 k3 门面）
_CMD_ALIAS = {
    'sign': ('05fdf55e', 100529502, '9.49.1 请求签名（调用点 n7c/f.i）'),
    'sign951': ('05c13380', 96547712, '9.51.0 请求签名（调用点 p9c/f.i）'),
    'init': ('016a1112', 23728402, '初始化，参数 Long(uptimeMillis)，跨版本通用'),
    'cfg': ('af670333', -1352203469, '9.49.1 配置灌入（k3.a 180 条重载）'),
}


def _find_dir():
    """按优先级找资产目录：运行时 data/reverse 优先，其次镜像内置 reverse_data。"""
    cands = [
        os.path.join(os.getcwd(), 'data', 'reverse'),
        '/app/data/reverse',
        os.path.join(_HERE, 'data', 'reverse'),
        os.path.join(os.getcwd(), 'reverse_data'),
        os.path.join(_HERE, 'reverse_data'),
    ]
    for c in cands:
        if os.path.isfile(os.path.join(c, 'api_paths.txt')):
            return c
    return None


class Assets(object):
    def __init__(self):
        self.reload()

    def reload(self):
        self.dir = _find_dir()
        self.paths = []
        self.headers = []
        self.cmds = {}
        # ★ 必须最先初始化：目录缺失时下面的 `return self` 会提前退出，
        #   若把 _pathset 放到函数末尾，exists() 就会 AttributeError（接口 500）。
        #   契约是「数据缺失返回空集，不抛异常」，空集就得在任何分支都成立。
        self._pathset = set()
        if not self.dir:
            return self
        try:
            with open(os.path.join(self.dir, 'api_paths.txt'), encoding='utf-8') as f:
                self.paths = [l.strip() for l in f if l.strip()]
        except Exception:
            self.paths = []
        try:
            with open(os.path.join(self.dir, 'headers.txt'), encoding='utf-8') as f:
                self.headers = [l.strip() for l in f if l.strip()]
        except Exception:
            self.headers = []
        try:
            with open(os.path.join(self.dir, 'cmd_ids.json'), encoding='utf-8') as f:
                self.cmds = json.load(f) or {}
        except Exception:
            self.cmds = {}
        self._pathset = set(self.paths)
        return self

    # ---------------- 查询 ----------------
    def exists(self, path):
        return (path or '') in self._pathset

    def classify(self, path):
        p = (path or '').lower()
        for name, kws in _FAMILIES:
            if any(k in p for k in kws):
                return name
        return '其他'

    def quota_kind(self, path):
        p = (path or '').split('?')[0]
        for pat, kind in _QUOTA_RULES:
            if pat.search(p):
                return kind
        return 'normal'

    def is_quota(self, path):
        return self.quota_kind(path) != 'normal'

    def quota_desc(self, path):
        return _QUOTA_DESC.get(self.quota_kind(path), '')

    def quota_paths(self):
        return [(p, self.quota_kind(p)) for p in self.paths if self.is_quota(p)]

    def cmd(self, name):
        key = (name or '').lower().lstrip('0x')
        if key in _CMD_ALIAS:
            hx, dec, note = _CMD_ALIAS[key]
            hit = self.cmds.get(hx) or {}
            return {'hex': hx, 'dec': dec, 'note': note,
                    'target': hit.get('target'), 'caller': hit.get('caller'),
                    'in_core_table': bool(hit)}
        v = self.cmds.get(key)
        if v:
            return dict(hex=key, **v)
        for k, info in self.cmds.items():
            if name and name in (info.get('caller') or ''):
                return dict(hex=k, **info)
        return None

    def summary(self):
        fam = {}
        for p in self.paths:
            fam[self.classify(p)] = fam.get(self.classify(p), 0) + 1
        return {
            'dir': self.dir,
            'api_paths': len(self.paths),
            'headers': len(self.headers),
            'cmd_ids': len(self.cmds),
            'quota_paths': sum(1 for p in self.paths if self.is_quota(p)),
            'families': dict(sorted(fam.items(), key=lambda kv: -kv[1])),
        }


assets = Assets()
