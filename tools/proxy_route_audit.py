# -*- coding: utf-8 -*-
"""链路代理审计：起一个会记账的 HTTP 代理，逐条链路实测流量是否真的经过代理。

原理：设备/工厂都把代理指向本地记账代理。凡出现对应 CONNECT/POST 记录 = 走了代理；
没记录 = 直连（泄漏）。业务结果（401/406 等）不重要，只关心流量路径。
"""
import os
import sys
import json
import socket
import select
import base64
import threading
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
os.chdir(_ROOT)                      # data/ 等相对路径以项目根为准
os.environ.pop('XHS_ALGO_BASE', None)


class RecordingProxy:
    """最小 HTTP 代理：CONNECT（https 隧道）+ 普通 HTTP 转发，逐条记账。"""

    def __init__(self):
        self.log = []
        self.lock = threading.Lock()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.url = 'http://127.0.0.1:%d' % self.port
        threading.Thread(target=self._loop, daemon=True).start()

    def add(self, *a):
        with self.lock:
            self.log.append(a)

    def mark(self):
        with self.lock:
            return len(self.log)

    def since(self, n):
        with self.lock:
            return list(self.log[n:])

    def _loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        try:
            c.settimeout(30)
            buf = b''
            while b'\r\n\r\n' not in buf:
                d = c.recv(8192)
                if not d:
                    return
                buf += d
            head, _, rest = buf.partition(b'\r\n\r\n')
            first = head.decode('latin1').split('\r\n')[0]
            parts = first.split(' ')
            method, target = parts[0], parts[1]
            if method.upper() == 'CONNECT':
                host, _, port = target.rpartition(':')
                self.add('CONNECT', host, int(port))
                up = socket.create_connection((host, int(port)), timeout=30)
                c.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                if rest:
                    up.sendall(rest)
                self._relay(c, up)
            else:
                from urllib.parse import urlsplit
                u = urlsplit(target)
                self.add(method, u.hostname, u.port or 80, u.path)
                up = socket.create_connection((u.hostname, u.port or 80), timeout=30)
                up.sendall(head + b'\r\n\r\n' + rest)
                self._relay(c, up)
        except Exception as e:  # noqa: BLE001
            self.add('ERR', str(e)[:70])
        finally:
            try:
                c.close()
            except Exception:
                pass

    def _relay(self, a, b):
        socks = [a, b]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], 30)
                if not r:
                    return
                for s in r:
                    d = s.recv(16384)
                    if not d:
                        return
                    (b if s is a else a).sendall(d)
        except Exception:
            pass
        finally:
            try:
                b.close()
            except Exception:
                pass


P = RecordingProxy()
print('记账代理: %s\n' % P.url)

import app as A
import xhs_client
import device_factory as df
from tiny_mua import build_mua

# ---- 造一台带代理的 9.49.1 设备（假材料，只为让请求发得出去）----
dev_id = '11111111-2222-3333-4444-555555555555'
gid = df.random_gid()
cp, local_did, oaid = df.independent_cp_full(dev_id, gid, 'X', 'SM8850')
mua0, _ = build_mua({'brand': 'redmi', 'model': 'X', 'android': '16',
                     'build_id': 'BP2A.250705.008', 'resolution': '1080*2400', 'cpu': 'SM8850'})
PAYLOAD = {
    'did': dev_id, 'device_id': dev_id, 'local_did': local_did, 'oaid': oaid,
    'hmac': base64.b64encode(os.urandom(96)).decode(), 'key64': '00' * 64,
    'mua0': mua0, 'cp': df.tune_cp(cp),
    'platform_info': 'platform=android&build=9491803&deviceId=' + dev_id,
    'scene': 'fs=0&point=601', 'gid': gid,
    'user_agent': df.random_user_agent(),
    'proxy': P.url,          # ★ 关键：设备绑到记账代理
    'ver': '9.49.1',
}
PAYLOAD_9192 = dict(PAYLOAD)
PAYLOAD_9192.pop('ver')       # 走 9.19.2 轨
PAYLOAD_9192['cp'] = PAYLOAD['cp'].replace('versionName=9.49.1', 'versionName=9.19.2').replace('build=9491803', 'build=9192809')
PAYLOAD_9192['user_agent'] = PAYLOAD['user_agent'].replace('Version/9.49.1', 'Version/9.19.2').replace('Build/9491803', 'Build/9192809')
PAYLOAD_9192['platform_info'] = PAYLOAD['platform_info'].replace('build=9491803', 'build=9192809')


def check(name, fn, expect_host=None, expect_proxy=True):
    n = P.mark()
    err = ''
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        err = '%s: %s' % (type(e).__name__, str(e)[:60])
    time.sleep(0.35)
    hits = P.since(n)
    real = [h for h in hits if h[0] not in ('ERR',)]
    hosts = sorted({h[1] for h in real})
    if expect_proxy:
        ok = bool(real) and (expect_host is None or any(h[1] == expect_host for h in real))
    else:
        ok = not real
    print('  %-42s %s  经过代理=%s  host=%s' % (name, '✔' if ok else '✗', bool(real), hosts or '—'))
    if err:
        print('      ↳ 业务结果: %s' % err)
    return ok, real


print('=== A. 9.49.1 轨（XhsSigner9491）===')
results = []
results.append(check('check_device → user/me', lambda: xhs_client.check_device(PAYLOAD), 'edith.xiaohongshu.com'))
results.append(check('fetch_notes_page → posted', lambda: xhs_client.fetch_notes_page(PAYLOAD, '5f1a2b3c4d5e6f7a8b9c0d1e', 2), 'edith.xiaohongshu.com'))
results.append(check('fetch_user_info → user/info', lambda: xhs_client.fetch_user_info(PAYLOAD, '5f1a2b3c4d5e6f7a8b9c0d1e'), 'edith.xiaohongshu.com'))
results.append(check('fetch_all_followings → followings', lambda: xhs_client.fetch_all_followings(PAYLOAD, '5f1a2b3c4d5e6f7a8b9c0d1e', 5, 1), 'edith.xiaohongshu.com'))
results.append(check('fetch_note_share_link → imagefeed', lambda: xhs_client.fetch_note_share_link(PAYLOAD, '6a1b2c3d4e5f60718293a4b5'), 'edith.xiaohongshu.com'))

print('\n=== B. 登录链（app.py 直连端点，走 signer）===')
from fastapi.testclient import TestClient
import sqlite3
d = sqlite3.connect('data/xhs_admin.db')
d.execute("delete from devices where id=4242")
d.execute("insert into devices (id,name,label,payload,nickname,xhs_user_id,status,last_checked_at,created_at) "
          "values (4242,'audit','audit',?,'','','active','','')", (json.dumps(PAYLOAD),))
d.commit(); d.close()

with TestClient(A.app, raise_server_exceptions=False) as c:
    H = {'Authorization': 'Bearer ' + c.post('/api/auth/login', json={'password': 'admin123'}).json()['token']}
    A._login_ok('testclient')
    results.append(check('send_code → vfc_code',
                         lambda: c.post('/api/devices/4242/login/send_code', headers=H,
                                        json={'phone': '13800000000', 'zone': '86'}), 'edith.xiaohongshu.com'))
    results.append(check('submit → check_code',
                         lambda: c.post('/api/devices/4242/login/submit', headers=H,
                                        json={'phone': '13800000000', 'zone': '86', 'code': '000000'}), 'edith.xiaohongshu.com'))
    results.append(check('captcha → redcaptcha/check',
                         lambda: c.post('/api/devices/4242/login/captcha', headers=H,
                                        json={'selectListSeq': '1,2'}), 'edith.xiaohongshu.com'))
    results.append(check('devices/{id}/check',
                         lambda: c.post('/api/devices/4242/check', headers=H), 'edith.xiaohongshu.com'))
    results.append(check('proxy_test（应走指定代理）',
                         lambda: c.post('/api/devices/4242/proxy_test', headers=H, json={'proxy': P.url}),
                         'ip.3322.net'))

print('\n=== C. 9.19.2 轨（XhsSigner，存量兼容）===')
results.append(check('9192 check_device', lambda: xhs_client.check_device(PAYLOAD_9192), 'edith.xiaohongshu.com'))
results.append(check('9192 fetch_notes_page', lambda: xhs_client.fetch_notes_page(PAYLOAD_9192, '5f1a2b3c4d5e6f7a8b9c0d1e', 2), 'edith.xiaohongshu.com'))

print('\n=== D. 设备生成链（device_factory）===')
results.append(check('generate_offline(proxy=…) → rec.xiaohongshu.com',
                     lambda: df.generate_offline(proxy=P.url), 'rec.xiaohongshu.com'))

print('\n=== E. 应当「不经过设备代理」的链路（对照）===')
results.append(check('_get_direct_ip（直连，用于对照）', lambda: A._get_direct_ip(), None, expect_proxy=False))
results.append(check('notifier 推送（微信/钉钉等，独立于设备）',
                     lambda: A.notifier.notify_custom({'enabled': True, 'channels': {
                         'serverchan': {'enabled': True, 'sendkey': 'SCT_invalid_key_for_audit'}}}, 't', 'c'),
                     None, expect_proxy=False))

d = sqlite3.connect('data/xhs_admin.db')
d.execute('delete from devices where id=4242')
d.commit()
print('\n清理后 devices =', d.execute('select count(*) from devices').fetchone()[0])
d.close()

ok_n = sum(1 for ok, _ in results if ok)
print('\n=== 汇总：%d/%d 条链路符合预期 ===' % (ok_n, len(results)))
for ok, real in results:
    if not ok:
        print('  ✗ 异常链路，实际 host:', sorted({h[1] for h in real}) or '（无流量，未走代理）')
