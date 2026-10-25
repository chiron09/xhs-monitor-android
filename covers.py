# -*- coding: utf-8 -*-
"""封面图本地化：入库时把小红书 CDN 的时效签名图下载到 data/covers/。

CDN 链接形如 http://sns-webpic-qc.xhscdn.com/<时间戳签名>/...，约数小时后过期
（403），因此入库时必须立即本地化，否则笔记列表的封面必然失效。

⚠️ **本模块不走设备代理**（urllib 直连），属于「代理覆盖范围」之外的唯一网络出口。
   当前抓取链路**已不使用它**（scheduler 直接用笔记原 CDN 链接，不做本地化），
   所以目前无实际影响。若将来重新启用封面下载，**必须先补代理支持**，
   否则这部分流量会绕过设备的出口 IP —— 详见 tools/proxy_route_audit.py。
"""
import os
import urllib.request

COVERS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "covers")

_EXT_BY_TYPE = {
    "image/webp": ".webp",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
}


def download_cover(note_id: str, url: str, timeout: float = 12.0):
    """下载封面到本地，返回可访问路径（/covers/<file>）；失败返回 None。"""
    if not url or not url.startswith(("http://", "https://")):
        return None
    try:
        os.makedirs(COVERS_DIR, exist_ok=True)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if not data or len(data) < 1024:  # 过小的响应视为异常图
            return None
        ext = _EXT_BY_TYPE.get(ctype, ".jpg")
        filename = f"{note_id}{ext}"
        with open(os.path.join(COVERS_DIR, filename), "wb") as f:
            f.write(data)
        return f"/covers/{filename}"
    except Exception:  # noqa: BLE001  # 下载失败不阻塞笔记入库
        return None
