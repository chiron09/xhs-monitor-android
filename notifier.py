# -*- coding: utf-8 -*-
"""新笔记推送：5 个国内主流渠道。

- Server酱（微信）：sendkey
- PushPlus（微信）：token
- 企业微信机器人：webhook
- 钉钉机器人：webhook（可选加签 secret）
- 飞书机器人：webhook

推送内容统一为「笔记标题 + 链接」。
"""
import base64
import copy
import hashlib
import hmac
import json
import time
from urllib.parse import quote_plus

import requests

TIMEOUT = 12

CHANNELS = ["serverchan", "pushplus", "wecom", "dingtalk", "feishu"]

# 各渠道在配置里需要填写的凭据字段（用于前端渲染 + 后端校验）
CHANNEL_FIELDS = {
    "serverchan": ["sendkey"],
    "pushplus": ["token"],
    "wecom": ["webhook"],
    "dingtalk": ["webhook", "secret"],
    "feishu": ["webhook"],
}

DEFAULT_CONFIG = {
    "enabled": False,
    "channels": {ch: {"enabled": False} for ch in CHANNELS},
}


# ---------- 配置读写 ----------

def get_config(db) -> dict:
    from db import Setting
    s = db.get(Setting, "notify_config")
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if s and s.value:
        try:
            loaded = json.loads(s.value)
            if isinstance(loaded, dict):
                cfg["enabled"] = bool(loaded.get("enabled", False))
                loaded_ch = loaded.get("channels") or {}
                for ch in CHANNELS:
                    c = loaded_ch.get(ch) or {}
                    cfg["channels"][ch] = {
                        "enabled": bool(c.get("enabled", False)),
                        **{k: str(c.get(k, "") or "") for k in CHANNEL_FIELDS[ch]},
                    }
        except Exception:  # noqa: BLE001
            pass
    return cfg


def save_config(db, cfg: dict) -> None:
    from db import Setting
    value = json.dumps(cfg, ensure_ascii=False)
    s = db.get(Setting, "notify_config")
    if s:
        s.value = value
    else:
        db.add(Setting(key="notify_config", value=value))
    db.commit()


# ---------- 消息格式化 ----------

def format_notes(blogger_name: str, notes: list) -> tuple[str, str]:
    """返回 (标题, 正文)。正文为纯文本，空行分隔。"""
    title = f"小红书新笔记：{blogger_name}"
    lines = [f"博主「{blogger_name}」发布了 {len(notes)} 条新笔记：", ""]
    for i, n in enumerate(notes, 1):
        t = (n.get("title") or "(无标题)").strip()
        lines.append(f"{i}. {t}")
        # 标注发布时间，便于确认是当天新发的（ms 时间戳）
        pt = n.get("publish_time") or 0
        if pt:
            try:
                from datetime import datetime as _dt
                lines.append(f"发布：{_dt.fromtimestamp(int(pt) / 1000).strftime('%Y-%m-%d %H:%M')}")
            except Exception:  # noqa: BLE001
                pass
        lines.append(f"链接：{n.get('note_url') or ''}")
        lines.append("")
    return title, "\n".join(lines)


# ---------- 各渠道发送 ----------

def _serverchan(sendkey: str, title: str, content: str) -> None:
    r = requests.post(
        f"https://sctapi.ftqq.com/{sendkey}.send",
        data={"title": title, "desp": content},
        timeout=TIMEOUT,
    )
    d = r.json()
    if d.get("code") != 0:
        raise RuntimeError(d.get("message") or d.get("info") or "Server酱返回失败")


def _pushplus(token: str, title: str, content: str) -> None:
    r = requests.post(
        "https://www.pushplus.plus/send",
        json={"token": token, "title": title, "content": content, "template": "txt"},
        timeout=TIMEOUT,
    )
    d = r.json()
    if d.get("code") != 200:
        raise RuntimeError(d.get("msg") or "PushPlus 返回失败")


def _wecom(webhook: str, content: str) -> None:
    r = requests.post(
        webhook,
        json={"msgtype": "text", "text": {"content": content}},
        timeout=TIMEOUT,
    )
    d = r.json()
    if d.get("errcode") != 0:
        raise RuntimeError(d.get("errmsg") or "企业微信返回失败")


def _dingtalk(webhook: str, secret: str, content: str) -> None:
    url = webhook
    if secret:
        ts = str(round(time.time() * 1000))
        string_to_sign = f"{ts}\n{secret}"
        digest = hmac.new(secret.encode(), string_to_sign.encode(), hashlib.sha256).digest()
        sign = quote_plus(base64.b64encode(digest))
        sep = "&" if "?" in webhook else "?"
        url = f"{webhook}{sep}timestamp={ts}&sign={sign}"
    r = requests.post(
        url,
        json={"msgtype": "text", "text": {"content": content}},
        timeout=TIMEOUT,
    )
    d = r.json()
    if d.get("errcode") != 0:
        raise RuntimeError(d.get("errmsg") or "钉钉返回失败")


def _feishu(webhook: str, content: str) -> None:
    r = requests.post(
        webhook,
        json={"msg_type": "text", "content": {"text": content}},
        timeout=TIMEOUT,
    )
    d = r.json()
    if d.get("code") != 0:
        raise RuntimeError(d.get("msg") or "飞书返回失败")


_SENDERS = {
    "serverchan": lambda c, t, ct: _serverchan(c.get("sendkey", ""), t, ct),
    "pushplus": lambda c, t, ct: _pushplus(c.get("token", ""), t, ct),
    "wecom": lambda c, t, ct: _wecom(c.get("webhook", ""), ct),
    "dingtalk": lambda c, t, ct: _dingtalk(c.get("webhook", ""), c.get("secret", ""), ct),
    "feishu": lambda c, t, ct: _feishu(c.get("webhook", ""), ct),
}


def _has_credential(name: str, c: dict) -> bool:
    return all(bool((c.get(f) or "").strip()) for f in CHANNEL_FIELDS[name] if f != "secret")


def _dispatch(config: dict, title: str, content: str, *, require_enabled: bool = True) -> dict:
    """向所有「已启用且凭据齐全」的渠道发送。返回 {ok_count, failures}。

    原来 notify_new_notes / notify_custom / send_test 各抄了一遍这个循环，
    三份必须同步维护 —— 抽出来只有一处。
    require_enabled=False 供「测试推送」用（总开关没开时也要能测）。
    """
    if not config or (require_enabled and not config.get("enabled")):
        return {"ok_count": 0, "failures": []}
    channels = config.get("channels") or {}
    ok_count, failures = 0, []
    for name, send in _SENDERS.items():
        c = channels.get(name) or {}
        if not c.get("enabled"):
            continue
        if not _has_credential(name, c):
            failures.append(f"{name}: 凭据未填完整")
            continue
        try:
            send(c, title, content)
            ok_count += 1
        except Exception as e:  # noqa: BLE001
            failures.append(f"{name}: {e}")
    return {"ok_count": ok_count, "failures": failures}


# ---------- 分发入口 ----------

def notify_new_notes(config: dict, blogger_name: str, new_notes: list) -> dict:
    """向所有启用的渠道推送新笔记。返回 {ok_count, failures}。"""
    title, content = format_notes(blogger_name, new_notes)
    return _dispatch(config, title, content)


def notify_custom(config: dict, title: str, content: str) -> dict:
    """向所有启用的渠道推送自定义消息（如账号告警）。返回 {ok_count, failures}。"""
    return _dispatch(config, title, content)


def send_test(config: dict) -> dict:
    """向所有启用的渠道发一条测试消息（不要求总开关 enabled）。返回 {ok_count, failures}。"""
    title = "小红书监控推送测试"
    content = "收到这条消息，说明推送配置成功 ✅\n\n测试笔记标题\n链接：https://www.xiaohongshu.com/explore/demo"
    return _dispatch(config, title, content, require_enabled=False)
