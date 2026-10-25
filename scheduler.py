# -*- coding: utf-8 -*-
"""博主监控轮巡调度：按间隔判断到期，抓首页笔记，识别新笔记入库并推送。"""
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

import notifier
from config import DATA_DIR, EXPIRY_KEYWORDS, MAX_PER_ROUND, PUSH_MAX_AGE_MS, RATE_LIMIT_KEYWORDS, get_tunables
from db import Device, Blogger, Note, SessionLocal, Setting
from xhs_client import (check_device, fetch_note_share_link, fetch_notes_page,
                        is_pinned, normalize_note)

# 账号异常告警：登录过期这类「持续状态」默认 6 小时内最多提醒一次；
# 风控是「冷却后重试」的周期事件，用冷却周期(30分钟)作去重窗口，让每次新风控都告警。
_ACCOUNT_ALERT_INTERVAL = 6 * 3600
_ACCOUNT_COOLDOWN_SECONDS = 30 * 60  # 风控后暂停该账号 30 分钟

# 推送补偿：失败笔记最多重试次数、重试冷却（秒）
_PUSH_MAX_ATTEMPTS = 5
_PUSH_RETRY_COOLDOWN = 300

_LOG = logging.getLogger("xhs_monitor.scheduler")

# 全局抓取节流：保证任意两次「博主抓取启动」至少间隔 crawl_interval_ms（毫秒，跨轮生效）。
# 多并发时把请求在时间轴上错峰打散；单并发时相当于「上一个抓完后至少等这么久再抓下一个」。
_crawl_gate = threading.Lock()
_last_crawl_start_ts = [0.0]


def _throttle_crawl(interval_ms: int) -> None:
    """抓取节流：距上次抓取启动不足 interval_ms 时等待补足。interval<=0 不节流。"""
    if interval_ms <= 0:
        return
    with _crawl_gate:
        if _last_crawl_start_ts[0] > 0:
            wait = (_last_crawl_start_ts[0] + interval_ms / 1000.0) - time.time()
            if wait > 0:
                time.sleep(wait)
        _last_crawl_start_ts[0] = time.time()

# 告警去重的进程内锁：多个博主并发抓取同时触发风控时，串行化「读去重→判断→写去重」，
# 避免并发线程同时读到旧去重时间戳、导致同一风控事件重复推送多条告警。
_ALERT_LOCK = threading.Lock()


def _setup_logging() -> None:
    """结构化日志落到 data/monitor.log（滚动），便于排查「某博主为何没抓到」。"""
    if _LOG.handlers:
        return
    try:
        from logging.handlers import RotatingFileHandler
        os.makedirs(DATA_DIR, exist_ok=True)
        h = RotatingFileHandler(
            os.path.join(DATA_DIR, "monitor.log"),
            maxBytes=1_000_000, backupCount=3, encoding="utf-8",
        )
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        _LOG.addHandler(h)
        _LOG.setLevel(logging.INFO)
    except Exception:  # noqa: BLE001
        pass


def _now_ms() -> int:
    return int(time.time() * 1000)


# 轮巡跳过日志降噪。
# 调度每 20 秒一轮，「已暂停抓取 / 无可用账号」这类持续状态原来每轮写一行 ——
# 实测 6 小时 15 分写出 983 行全是同一句，4MB 滚动日志被这句吃满，
# 真正的风控告警会被冲掉。改为：同一原因 30 分钟只记一次，原因变化立即记。
_SKIP_LOG_LOCK = threading.Lock()
_skip_log_state = {'key': '', 'ts': 0.0}
_SKIP_LOG_INTERVAL = 1800


def _log_skip(key: str, msg: str, level: int = logging.INFO) -> None:
    now = time.time()
    with _SKIP_LOG_LOCK:
        if _skip_log_state['key'] == key and now - _skip_log_state['ts'] < _SKIP_LOG_INTERVAL:
            return
        _skip_log_state['key'] = key
        _skip_log_state['ts'] = now
    _LOG.log(level, msg)


def _notify_account_alert(db, account, blogger_name: str, title: str, content: str,
                          dedup_key: str = "acct_alert_ts",
                          dedup_interval: int = _ACCOUNT_ALERT_INTERVAL) -> bool:
    """账号异常告警（跨渠道），带时间窗去重，去重状态落库（重启不丢、多实例共享）。

    dedup_key 区分告警类型（登录过期 / 风控各自独立去重，互不压制）。
    dedup_interval 控制去重窗口：风控=冷却周期(30分钟)，登录过期=6小时。
    返回 True 表示这是一次「新的告警事件」（去重通过、已尝试推送）；
    False 表示被去重窗口跳过（不算新事件）。推送成败写入日志。
    """
    # 去重判断 + 写时间戳：加锁串行化，避免并发重复推送（推送本身放锁外，避免阻塞网络请求）
    with _ALERT_LOCK:
        now = time.time()
        s = db.get(Setting, dedup_key)
        try:
            data = json.loads(s.value) if s and s.value else {}
        except Exception:  # noqa: BLE001
            data = {}
        if now - float(data.get(str(account.id), 0) or 0) < dedup_interval:
            return False
        data[str(account.id)] = now
        if s:
            s.value = json.dumps(data)
        else:
            db.add(Setting(key=dedup_key, value=json.dumps(data)))
        db.commit()
    try:
        result = notifier.notify_custom(notifier.get_config(db), title, content)
    except Exception as e:  # noqa: BLE001
        _LOG.warning("账号告警推送异常（%s）: %s", title, e)
    else:
        ok = (result or {}).get("ok_count", 0)
        if ok:
            _LOG.info("账号告警已推送（%d 渠道）: %s", ok, title)
        else:
            _LOG.warning("账号告警推送无成功渠道（%s）: failures=%s",
                         title, (result or {}).get("failures"))
    return True


def _record_ratelimit(db, account, blogger_name: str, error: str = "") -> None:
    """记录每次风控的具体时间（落库历史，最多保留 50 条，重启不丢）。"""
    key = "acct_ratelimit_log"
    s = db.get(Setting, key)
    try:
        log = json.loads(s.value) if s and s.value else []
    except Exception:  # noqa: BLE001
        log = []
    if not isinstance(log, list):
        log = []
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "account_id": account.id,
        "account": account.name,
        "blogger": blogger_name,
        "error": error or "",
    }
    log.append(entry)
    log = log[-50:]
    if s:
        s.value = json.dumps(log, ensure_ascii=False)
    else:
        db.add(Setting(key=key, value=json.dumps(log, ensure_ascii=False)))
    db.commit()
    _LOG.info("记录风控 账号#%s %s 时间=%s error=%s",
              account.id, account.name, entry["time"], error or "")


def _alert_account_expiry(db, account, blogger_name: str) -> None:
    """设备登录态失效告警。"""
    _notify_account_alert(
        db, account, blogger_name,
        "⚠️ 小红书设备登录态已失效，监控暂停",
        f"设备「{account.name}」的登录态已失效（sid 过期或被踢），该设备下的博主监控暂停。\n\n"
        f"最近受影响博主：{blogger_name}\n"
        f"恢复方法：打开监控后台 → 设备管理 → 点该设备的「登录」→ 用手机验证码重新登录。\n"
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        dedup_key="acct_expiry_ts",
    )


def _alert_account_ratelimit(db, account, blogger_name: str, error: str = "") -> None:
    """账号触发风控（300011 账号异常）：记录风控时间 + 告警推送。"""
    code = "300011" if "300011" in (error or "") else ""
    hint = f"接口返回：{error}" if error else "接口返回 300011（账号异常）"
    is_new = _notify_account_alert(
        db, account, blogger_name,
        "⚠️ 小红书账号触发风控（300011），已暂停抓取",
        f"账号「{account.name}」被风控，已自动暂停 {_ACCOUNT_COOLDOWN_SECONDS // 60} 分钟，"
        f"期间该账号下所有博主暂停抓取，避免持续请求加重风控。\n\n"
        f"错误码：{code or '300011'}\n"
        f"{hint}\n"
        f"最近受影响博主：{blogger_name}\n"
        f"时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        dedup_key="acct_ratelimit_ts",
        dedup_interval=_ACCOUNT_COOLDOWN_SECONDS,  # 30 分钟：每次新风控事件都告警
    )
    if is_new:
        # 只在「新风控事件」时记录具体时间，避免冷却内重复触发导致历史重复
        _record_ratelimit(db, account, blogger_name, error)


def _account_cooldown_until(db, account_id) -> float:
    """账号风控冷却到期时间（epoch 秒）；无冷却返回 0。"""
    if not account_id:
        return 0.0
    s = db.get(Setting, f"acct_cooldown:{account_id}")
    try:
        return float(s.value) if s and s.value else 0.0
    except (ValueError, TypeError):
        return 0.0


def _set_account_cooldown(db, account_id, seconds: int) -> None:
    """设置账号风控冷却（落库，独立 commit，不依赖告警是否去重）。"""
    if not account_id:
        return
    key = f"acct_cooldown:{account_id}"
    s = db.get(Setting, key)
    val = str(time.time() + seconds)
    if s:
        s.value = val
    else:
        db.add(Setting(key=key, value=val))
    db.commit()


def _is_rate_limited(error) -> bool:
    return any(k in (error or "") for k in RATE_LIMIT_KEYWORDS)


def _get_baseline(blogger: Blogger) -> list:
    try:
        return json.loads(blogger.baseline_note_ids or "[]")
    except Exception:  # noqa: BLE001
        return []


def _set_baseline(blogger: Blogger, note_ids: list) -> None:
    blogger.baseline_note_ids = json.dumps(note_ids, ensure_ascii=False)


def _day_start_ms(ts: float) -> int:
    """给定时间戳，返回其所在「当天 00:00:00」的毫秒时间戳（本地时区）。"""
    d = datetime.fromtimestamp(ts)
    start = d.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(start.timestamp() * 1000)


def _is_published_today(publish_time: int) -> bool:
    """publish_time（epoch 毫秒，绝对时间）是否落在「今天 00:00 ~ 现在」。

    「今天」按服务器本地时区定义（部署机为 GMT+8，即用户所在时区）。
    缺失 / 非法 / 非正值一律判 False（无法确认是今天，保守不推）。
    """
    try:
        pt = int(publish_time or 0)
    except (TypeError, ValueError):
        return False
    if pt <= 0:
        return False
    now = datetime.now()
    return _day_start_ms(now.timestamp()) <= pt <= int(now.timestamp() * 1000)


def _is_after_monitor_since(publish_time: int, monitor_since: int) -> bool:
    """publish_time 是否晚于「添加博主」时刻。

    monitor_since 未设置（0）时不做此过滤（兼容历史博主）。
    发布时间缺失/非法 → 保守判 False（无法证明是监控起点后发布）。
    """
    if not monitor_since:
        return True
    try:
        pt = int(publish_time or 0)
    except (TypeError, ValueError):
        return False
    if pt <= 0:
        return False
    return pt > int(monitor_since)


def _is_recent(publish_time: int, now_ms: int | None = None,
               max_age_ms: int | None = None) -> bool:
    """publish_time 是否在「最近 max_age_ms」内（距当前不超过时效窗口）。

    用于过滤「监控停摆期间漏抓的旧笔记」：发布时间距现在太久就不推送。
    缺失/非法/非正值 → 保守判 False；max_age_ms <= 0 视为「不限制时效」。
    now_ms 用于单测注入固定时间。
    """
    try:
        pt = int(publish_time or 0)
    except (TypeError, ValueError):
        return False
    if pt <= 0:
        return False
    now = now_ms if now_ms is not None else _now_ms()
    age = max_age_ms if max_age_ms is not None else PUSH_MAX_AGE_MS
    if age <= 0:  # 0/负值 = 不限制时效（仅保留「今天 + 晚于监控起点」两层过滤）
        return True
    return 0 <= now - pt <= age


def _passes_new_filter(note: dict, monitor_since: int,
                       max_age_ms: int | None = None) -> bool:
    """三重过滤：必须「今天发布」且「晚于监控起点」且「最近 N 分钟内」。

    发布时间缺失/非法 → 都不满足 → 不推（保守，避免误报旧笔记）。
    max_age_ms 由调用方从 tunables 传入；None 用默认（30 分钟），<=0 不限时效。
    """
    pt = note.get("publish_time", 0)
    return (_is_published_today(pt)
            and _is_after_monitor_since(pt, monitor_since)
            and _is_recent(pt, max_age_ms=max_age_ms))


def _parse_hhmm(value: str):
    """把 'HH:MM' 解析为当天的分钟数（0~1439）；格式非法返回 None。"""
    if not value:
        return None
    try:
        hh, mm = str(value).strip().split(":")
        h, m = int(hh), int(mm)
    except (ValueError, AttributeError):
        return None
    if 0 <= h <= 23 and 0 <= m <= 59:
        return h * 60 + m
    return None


def in_monitor_window(blogger, now: datetime | None = None) -> bool:
    """当前是否落在博主的监控时段内。

    两端为空 → 全天放行（兼容历史博主）。
    只填一端 → 视为从该时刻开始 / 到该时刻结束。
    start > end → 跨天时段（如 22:00-06:00）。
    """
    start_raw = (getattr(blogger, "monitor_start", "") or "").strip()
    end_raw = (getattr(blogger, "monitor_end", "") or "").strip()
    if not start_raw and not end_raw:
        return True

    start = _parse_hhmm(start_raw)
    end = _parse_hhmm(end_raw)
    if start is None and end is None:
        return True  # 配置非法，不阻断监控
    if start is None:
        start = 0
    if end is None:
        end = 24 * 60 - 1

    now = now or datetime.now()
    cur = now.hour * 60 + now.minute
    if start <= end:
        return start <= cur <= end
    # 跨天：22:00-06:00 → [22:00, 24:00) ∪ [00:00, 06:00]
    return cur >= start or cur <= end


def _is_due(b: Blogger, now_ms: int, interval_minutes: int) -> bool:
    """是否到期：从未抓过 → 到期；否则距上次「尝试」超过 interval_minutes（失败再退避 2^n）。

    interval_minutes 目前由 account_switch_minutes（账号轮询切换间隔）传入 ——
    抓取频率与切换节奏被绑成同一个参数。改这个名是为了让读代码的人一眼看到
    语义耦合，别误以为它只影响「换号」。
    失败退避：fail_count 封顶 3 → 最长间隔 = interval × 8。
    """
    if not b.last_attempt_at:
        return True
    fails = min(b.fail_count or 0, 3)
    interval_ms = interval_minutes * 60 * 1000 * (1 << fails)
    return (now_ms - b.last_attempt_at) >= interval_ms


# ---------- 账号轮询 ----------

_ACCOUNT_CURRENT_KEY = "current_account_id"
_ACCOUNT_SWITCHED_AT_KEY = "account_switched_at"


def _get_current_account_id(db) -> int:
    s = db.get(Setting, _ACCOUNT_CURRENT_KEY)
    try:
        return int(s.value) if s and s.value else 0
    except (ValueError, TypeError):
        return 0


def _get_switched_at(db) -> float:
    s = db.get(Setting, _ACCOUNT_SWITCHED_AT_KEY)
    try:
        return float(s.value) if s and s.value else 0.0
    except (ValueError, TypeError):
        return 0.0


def _set_current_account(db, account_id: int) -> None:
    """记录当前轮询账号 + 切换时间戳（落库，重启不丢）。"""
    s = db.get(Setting, _ACCOUNT_CURRENT_KEY)
    if s:
        s.value = str(account_id)
    else:
        db.add(Setting(key=_ACCOUNT_CURRENT_KEY, value=str(account_id)))
    s2 = db.get(Setting, _ACCOUNT_SWITCHED_AT_KEY)
    if s2:
        s2.value = str(time.time())
    else:
        db.add(Setting(key=_ACCOUNT_SWITCHED_AT_KEY, value=str(time.time())))
    db.commit()


def _account_healthy(db, acc, *, probe_ratelimit: bool = False) -> bool:
    """检测账号是否可用。失败则标记状态并返回 False。

    只用一次 user/me 探测（check_device）——同时覆盖「风控」与「登录态失效」。
    probe_ratelimit=True 时才探测（切换账号时）；间隔内复用不探测，
    靠抓取失败兜底切换，避免每 20 秒打一次抓取请求加重风控。
    """
    if not acc or not acc.payload_dict():
        return False
    if not probe_ratelimit:
        return True  # 不探测（间隔内复用），直接放行，靠抓取失败兜底
    if not acc.xhs_user_id:
        return True  # 无已存 uid，无法探测，保守放行（抓取失败会兜底标记）
    try:
        d_ok, d_nick, d_uid, kind, d_err = check_device(acc.payload_dict())
    except Exception as e:  # noqa: BLE001
        d_ok, d_nick, d_uid, kind, d_err = False, '', '', 'unknown', str(e)
    if d_ok:
        acc.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if d_nick:
            acc.nickname = d_nick
        if d_uid:
            acc.xhs_user_id = d_uid
        db.commit()
        return True
    if kind == "anomaly":
        acc.status = "rate_limited"
        acc.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _set_account_cooldown(db, acc.id, _ACCOUNT_COOLDOWN_SECONDS)
        db.commit()
        _LOG.warning("设备#%s %s 风控中（切换前探测）: %s", acc.id, acc.name, d_err)
        return False
    if kind in ("expired", "kicked"):
        acc.status = kind
        acc.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.commit()
        _LOG.warning("设备#%s %s 登录态失效（切换前探测）: %s", acc.id, acc.name, d_err)
        return False
    # unknown（网络抖动等）：不标记状态，保守本轮不用，下一轮再试
    _LOG.warning("设备#%s %s 检测异常（切换前探测）: %s", acc.id, acc.name, d_err)
    return False


def _pick_next_healthy_account(db, accounts, cur_id: int):
    """从 cur_id 的下一个开始循环，找第一个可用账号；都不可用返回 None。

    - active 账号：做完整检测（风控探测），健康才用；
    - rate_limited 账号：冷却到期后才探测，已恢复则改回 active 并用，
      冷却未到期则跳过（避免持续请求加重风控）；
    - expired / unknown / paused：不自动尝试（需用户手动处理）。

    候选账号并行探测（各用独立会话），一次拿到全部健康状态，按顺序选第一个，
    避免串行逐个探测的累计延迟（每个探测约 2.5s）。
    """
    ids = [a.id for a in accounts]
    if not ids:
        return None
    if cur_id in ids:
        idx = ids.index(cur_id)
        order = ids[idx + 1:] + ids[:idx + 1]
    else:
        order = ids
    now = time.time()

    # 1) 筛出可探测的候选（active，或 rate_limited 且冷却到期）
    candidates = []
    for aid in order:
        acc = db.get(Device, aid)
        if not acc or not acc.payload_dict():
            continue
        if acc.status == "rate_limited":
            if _account_cooldown_until(db, aid) > now:
                continue  # 冷却未到期，跳过
        elif acc.status != "active":
            continue  # expired / unknown / paused 不自动尝试
        candidates.append(aid)
    if not candidates:
        return None

    # 2) 并行探测（每账号独立会话，避免并发写同一 SQLAlchemy session）
    def _probe(aid: int):
        d = SessionLocal()
        try:
            a = d.get(Device, aid)
            if not a or not a.payload_dict():
                return aid, False
            return aid, _account_healthy(d, a, probe_ratelimit=True)
        finally:
            d.close()

    healthy: dict = {}
    if len(candidates) == 1:
        aid = candidates[0]
        healthy[aid] = _probe(aid)[1]
    else:
        with ThreadPoolExecutor(max_workers=len(candidates)) as ex:
            for aid, ok in ex.map(_probe, candidates):
                healthy[aid] = ok

    # 3) 按顺序选第一个健康的（恢复 active 标记）
    for aid in order:
        if healthy.get(aid) is not True:
            continue
        db.expire_all()  # 强制重新加载，拿到并行探测里更新的最新状态
        acc = db.get(Device, aid)
        if acc is None:
            continue
        if acc.status != "active":
            acc.status = "active"
            acc.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            db.commit()
            _LOG.info("账号#%s %s 已解除风控，重新参与轮询", acc.id, acc.name)
        return acc
    return None


def _note_to_dict(note: Note) -> dict:
    """把 Note 行还原成推送所需字段（失败重推用）。"""
    return {
        "note_id": note.note_id,
        "title": note.title,
        "cover_url": note.cover_url,
        "note_url": note.note_url,
        "publish_time": note.publish_time,
        "liked_count": note.liked_count,
    }


def retry_failed_pushes(db) -> dict:
    """推送补偿：重推 push_status=failed 且未超过重试上限的笔记（按博主分组）。"""
    now = time.time()
    s = db.get(Setting, "push_retry_at")
    try:
        last = float(s.value) if s and s.value else 0.0
    except (ValueError, TypeError):
        last = 0.0
    if now - last < _PUSH_RETRY_COOLDOWN:
        return {"retried": 0}
    # 无论有无失败都记录本次检查时间，避免每 20 秒全表扫一次
    if s:
        s.value = str(now)
    else:
        db.add(Setting(key="push_retry_at", value=str(now)))
    db.commit()

    failed = (db.query(Note)
              .filter(Note.push_status == "failed", Note.push_attempts < _PUSH_MAX_ATTEMPTS)
              .all())
    if not failed:
        return {"retried": 0}

    cfg = notifier.get_config(db)
    if not cfg.get("enabled"):
        # 推送未启用：无需重试，标记为已处理，避免永远挂在 failed
        for n in failed:
            n.push_status = "sent"
        db.commit()
        return {"retried": 0}

    by_blogger: dict[int, list] = {}
    for n in failed:
        by_blogger.setdefault(n.blogger_id, []).append(n)

    retried = 0
    for bid, notes in by_blogger.items():
        blogger = db.get(Blogger, bid)
        if not blogger:
            continue
        note_dicts = [_note_to_dict(n) for n in notes]
        try:
            res = notifier.notify_new_notes(cfg, blogger.name, note_dicts)
            ok = (res or {}).get("ok_count", 0) > 0
        except Exception:  # noqa: BLE001
            ok = False
        for n in notes:
            if ok:
                n.push_status = "sent"
            else:
                n.push_attempts = (n.push_attempts or 0) + 1
        if ok:
            retried += len(notes)
            _LOG.info("推送补偿成功 博主#%s %s 共%d条", bid, blogger.name, len(notes))
        db.commit()
    return {"retried": retried}


def refresh_blogger(db, blogger_id: int, *, account_id: int = 0,
                    establish_baseline: bool = False, force: bool = False) -> dict:
    """抓取一个博主，识别新笔记并入库、推送。

    account_id：用哪个账号抓取（账号轮询时由调度器传入当前健康账号）。
    establish_baseline=True 时只建立基线不入库（用于添加博主那一刻）。
    force=True 时忽略监控时段（用户手动点「抓取」时使用）。
    入库条件（同时满足）：① 不在基线中；② 不在已入库去重集；③ 今天发布；④ 晚于监控起点。
    """
    blogger = db.get(Blogger, blogger_id)
    if not blogger:
        return {"ok": False, "error": "博主不存在"}

    # 拉黑的博主：定时监控与手动抓取都拒绝（status 非 active 本就不会进调度队列，
    # 这里拦截手动抓取接口 force=True 的路径）
    if blogger.status == "blocked":
        return {"ok": False, "error": "博主已拉黑，不监控"}

    if not force and not establish_baseline and not in_monitor_window(blogger):
        return {"ok": False, "error": "当前不在监控时段", "skipped_by_window": True}

    account = db.get(Device, account_id) if account_id else None
    if account is None:
        # 未指定账号：自动选一个健康账号（添加博主建基线 / 手动抓取）
        accounts = (db.query(Device)
                    .filter(Device.status == "active")
                    .order_by(Device.id.asc())
                    .all())
        account = _pick_next_healthy_account(db, accounts, 0)
    if not account or not account.payload_dict():
        blogger.last_error = "无可用账号"
        db.commit()
        return {"ok": False, "error": "无可用账号"}

    # 首次抓取且未设监控起点：以当前时刻为起点（添加博主那一刻）
    if not blogger.monitor_since:
        blogger.monitor_since = _now_ms()

    # 记录本次尝试时间（失败退避用）；成功时间单独记 last_crawled_at
    blogger.last_attempt_at = _now_ms()

    # 可调参数：增量抓取条数 / 首抓条数 / 推送时效 从后台设置读取（环境变量兜底）
    tun = get_tunables(db)
    num = tun["first_crawl_num"] if establish_baseline else tun["crawl_num"]

    ok, notes, nickname, error = fetch_notes_page(
        account.payload_dict(), blogger.xhs_user_id,
        num=num,
    )

    if not ok:
        # 失败：不推进 last_crawled_at，累加 fail_count 做退避
        blogger.fail_count = (blogger.fail_count or 0) + 1
        blogger.last_error = error or "抓取失败"
        db.commit()
        _LOG.warning("博主#%s %s 抓取失败: %s", blogger.id, blogger.name, error)
        # 新客户端错误分类：
        #   300011/300014        = 风控标记（要换账号）
        #   code 0 + HTTP 461    = 纯限流（token bucket 打空，6 分钟自愈，别换账号）
        #   -100 / 过期关键词     = 登录失效
        err_s = error or ''
        if _is_rate_limited(error) or '300011' in err_s or '300014' in err_s:
            err_kind = 'rate_limited'
        elif '(code 0)' in err_s or err_s.rstrip().endswith('code 0'):
            err_kind = 'throttled'
        elif any(k in err_s for k in EXPIRY_KEYWORDS) or 'code -100' in err_s:
            err_kind = 'expired'
        else:
            err_kind = 'unknown'
        if account and err_kind in ('rate_limited', 'throttled'):
            # rate_limited：风控标记（换账号）；throttled：纯限流（冷却 6 分钟原地自愈）
            account.status = "rate_limited"
            account.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            _set_account_cooldown(db, account.id,
                                  360 if err_kind == 'throttled' else _ACCOUNT_COOLDOWN_SECONDS)
            db.commit()
            if err_kind == 'rate_limited':
                _alert_account_ratelimit(db, account, blogger.name, error)
            else:
                _LOG.info("博主#%s %s 触发限流（code 0），账号 %s 冷却 6 分钟后重试",
                          blogger.id, blogger.name, account.id)
        elif account and err_kind == 'expired':
            account.status = "expired"
            account.last_checked_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            db.commit()
            _alert_account_expiry(db, account, blogger.name)
        return {"ok": False, "error": error or "抓取失败"}

    # 成功：复位失败计数、记成功时间
    blogger.fail_count = 0
    blogger.last_crawled_at = _now_ms()
    blogger.last_error = ""

    # 归一化：跳过置顶笔记（置顶永远排最前，必须 continue 跳过而非 break）。
    # 不做「非今天即早停」——num 已很小（默认 5），早停收益可忽略；若接口排序
    # 偶发不严格倒序，早停反而会漏掉排在后面的今天新笔记。全量归一化后交给三重过滤兜底。
    normalized = []
    for n in notes:
        # fetch_notes_page 返回的是原始 app 字段，笔记 id 在 `id` 字段（不是 `note_id`）
        if not (isinstance(n, dict) and n.get("id")):
            continue
        if is_pinned(n):
            continue
        normalized.append(normalize_note(n))
    current_ids = [n["note_id"] for n in normalized]
    baseline = _get_baseline(blogger)

    if establish_baseline:
        # 添加博主那一刻：只建基线，不识别新笔记（绝不把添加前的旧笔记当新笔记）。
        candidates = []
    else:
        known = set(baseline)
        candidates = [n for n in normalized if n["note_id"] not in known]

    # 三重过滤：只保留「今天发布」且「晚于监控起点」且「时效窗口内」的笔记
    monitor_since = blogger.monitor_since or 0
    max_age_ms = tun["push_max_age_minutes"] * 60000  # 0 = 不限制时效
    new_notes = [n for n in candidates if _passes_new_filter(n, monitor_since, max_age_ms)]
    skipped = len(candidates) - len(new_notes)

    # 去重：已入库的 note 不再重复插入（DB 唯一索引兜底并发）
    existing_ids = {
        row.note_id for row in db.query(Note).filter(Note.blogger_id == blogger.id).all()
    }
    new_notes = [n for n in new_notes if n["note_id"] not in existing_ids]

    # 为新笔记补充官方分享链接（带 xsec_token，手机点击直达笔记详情页）。
    # 走 imagefeed 详情接口取 token；单条失败静默降级（保留默认跳转页链接），
    # 不影响抓取主流程，也不标记账号状态（这是增强调用，非主链路）。
    for n in new_notes:
        try:
            ok_link, share_url, _ = fetch_note_share_link(account.payload_dict(), n["note_id"])
            if ok_link and share_url:
                n["note_url"] = share_url
        except Exception:  # noqa: BLE001
            pass

    # 封面直接使用原 URL（不下载本地化）
    note_objs = []
    for n in new_notes:
        note_objs.append(Note(
            blogger_id=blogger.id,
            note_id=n["note_id"],
            title=n["title"],
            cover_url=n["cover_url"],
            note_url=n["note_url"],
            publish_time=n["publish_time"],
            liked_count=n["liked_count"],
            push_status="pending",
            push_attempts=0,
        ))
    if note_objs:
        db.add_all(note_objs)

    # 基线更新：抓到空列表时不动基线（避免旧笔记被误判为新笔记、造成重复推送）
    if current_ids:
        _set_baseline(blogger, current_ids)

    db.commit()

    # 新笔记推送（失败不影响抓取结果；失败标记进补偿队列）
    # 时段只约束「定时轮巡」：时段外调度器不抓取，自然不会推送。
    # 用户手动点「抓取」（force=True）是主动行为，抓到新笔记照常推送。
    notify_result = None
    pushed = False
    if note_objs:
        cfg = notifier.get_config(db)
        try:
            if cfg.get("enabled"):
                notify_result = notifier.notify_new_notes(cfg, blogger.name, new_notes)
                ok_push = (notify_result or {}).get("ok_count", 0) > 0
            else:
                # 推送未启用：视为无需重试
                ok_push = True
                notify_result = {"ok_count": 0, "failures": []}
            pushed = bool(ok_push and cfg.get("enabled"))
            for no in note_objs:
                no.push_status = "sent" if ok_push else "failed"
                if not ok_push:
                    no.push_attempts = 1
        except Exception:  # noqa: BLE001
            notify_result = None
            for no in note_objs:
                no.push_status = "failed"
                no.push_attempts = 1
        db.commit()

    _LOG.info("博主#%s %s 抓取成功 抓取=%d 新=%d 推送=%s",
              blogger.id, blogger.name, len(normalized), len(new_notes), pushed)

    return {
        "ok": True,
        "crawled": len(normalized),
        "new_count": len(new_notes),
        "pushed": pushed,
        "skipped_count": skipped,
        "baseline_count": len(current_ids),
        "nickname": nickname,
        "notify": notify_result,
    }


def check_and_crawl() -> dict:
    """账号轮询监控：用「当前账号」抓取所有到期博主。

    - 默认每 account_switch_minutes 分钟切换到下一个健康账号；
    - 切换前先检测账号状态，正常才用，否则标记状态并继续切下一个；
    - 抓取中账号触发风控会被标记 rate_limited，下一轮自动切换到下一个账号；
    - 到期排序按「最久未抓取优先」（LRU），避免 id 靠后的博主长期饿死。
    """
    _setup_logging()
    db = SessionLocal()
    due_ids = []
    account_id = 0
    account_name = ""
    max_per_round = MAX_PER_ROUND
    switch_minutes = 10
    crawl_interval_ms = 0
    skipped_window = 0
    try:
        tun = get_tunables(db)
        max_per_round = tun["max_per_round"]
        switch_minutes = tun["account_switch_minutes"]
        crawl_interval_ms = tun.get("crawl_interval_ms") or 0
        if max_per_round <= 0:
            # 并发数=0：用户主动暂停抓取，本轮不处理
            _log_skip('paused', '并发数=0（已暂停抓取），本轮跳过（同因 30 分钟内不重复记录）')
            return {"checked": 0, "skipped_window": 0, "paused": True, "results": []}

        # 1. 候选账号：active + rate_limited（后者冷却到期后可自动重试恢复）
        accounts = (db.query(Device)
                    .filter(Device.status.in_(["active", "rate_limited"]))
                    .order_by(Device.id.asc())
                    .all())
        if not accounts:
            _log_skip('no_account', '无可用账号，本轮跳过（同因 30 分钟内不重复记录）')
            return {"checked": 0, "skipped_window": 0, "results": []}

        # 2. 确定当前账号：切换间隔内仍 active 则复用（不做每轮检测，抓取失败会自动兜底切换）；
        #    否则切换到下一个可用账号（切换时才做完整检测：登录态 + 风控探测）。
        cur_id = _get_current_account_id(db)
        switched_at = _get_switched_at(db)
        now = time.time()

        current = None
        if cur_id and now - switched_at < switch_minutes * 60:
            acc = db.get(Device, cur_id)
            if acc and acc.status == "active":
                current = acc

        if current is None:
            current = _pick_next_healthy_account(db, accounts, cur_id)
            if current is None:
                _log_skip('all_unavailable', '所有账号均不可用（风控/失效），本轮跳过（同因 30 分钟内不重复记录）', logging.WARNING)
                return {"checked": 0, "skipped_window": 0, "results": []}
            _set_current_account(db, current.id)

        account_id = current.id
        account_name = current.name

        # 3. 用当前账号抓取到期博主
        bloggers = (db.query(Blogger)
                    .filter(Blogger.status == "active")
                    .order_by(Blogger.id.asc())
                    .all())
        now_ms = _now_ms()
        due = []
        for b in bloggers:
            if not in_monitor_window(b):
                skipped_window += 1
                continue
            if _is_due(b, now_ms, switch_minutes):
                due.append(b)
        due.sort(key=lambda b: b.last_attempt_at or 0)  # 最久未抓取优先
        due_ids = [b.id for b in due[:max_per_round]]
    finally:
        db.close()

    results = []

    def _run(bid: int, interval_ms: int = 0) -> dict:
        # 抓取间隔：全局节流（跨轮生效），保证相邻两次抓取启动至少间隔 interval_ms
        _throttle_crawl(interval_ms)
        d = SessionLocal()
        try:
            return {"blogger_id": bid, **refresh_blogger(d, bid, account_id=account_id)}
        finally:
            d.close()

    if due_ids:
        with ThreadPoolExecutor(max_workers=max(1, max_per_round)) as ex:
            futures = [ex.submit(_run, bid, crawl_interval_ms) for bid in due_ids]
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:  # noqa: BLE001
                    results.append({"blogger_id": None, "ok": False, "error": str(e)})

    # 推送补偿重试（有冷却，不会每轮都全表扫）
    retried = 0
    db2 = SessionLocal()
    try:
        retried = (retry_failed_pushes(db2) or {}).get("retried", 0)
    finally:
        db2.close()

    # 空闲轮次（无抓取、无补偿）不写日志：否则「所有博主都在时段外」也会每 20 秒刷一行。
    if results or retried:
        _LOG.info("轮巡结束 账号=%s(#%s) 抓取=%d 时段外=%d 补偿重推=%d",
                  account_name, account_id, len(results), skipped_window, retried)
        for r in results:
            _LOG.info("  - 博主#%s ok=%s new=%d pushed=%s err=%s",
                      r.get("blogger_id"), r.get("ok"), r.get("new_count", 0),
                      r.get("pushed"), r.get("error", ""))

    return {
        "checked": len(results),
        "skipped_window": skipped_window,
        "account_id": account_id,
        "account_name": account_name,
        "retried": retried,
        "results": results,
    }


_scheduler = None
_lock = threading.Lock()


def start_scheduler() -> None:
    global _scheduler
    with _lock:
        if _scheduler is not None:
            return
        from config import SCHEDULER_INTERVAL
        _setup_logging()
        _scheduler = BackgroundScheduler()
        _scheduler.add_job(
            check_and_crawl,
            "interval",
            seconds=SCHEDULER_INTERVAL,
            id="blogger_crawl",
            coalesce=True,                     # 积压时只跑最新一轮
            misfire_grace_time=SCHEDULER_INTERVAL,  # 一轮略超时仍补跑，避免整体错位
        )
        _scheduler.start()
        _LOG.info("调度器启动 间隔=%ds（并发数/切换间隔/抓取条数/推送时效由后台「系统设置」动态读取）",
                  SCHEDULER_INTERVAL)


def stop_scheduler() -> None:
    global _scheduler
    with _lock:
        if _scheduler is not None:
            _scheduler.shutdown(wait=False)
            _scheduler = None
