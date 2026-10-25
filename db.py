# -*- coding: utf-8 -*-
"""SQLAlchemy 数据模型 + 会话。"""
import os
from datetime import datetime

from sqlalchemy import BigInteger, Column, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DATA_DIR, DB_PATH

os.makedirs(DATA_DIR, exist_ok=True)

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _fmt_ms(ms) -> str:
    """epoch 毫秒 → 'YYYY-MM-DD HH:MM:SS'；0/非法 → 空字符串（供前端直接展示）。"""
    try:
        v = int(ms or 0)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    return datetime.fromtimestamp(v / 1000).strftime("%Y-%m-%d %H:%M:%S")


class Device(Base):
    """签名设备（App 协议，替代原 Cookie 账号）。

    payload 为完整设备材料 JSON（did/hmac/key64/mua0/cp/platform_info/scene/
    user_agent/gid/sid/user_id/nickname...），由 xhs-console 零模板生成器产出。
    """
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), default="")
    label = Column(String(128), default="")       # 设备备注名（沿用生成时的机型名）
    payload = Column(Text, default="{}")          # 设备材料 JSON
    nickname = Column(String(128), default="")    # 登录账号昵称（体检回写）
    xhs_user_id = Column(String(64), default="")  # 登录账号 user_id
    status = Column(String(16), default="unknown")  # active / expired / kicked / anomaly / unknown
    last_checked_at = Column(String(32), default="")
    created_at = Column(String(32), default=_now)

    def to_dict(self, with_payload: bool = False) -> dict:
        d = {
            "id": self.id,
            "name": self.name,
            "label": self.label,
            "nickname": self.nickname,
            "xhs_user_id": self.xhs_user_id,
            "status": self.status,
            "last_checked_at": self.last_checked_at,
            "created_at": self.created_at,
        }
        if with_payload:
            d["payload"] = self.payload
        return d

    def payload_dict(self) -> dict:
        import json
        try:
            return json.loads(self.payload or "{}")
        except Exception:
            return {}


class Blogger(Base):
    """博主监控目标。"""
    __tablename__ = "bloggers"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), default="")
    url = Column(Text, default="")
    xhs_user_id = Column(String(64), default="")
    status = Column(String(16), default="active")  # active / paused
    # 监控时段（抓取时段）：'HH:MM' 字符串，闭区间 [monitor_start, monitor_end]。
    # 两端都为空 → 全天监控（兼容历史博主）；start > end 视为跨天（如 22:00-06:00）。
    monitor_start = Column(String(8), default="")
    monitor_end = Column(String(8), default="")
    baseline_note_ids = Column(Text, default="[]")  # JSON 列表
    # 监控起点（毫秒时间戳）：添加博主那一刻。
    # 只把此刻之后发布的笔记视为「新笔记」，避免把添加前的历史笔记推出去。
    monitor_since = Column(BigInteger, default=0)
    # 上次「成功抓取」时间（epoch 毫秒，0=从未）；上次「尝试」时间与连续失败次数
    # 用于失败退避（见 scheduler._is_due），二者分开：失败不推进 last_crawled_at。
    last_crawled_at = Column(BigInteger, default=0)
    last_attempt_at = Column(BigInteger, default=0)
    fail_count = Column(Integer, default=0)
    last_error = Column(Text, default="")
    created_at = Column(String(32), default=_now)

    def to_dict(self) -> dict:
        import json
        try:
            baseline = json.loads(self.baseline_note_ids or "[]")
        except Exception:
            baseline = []
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "xhs_user_id": self.xhs_user_id,
            "monitor_start": self.monitor_start or "",
            "monitor_end": self.monitor_end or "",
            "status": self.status,
            "baseline_count": len(baseline),
            "monitor_since": self.monitor_since or 0,
            "last_crawled_at": _fmt_ms(self.last_crawled_at),
            "last_error": self.last_error,
            "created_at": self.created_at,
        }


class Note(Base):
    """记录博主添加之后新发布的笔记。"""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True)
    blogger_id = Column(Integer, ForeignKey("bloggers.id"), index=True)
    note_id = Column(String(64), default="", index=True)
    title = Column(String(512), default="")
    cover_url = Column(Text, default="")
    note_url = Column(Text, default="")
    publish_time = Column(BigInteger, default=0)  # 毫秒时间戳
    liked_count = Column(Integer, default=0)
    # 推送状态："" / "pending" / "sent" / "failed"（推送补偿重试用）
    push_status = Column(String(16), default="")
    push_attempts = Column(Integer, default=0)
    created_at = Column(String(32), default=_now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "blogger_id": self.blogger_id,
            "note_id": self.note_id,
            "title": self.title,
            "cover_url": self.cover_url,
            "note_url": self.note_url,
            "publish_time": self.publish_time,
            "liked_count": self.liked_count,
            "push_status": self.push_status,
            "push_attempts": self.push_attempts,
            "created_at": self.created_at,
        }


class Setting(Base):
    """键值设置（后台密码 hash 等）。"""
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, default="")


class AuthToken(Base):
    """登录 token（持久化，重启后台不掉登录）。

    expires_at 为空字符串表示永不过期；非空则为 'YYYY-MM-DD HH:MM:SS'，
    校验时与该时刻比较，过期即视为无效。
    """
    __tablename__ = "auth_tokens"

    token = Column(String(64), primary_key=True)
    created_at = Column(String(32), default=_now)
    expires_at = Column(String(32), default="")
    last_seen_at = Column(String(32), default="")
    user_agent = Column(String(256), default="")
    remote_addr = Column(String(64), default="")


Base.metadata.create_all(engine)


def _ensure_columns() -> None:
    """轻量迁移：为已存在的旧表补新增列（SQLite 不支持自动加列）。"""
    import sqlite3
    wanted = {
        "bloggers": [
            ("monitor_since", "BIGINT DEFAULT 0"),
            ("monitor_start", "VARCHAR(8) DEFAULT ''"),
            ("monitor_end", "VARCHAR(8) DEFAULT ''"),
            ("last_attempt_at", "BIGINT DEFAULT 0"),
            ("fail_count", "INTEGER DEFAULT 0"),
        ],
        "notes": [
            ("push_status", "VARCHAR(16) DEFAULT ''"),
            ("push_attempts", "INTEGER DEFAULT 0"),
        ],
    }
    try:
        conn = sqlite3.connect(DB_PATH)
        try:
            for table, cols in wanted.items():
                existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
                for name, ddl in cols:
                    if name not in existing:
                        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

            # 数据迁移：last_crawled_at 由 'YYYY-MM-DD HH:MM:SS' 字符串改为 epoch 毫秒。
            # 幂等：已是整数、或纯数字字符串（上轮已迁移，旧 VARCHAR 亲和列会把 int 存成
            # 数字文本）都跳过；只对日期串做 strptime 转换，避免二次重启把值误清零。
            for bid, val in conn.execute("SELECT id, last_crawled_at FROM bloggers").fetchall():
                if val is None:
                    continue
                if isinstance(val, int):
                    continue
                if isinstance(val, str) and val.strip().isdigit():
                    continue
                epoch = 0
                try:
                    epoch = int(datetime.strptime(val or "", "%Y-%m-%d %H:%M:%S").timestamp() * 1000)
                except Exception:  # noqa: BLE001
                    epoch = 0
                conn.execute("UPDATE bloggers SET last_crawled_at=? WHERE id=?", (epoch, bid))

            # 常用过滤条件的索引（老库没有，这里补；新库由 Column(index=True) 建）
            #   notes.push_status      —— 推送补偿每次都要按 failed 过滤
            #   bloggers.status        —— 调度每轮都查 active
            conn.execute("CREATE INDEX IF NOT EXISTS ix_notes_push_status ON notes(push_status)")
            conn.execute("CREATE INDEX IF NOT EXISTS ix_bloggers_status ON bloggers(status)")

            # notes 去重 + 唯一索引（防并发/重复入库）。
            # 先探测有没有重复再删：原来无条件执行全表 DELETE ... NOT IN(子查询)，
            # 每次启动都要扫一遍全表，数据量上来后启动会被拖慢。
            dup = conn.execute(
                "SELECT COUNT(*) FROM (SELECT blogger_id, note_id FROM notes "
                "GROUP BY blogger_id, note_id HAVING COUNT(*) > 1)"
            ).fetchone()[0]
            if dup:
                conn.execute(
                    "DELETE FROM notes WHERE id NOT IN "
                    "(SELECT MIN(id) FROM notes GROUP BY blogger_id, note_id)"
                )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_notes_blogger_note "
                "ON notes(blogger_id, note_id)"
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:  # noqa: BLE001  # 迁移失败不应阻断启动
        pass


_ensure_columns()
