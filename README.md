# xhs-monitor-android · 小红书博主监控（安卓登录态抓取）

> 单体项目，自包含，可独立部署。**只做安卓 App 登录态抓取**。

---

## 定位与边界

**做什么**：用一批「安卓设备材料 + 手机验证码登录态」直接调小红书 App 端接口，按时段轮巡监控指定博主，
识别新笔记 → 入库 → 推送到 Server酱 / PushPlus / 企业微信 / 钉钉 / 飞书。

**不做什么**（本项目**不含**，也不打算加）：

| 不含 | 说明 |
|---|---|
| iOS / 游客态 | 没有 `ios_mua.py` / `guest_factory.py` / `rnote_client.py` / `android_bootstrap/`；本项目的登录只有一条路：**手机验证码** |
| 代理 IP 池 | 没有全局代理池；出口代理是**每台设备自带**的 `payload.proxy` 字段 |
| 独立抓取引擎 | 没有 `crawl_engine.py`；抓取由 `scheduler.py` 直接跑 |
| 抓取日志面板 | 没有 `crawl_logs` 表、没有 `/api/crawl/*` |
| Cookie 账号体系 | 不是 Cookie 登录，是设备材料 + sid |

> 需要 iOS 游客态能力的，是另一个项目，别往这里混。

---

## 快速开始

### 本地跑

```bash
pip install -r requirements.txt
python -m uvicorn app:app --host 127.0.0.1 --port 8091
# 默认密码 admin123（env: XHS_ADMIN_PASSWORD 可覆盖）
```

**零配置即可用**：算法资产在 `vendor_algo/`、逆向资产在 `data/reverse/`，都随项目走，
不需要设 `XHS_ALGO_BASE`（需要时仍可用它覆盖）。

### Docker

```bash
docker compose up -d --build
# 80 → nginx → 容器 8091；数据在 ./data，前端在 ./static
```

---

## 目录结构

```
app.py              FastAPI 主应用（35 个 /api 路由 + 页面 + /jump 跳转页）
scheduler.py        轮巡调度：到期判断、账号切换与冷却、新笔记识别、推送补偿
xhs_client.py       小红书 App 端接口客户端（双轨签名器入口 + 各接口封装）
xhs_core.py         9.19.2 离线签名核心（存量兼容轨）
xhs_core_9491.py    9.49.1 离线签名核心（当前主轨）
device_factory.py   设备材料生成 + verify_material() 材料一致性校验
xhs_perm.py         s1 里 perm8 的真算法（bionic random + 倒序 Fisher-Yates）
tiny_mua.py         9.49.x 的 x-mini-mua 真离线生成器
xhs_assets.py       逆向资产只读查询（分类 / 额度判断 / 命令号）
notifier.py         5 个推送渠道
db.py               SQLAlchemy 模型 + 轻量迁移
config.py           配置与运行时可调参数
covers.py           封面目录（机制保留，当前链路不本地化封面）

vendor_algo/        算法资产（algo_complete / sig_final / sig_matrix_9491 / shield_sdk / xhs_signer / mini_alg）
data/reverse/       逆向资产（1643 条接口 path / 124 个请求头 / 62 个 libtiny 命令号）
static/             前端单页（Vue3 + Element Plus，4 菜单）
docs/               文档（见下）
```

---

## 关键事实（改代码前必读）

| 项 | 值 |
|---|---|
| 安卓 App 版本 | **9.49.1 / build 9491803** |
| mua 载荷版本 | **2.10.1**（改版本号必须同步 UA / cp / platform_info） |
| 签名轨选择 | `payload.ver == '9.49.1'` → `XhsSigner9491`，否则走 `XhsSigner`(9.19.2) |
| 实际发送头数 | **17**（签名三头：`x-mini-gid` / `x-mini-mua` / `x-mini-sig`） |
| `x-mini-s1` | **不发**（dex 全量无此头；62 字节 s1 的真名就是 `x-mini-sig`） |
| `hmac` 长度 | 必须是 **96 字节**（base64 后 128 字符），否则 key64 派生失败 |
| 材料一致性 | UA `Version/x Build/y` ↔ cp `versionName/build` ↔ platform_info `build`；mua 头 `v` ↔ ver；cp `cpu_abi` = `armeabi-v7a` |
| 吃内容额度的接口 | 7 类，详见 `docs/03`。**详情族额度远小于普通接口**，一见 `461 + code=0` 立刻停手 |

---

## 自检与体检

```bash
TOK=$(curl -s -X POST http://127.0.0.1:8091/api/auth/login \
      -H 'Content-Type: application/json' -d '{"password":"admin123"}' \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 1) 一键自检：盾 / perm8 / s1 / sig / 材料规则，5 项全过才 ok=true（纯离线，不发网络）
curl -s http://127.0.0.1:8091/api/reverse/selftest -H "Authorization: Bearer $TOK"

# 2) 逐台材料体检：列出每台设备不自洽的具体项
curl -s http://127.0.0.1:8091/api/devices/material_audit -H "Authorization: Bearer $TOK"

# 3) 逆向资产总览（1643 path / 124 header / 62 命令号）
curl -s http://127.0.0.1:8091/api/reverse/assets -H "Authorization: Bearer $TOK"
```

---

## 文档

| 文档 | 什么时候看 |
|---|---|
| [docs/README.md](docs/README.md) | 文档索引 + 关键事实速查 |
| [docs/01-架构与运维.md](docs/01-架构与运维.md) | 代码怎么组织、怎么部署、怎么回滚 |
| [docs/02-接口清单.md](docs/02-接口清单.md) | 本服务的 35 个后台接口（含真实返回样例） |
| [docs/03-小红书接口使用.md](docs/03-小红书接口使用.md) | 小红书上游接口、签名头、额度与封禁判定 |
| [DEPLOY.md](DEPLOY.md) | 139 服务器的实际部署步骤（1Panel / compose） |
