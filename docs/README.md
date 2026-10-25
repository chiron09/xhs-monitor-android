# 文档索引

> 最后更新：2026-10-26 04:35
> 项目：`xhs-monitor-android`（安卓登录态抓取，单体自包含）

---

## 这是什么

**安卓登录态抓取**：设备由**手机号验证码登录**得到登录态，调度器用这批设备直接抓博主笔记。

**本项目不含**的东西（别误加，也别按老文档操作）：

| 不含 | 说明 |
|---|---|
| 代理 IP 池 | 出口代理改为**每台设备自带**一个 `proxy` 字段，没有全局池 |
| 独立抓取引擎 | 抓取由 `scheduler.py` 直接跑，没有 `crawl_engine.py` |
| 抓取日志面板 | 没有 `crawl_logs` 表，也没有 `/api/crawl/*` |
| iOS / 游客态 | 本项目的登录只有**手机验证码**一条路，没有 iOS 相关模块 |

---

## 三份文档

| 文档 | 什么时候看 |
|---|---|
| [01-架构与运维.md](01-架构与运维.md) | 想知道代码怎么组织、怎么部署、怎么回滚 |
| [02-接口清单.md](02-接口清单.md) | 要调后台接口、写脚本、对前端 |
| [03-小红书接口使用.md](03-小红书接口使用.md) | 要抓数、要签名头、要判断额度与封禁 |

---

## 三条最常用的命令

```bash
# 1) 看服务活着没
curl -s -o /dev/null -w '%{http_code}\n' http://YOUR_HOST/api/auth/status

# 2) 登录取 token
TOK=$(curl -s -X POST http://YOUR_HOST/api/auth/login \
      -H 'Content-Type: application/json' -d '{"password":"<密码>"}' \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

# 3) 一键自检（盾/perm8/s1/sig/材料规则，5 项全通过才 ok=true）
curl -s "http://YOUR_HOST/api/reverse/selftest" -H "Authorization: Bearer $TOK"

# 4) 看逆向资产（1644 条接口 / 62 个命令号）
curl -s "http://YOUR_HOST/api/reverse/assets" -H "Authorization: Bearer $TOK"
```

---

## 关键事实速查

| 项 | 值 |
|---|---|
| 安卓 App 版本 | **9.49.1 / build 9491803** |
| mua 载荷版本 | **2.10.1** |
| 签名轨 | `ver == '9.49.1'` → `XhsSigner9491`；否则 `XhsSigner`(9.19.2 存量兼容) |
| 实际发送头数 | 17 个（签名头 3 个：`x-mini-gid` / `x-mini-mua` / `x-mini-sig`） |
| 后台接口 | **35 个** `/api` 路由（29 业务 + 6 逆向/体检） |
| 一键自检 | `GET /api/reverse/selftest`（盾/perm8/s1/sig/材料规则，纯离线不发网络） |
| 材料体检 | `GET /api/devices/material_audit`（逐台列出不一致项） |
| `x-mini-s1` | **不发送**（dex 全量无此头，`x-mini-sig` 才是 62 字节 s1 的真名） |
| 吃内容额度的接口 | **7 个**（详见 03 文档） |
| 已知接口全集 | 1644 条（`/api/reverse/classify` 可查任意一条） |
| 数据库 | `data/xhs_admin.db`（bind mount，含 devices/bloggers/notes/settings/auth_tokens） |
