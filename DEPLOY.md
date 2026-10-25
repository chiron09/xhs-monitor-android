# 部署说明（生产机）

> 本项目 = 安卓登录态抓取单体项目。部署形态：宿主机目录作 build context + bind mount 数据，
> **更新代码走 `docker cp`，不重建镜像**（重建会重装依赖，把环境搞漂）。

---

## 一、线上的实际形态

| 项 | 值 |
|---|---|
| 宿主机项目目录 | `/home/ubuntu/xhs-monitor/`（build context） |
| 容器名 | `xhs-monitor`（镜像 `xhs-monitor:latest`） |
| 容器内代码 | `/app/`（**扁平**：`/app/app.py`，没有子目录） |
| 端口 | 容器 `8091` **不映射**；宿主机 nginx `80 → 8091`，冒烟走 `http://127.0.0.1/` |
| 数据卷 | `./data:/app/data`（库 / 日志 / 逆向资产） |
| 前端卷 | `./static:/app/static`（改前端不用重启容器，强刷即可） |
| 算法资产 | 镜像内 `/app/vendor_algo`（`XHS_ALGO_BASE` 指向它；不设也能跑，会自动回落项目内） |
| 入口密码 | `XHS_ADMIN_PASSWORD`（compose 里设，默认 `admin123`） |

---

## 二、首次部署（1Panel 编排）

1. 整个项目上传到 `/home/ubuntu/xhs-monitor/`
2. 1Panel → 容器 → 编排 → 创建编排，来源选该目录（含 `docker-compose.yml`）
3. 部署，等镜像构建完（首次 2~3 分钟，依赖走清华镜像）
4. 访问 `http://YOUR_HOST/`（nginx 80 转容器 8091）
5. 腾讯云安全组只需放行 **80**（容器端口不出网）

> `data/` 挂载宿主机，删容器不丢数据；`.dockerignore` 已排除 `data/`，不会把库打进镜像。

---

## 三、更新代码（日常）

**两处都要同步**，否则「跑着的容器」和「下次重建用的 build context」会不一致：

```bash
# 1) 传文件到宿主机 build context
sftp> put app.py /home/ubuntu/xhs-monitor/app.py

# 2) 同步进正在运行的容器
sudo -n docker cp /home/ubuntu/xhs-monitor/app.py xhs-monitor:/app/app.py

# 3) 改的是 .py 才需要重启（改 static/index.html 不用，强刷即可）
sudo -n docker restart xhs-monitor
```

冒烟（必做）：

```bash
curl -s -o /dev/null -w '%{http_code} %{size_download}B\n' http://127.0.0.1/     # 期望 200 / ~87KB
curl -s http://127.0.0.1/api/auth/status                                          # 期望 {"authed":false}
TOK=$(curl -s -X POST http://127.0.0.1/api/auth/login -H 'Content-Type: application/json' \
      -d '{"password":"<密码>"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
for p in devices bloggers notes settings/tunables notify/config devices/material_audit \
         reverse/assets reverse/quota reverse/selftest; do
  echo -n "$p => "; curl -s -o /dev/null -w '%{http_code}\n' "http://127.0.0.1/api/$p" -H "Authorization: Bearer $TOK"
done
sudo -n docker logs --tail 40 xhs-monitor 2>&1 | grep -iE 'traceback|error' || echo '日志无异常'
```

---

## 四、回滚

```bash
# 代码回滚（在宿主机 build context 里换回旧文件 → cp 进容器 → 重启）
sudo -n docker cp /home/ubuntu/deploy_backup/<备份目录>/app.py xhs-monitor:/app/app.py
sudo -n docker restart xhs-monitor

# 镜像回滚（不要加 --build）
sudo -n docker compose -f /home/ubuntu/xhs-monitor/docker-compose.yml up -d --force-recreate xhs-monitor
```

改代码前先打两个点：`/app` 全量 tgz + 宿主机 `data/xhs_admin.db` 快照，都放 `/home/ubuntu/deploy_backup/`。

---

## 五、注意

- 容器内**没有 pycryptodome**，加密只用 `cryptography`（`tiny_mua.py` 已按此实现）。
- `/api/auth/login` 要 **JSON body**，不是表单。
- 改 `.py` 后必须重启；改 `static/index.html` 不用重启（bind mount），但要强刷。
- 前端改动上线前先本地 `node --check` 检查 script 块，白屏基本都出在这里。
- `data/reverse/`（1643 path / 124 header / 62 命令号）是数据卷内容，**不在代码包里**，按需单独同步。
