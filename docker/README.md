# MyCodex Relay Docker 部署

Docker 版以单实例运行 Relay。默认只把端口发布到宿主机
`127.0.0.1:38443`，公网 TLS 应由宿主机上的 Nginx、Caddy 或 Traefik
终止。

## 使用正式发布包

GitCode Release 为 `linux/amd64` 和 `linux/arm64` 各提供一个离线部署包。
附件直链遵循固定规则：

```text
https://api.gitcode.com/api/v5/repos/gcw_SpGZ48lW/mycodex-updates/releases/relay-v<version>/attach_files/<file-name>/download
```

在 Docker 主机上按 CPU 架构下载对应文件和 `DOCKER-SHA256SUMS.txt`。例如
下载 `linux/arm64` 版本：

```bash
VERSION=0.1.0
PACKAGE="mycodex-relay-${VERSION}-docker-linux-arm64.tar.gz"
BASE="https://api.gitcode.com/api/v5/repos/gcw_SpGZ48lW/mycodex-updates/releases/relay-v${VERSION}/attach_files"
curl -fL "$BASE/$PACKAGE/download" -o "$PACKAGE"
curl -fL "$BASE/DOCKER-SHA256SUMS.txt/download" -o DOCKER-SHA256SUMS.txt
grep "  $PACKAGE\$" DOCKER-SHA256SUMS.txt | sha256sum -c -
tar -xzf "$PACKAGE"
cd "${PACKAGE%.tar.gz}"
docker load -i mycodex-relay-image.tar
cp docker/relay-config.example.json docker/relay-config.json
```

包内 `.env` 已把 Compose 镜像版本锁定到下载的版本。编辑配置后，按下文创建
第一个租户并启动服务。升级时下载更高版本的包并重新 `docker load`，不要覆盖
原部署目录中的 `docker/relay-config.json`。

## 准备配置

从仓库根目录复制配置示例：

```bash
cp docker/relay-config.example.json docker/relay-config.json
```

编辑 `docker/relay-config.json`：

- `listenHost` 保持 `0.0.0.0`；
- `listenPort` 保持 `38443`；
- `publicHost` 改为 Relay 的公网域名；
- 反向代理提供 HTTPS 时，保持 `publicPort: 443` 和 `publicTls: true`；
- `statePath` 保持 `/var/lib/mycodex-relay/relay-state.db`；
- 反向代理终止 TLS 时，保持 `tls.enabled: false`。

不要提交 `docker/relay-config.json`。它是部署配置，不是镜像内容。

## 首次启动

从源码部署时构建镜像；正式发布包已经执行过 `docker load`，跳过此命令：

```bash
docker compose build
```

在持久卷中创建第一个租户：

```bash
docker compose run --rm relay local ensure-tenant \
  --config /etc/mycodex-relay/relay-config.json \
  --name Production \
  --json
```

命令输出的 `secret.value` 只显示一次。立即保存在安全位置，不要写入仓库、
普通日志或 Compose 文件。

启动 Relay：

```bash
docker compose up -d
docker compose ps
curl http://127.0.0.1:38443/health
```

查看不包含租户密钥的连接信息：

```bash
docker compose exec relay local info \
  --config /etc/mycodex-relay/relay-config.json \
  --json
```

## 反向代理

反向代理应把公网 HTTPS/WebSocket 请求转发到
`http://127.0.0.1:38443`，并保留 WebSocket Upgrade 头。不要把 Compose
端口映射改成无主机地址的 `38443:38443`，否则 Docker 会默认绑定所有宿主机
接口。

如果反向代理也运行在 Docker 中，应把两个服务加入同一个外部网络，并让代理
访问 `relay:38443`；此时可以删除 `ports`，不要同时公开 Relay 的明文端口。

## 数据、升级与备份

命名卷 `relay-data` 保存整个 `/var/lib/mycodex-relay`，其中包括：

- SQLite 数据库；
- `relay-state.db.identity.pk8` Relay 身份私钥；
- 数据迁移生成的相邻备份文件。

数据库与身份文件必须作为一个整体保留。升级前先停止服务，再备份配置文件和
完整命名卷：

```bash
docker compose stop relay
mkdir -p backup
cp docker/relay-config.json backup/relay-config.json
docker run --rm \
  -v mycodex-relay_relay-data:/data:ro \
  -v "$PWD/backup:/backup" \
  alpine:3.23 \
  tar -C /data -czf /backup/relay-data.tar.gz .
docker compose start relay
```

确认 `backup/relay-config.json` 和 `backup/relay-data.tar.gz` 已保存到安全
位置后，构建或加载新镜像，再重新创建容器。源码部署使用：

`backup/` 已被 Git 和 Docker 构建上下文忽略。该目录包含 Relay 身份私钥，
不得提交、公开或随普通日志发送。

```bash
docker compose up -d --build
```

正式发布包使用：

```bash
docker compose up -d --no-build
```

不要使用 `docker compose down -v` 执行升级；`-v` 会删除持久卷。升级后应确认
`/health` 正常，并检查 `/.well-known/mycodex-relay` 的身份指纹没有变化。

停止但保留数据：

```bash
docker compose down
```

## 运行边界

- 只支持一个 Relay 副本；不要让多个容器共享同一个状态卷。
- 容器以固定的非 root UID/GID `10001:10001` 运行。
- 根文件系统只读，仅状态卷和 `/tmp` 可写。
- Docker 停止宽限期为 20 秒；Relay 收到 `SIGTERM` 后会关闭 WebSocket，等待
  处理器退出，再关闭 SQLite。
