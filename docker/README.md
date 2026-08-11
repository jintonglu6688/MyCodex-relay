# MyCodex Relay Docker 部署

Docker 版通过腾讯云容器镜像服务在线分发，同时支持 `linux/amd64` 和
`linux/arm64`。用户准备好 Compose 文件和配置文件后，执行
`docker compose up -d` 即会自动拉取与当前服务器架构匹配的镜像。

默认部署一个非 root Relay 实例，只把明文 HTTP/WebSocket 端口发布到宿主机
`127.0.0.1:38443`。公网 TLS 应由宿主机上的 Nginx、Caddy 或 Traefik 终止。

## 准备文件

将 [`compose.release.yaml`](compose.release.yaml) 保存为 `compose.yaml`，并把
[`relay-config.example.json`](relay-config.example.json) 保存为
`docker/relay-config.json`：

```text
mycodex-relay/
  compose.yaml
  docker/
    relay-config.json
```

编辑 `docker/relay-config.json`：

- `listenHost` 保持 `0.0.0.0`；
- `listenPort` 保持 `38443`；
- `publicHost` 改为 Relay 的公网域名；
- 反向代理提供 HTTPS 时，保持 `publicPort: 443` 和 `publicTls: true`；
- `statePath` 保持 `/var/lib/mycodex-relay/relay-state.db`；
- 反向代理终止 TLS 时，保持 `tls.enabled: false`。

配置文件可能包含部署信息，不要提交或公开。

## 首次启动

先拉取固定版本镜像：

```bash
docker compose pull
```

在持久卷中创建第一个租户：

```bash
docker compose run --rm relay local ensure-tenant \
  --config /etc/mycodex-relay/relay-config.json \
  --name Production \
  --json
```

命令输出的 `secret.value` 只显示一次。立即保存到安全位置，不要写入仓库、普通
日志或 Compose 文件。

启动并检查服务：

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
`http://127.0.0.1:38443`，并保留 WebSocket Upgrade 头。不要把 Compose 端口
改成无主机地址的 `38443:38443`，否则 Docker 会默认绑定所有宿主机接口。

如果反向代理也运行在 Docker 中，应把两个服务加入同一个外部网络，让代理访问
`relay:38443`，并删除 Relay 的 `ports`，不要同时公开明文端口。

## 升级与备份

命名卷 `relay-data` 保存整个 `/var/lib/mycodex-relay`，其中包括 SQLite 数据库、
`relay-state.db.identity.pk8` 身份私钥和迁移备份。它们必须作为一个整体保留。

升级前先停止服务并备份配置与完整数据卷：

```bash
docker compose stop relay
mkdir -p backup
cp docker/relay-config.json backup/relay-config.json
docker run --rm \
  -v mycodex-relay_relay-data:/data:ro \
  -v "$PWD/backup:/backup" \
  alpine:3.23 \
  tar -C /data -czf /backup/relay-data.tar.gz .
```

确认备份已安全保存后，修改 `compose.yaml` 中的版本号，拉取并重建容器：

```bash
docker compose pull
docker compose up -d
```

升级后确认 `/health` 正常，并检查 `/.well-known/mycodex-relay` 的身份指纹没有
变化。不要使用 `docker compose down -v` 升级，`-v` 会删除持久卷。

## 运行边界

- 只支持一个 Relay 副本；不要让多个容器共享同一个状态卷。
- 容器以固定的非 root UID/GID `10001:10001` 运行。
- 根文件系统只读，仅状态卷和 `/tmp` 可写。
- Docker 停止宽限期为 20 秒；Relay 会先关闭 WebSocket，再关闭 SQLite。
