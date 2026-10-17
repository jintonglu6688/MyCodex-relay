# MyCodex Relay Docker 正式版可行性评估

日期：2026-08-11

实施状态：`SIGTERM`/WebSocket 优雅停止已经修复；Docker Compose 已在 Apple
Silicon Mac 的 OrbStack 环境完成 ARM64、AMD64、健康检查、非 root、只读根文件
系统、持久卷、正常停止、身份持久化和容器重建升级验证。正式分发已确定使用
腾讯云 TCR 公有仓库，不再提供新的离线镜像包。`0.1.0` 多架构镜像已发布，
并通过无 TCR 凭据环境完成匿名清单读取、双架构拉取和版本运行验证。

## 结论

**可行性高，可以做正式 Docker 版，不需要重写服务或更换 SQLite。** Relay 已经是单进程 Go HTTP/WebSocket 服务，使用纯 Go SQLite 驱动，现有构建也已覆盖 `linux/amd64` 与 `linux/arm64`。最小方案是：一个多阶段 `Dockerfile`、一个单服务 `compose.yaml`、一个 `.dockerignore`，再补齐进程对 `SIGTERM` 的优雅停止。

推荐首版边界：

- 单实例 Relay 容器；不做集群、自动扩缩容或编排平台适配。
- TLS 继续交给宿主机或同一 Compose 网络中的 Nginx/Caddy/Traefik；Relay 镜像只暴露内部端口 `38443`。
- 配置文件只读挂载；SQLite、Relay identity 和迁移备份放在同一个可写持久卷。
- 正式镜像同时构建 `linux/amd64` 和 `linux/arm64`。
- 正式镜像发布到腾讯云 TCR，用户通过 Compose 直接在线拉取；GitCode 只分发原生平台二进制。

评估时发现的代码阻断项是优雅停止；该问题已经修复并通过真实 Linux
`SIGTERM` 与 Docker Compose 停止验证。当前可以进入 Docker 发布集成阶段。

## 1. 当前服务为什么适合容器化

### 1.1 单二进制、纯 Go 依赖

项目声明 Go 1.25，并使用 `modernc.org/sqlite`；当前依赖图没有 cgo 文件。现有构建脚本已经直接交叉编译 Linux AMD64/ARM64 二进制，说明容器构建无需系统 SQLite 动态库或额外数据库进程：[go.mod](../../go.mod#L1)、[scripts/build.sh](../../scripts/build.sh#L32)。

Docker 官方建议用多阶段构建，将编译器和源码留在构建阶段，运行阶段只复制产物；Go 官方镜像适合作为构建阶段，最终阶段使用满足运行依赖的最小可信镜像。[Docker 多阶段构建](https://docs.docker.com/build/building/multi-stage/)、[Docker Go 指南](https://docs.docker.com/guides/golang/)、[Docker 构建最佳实践](https://docs.docker.com/build/building/best-practices/)

建议正式镜像使用：

- builder：与 `go.mod` 匹配的官方 `golang:1.25-alpine`；
- runtime：固定大版本并在发布时记录 digest 的官方 Alpine；
- `CGO_ENABLED=0`、`-trimpath` 和现有版本 `ldflags`；
- 最终镜像仅包含 Relay 二进制、CA/健康检查所需的最少运行文件，不包含源码。

不推荐首版使用 `scratch`：它虽然更小，但没有 shell、CA 和 HTTP 探针工具，会让健康检查与现场诊断额外复杂化。等镜像稳定后，如确有体积或攻击面收益，再评估 `scratch` 或 distroless。[Docker 基础镜像](https://docs.docker.com/build/building/base-images/)

### 1.2 SQLite 适合首版单实例

Store 将 SQLite 最大连接数限制为 1，设置 `busy_timeout`，启动时执行 schema 初始化/迁移，退出时支持关闭数据库：[internal/store/store.go](../../internal/store/store.go#L14)。这很适合单容器、单持久卷部署。

但它不适合把多个 Relay 副本挂到同一数据库上：在线 host/device 路由保存在每个进程自己的内存 map 中，而不是数据库中：[internal/relay/server.go](../../internal/relay/server.go#L35)、[internal/relay/server.go](../../internal/relay/server.go#L51)。因此首版必须明确：

- `replicas = 1`；
- 不做滚动双实例；
- 升级时允许短暂断开 WebSocket，由客户端按现有重连机制恢复；
- 若未来要横向扩展，需要先重构会话路由和共享状态，不能只增加容器数量。

## 2. 推荐容器拓扑

```text
Internet :443
    |
    v
Nginx / Caddy / Traefik（TLS 与证书续期）
    |
    | HTTP + WebSocket，Compose 内部网络或宿主机 127.0.0.1
    v
mycodex-relay:38443（非 root，单实例）
    |
    +-- /etc/mycodex-relay/relay-config.json 只读
    +-- /var/lib/mycodex-relay               可写持久卷
```

Relay 现有 Linux 部署本来就是 Nginx 终止 TLS、反代到 `127.0.0.1:38443`，并包含 WebSocket Upgrade 头和超时配置：[deploy-relay.sh](../../scripts/package/linux/deploy-relay.sh#L133)。Docker 版应复用该拓扑，不把反向代理打包进 Relay 镜像。Docker 官方也建议容器职责解耦，并明确 `EXPOSE` 不会自动发布端口，真正的对外开放由 `ports`/`-p` 决定。[Docker 构建最佳实践](https://docs.docker.com/build/building/best-practices/)、[Docker 端口发布](https://docs.docker.com/engine/network/port-publishing/)

两种支持方式：

1. **宿主机已有反向代理**：发布 `127.0.0.1:38443:38443`，不绑定公网接口。
2. **反向代理也在 Compose 中**：Relay 只加入内部网络，不配置宿主机 `ports`，代理通过服务名访问 `relay:38443`。

容器内配置的 `listenHost` 必须是 `0.0.0.0`；项目默认值是 `127.0.0.1`，若不覆盖，其他容器或端口映射无法访问：[internal/config/config.go](../../internal/config/config.go#L63)。公网元数据仍应设置 `publicHost=<域名>`、`publicPort=443`、`publicTls=true`，而 `tls.enabled=false` 表示 TLS 在代理终止。

直接由 Relay 提供 TLS 也能工作：代码支持从配置指定证书和私钥：[internal/config/config.go](../../internal/config/config.go#L11)、[internal/relay/server.go](../../internal/relay/server.go#L109)。此时把证书/私钥只读挂载，并将宿主机 `443` 映射到容器高位端口 `38443`；容器内无需 root 绑定低位端口。首版仍推荐代理终止 TLS，因为续证、WebSocket 代理和公网入口已经有成熟现有路径。

## 3. 用户、文件系统与挂载

Docker 官方建议无特权服务使用 `USER`，并在卷权限依赖 UID/GID 时使用稳定的显式 UID/GID。[Docker USER 最佳实践](https://docs.docker.com/build/building/best-practices/#user)

推荐镜像：

- 固定 UID/GID，例如 `10001:10001`；
- `USER 10001:10001`；
- `WORKDIR /var/lib/mycodex-relay`；
- 根文件系统可设为只读，仅状态卷可写；
- 不安装 `sudo`，不授予 Linux capabilities。

挂载边界：

| 容器路径 | 模式 | 内容 | 要求 |
| --- | --- | --- | --- |
| `/etc/mycodex-relay/relay-config.json` | 只读 bind mount | Relay 配置 | 非 root 用户可读，不放入镜像 |
| `/var/lib/mycodex-relay` | 可写 named volume | SQLite、Relay identity、迁移备份 | 必须整体持久化和整体备份 |
| `/etc/mycodex-relay/tls` | 可选只读 bind mount | TLS cert/key | 仅 Relay 直连 TLS 时需要 |

状态卷必须包含：

```text
/var/lib/mycodex-relay/relay-state.db
/var/lib/mycodex-relay/relay-state.db.identity.pk8
/var/lib/mycodex-relay/relay-state.db.pre-secure-pairing.bak（存在时）
```

identity 的实际路径固定为 `StatePath + ".identity.pk8"`：[internal/relay/auth_handlers.go](../../internal/relay/auth_handlers.go#L22)。丢失或替换 identity 会改变 Relay 签名指纹，使已信任旧身份的客户端拒绝连接。数据库迁移也可能在同目录生成备份：[internal/store/store.go](../../internal/store/store.go#L51)。因此不能只挂载或备份单个 `.db` 文件，最简单可靠的规则是持久化整个 `/var/lib/mycodex-relay`。

Docker 的容器可写层会随容器删除；命名卷生命周期独立于容器，适合长期状态。配置和证书更适合只读 bind mount。[Docker Storage](https://docs.docker.com/engine/storage)、[Docker Volumes](https://docs.docker.com/engine/storage/volumes/)、[Docker Bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)

## 4. 配置与首次初始化

无需增加环境变量配置层或自定义 entrypoint。现有 CLI 已能生成配置和租户，首版直接复用即可：[internal/cli/local_commands.go](../../internal/cli/local_commands.go#L35)。

建议流程：

1. 创建配置目录和名为 `mycodex-relay-data` 的 volume；
2. 用同一镜像运行一次 `local init`，显式指定：
   - `--config /config/relay-config.json`
   - `--state /var/lib/mycodex-relay/relay-state.db`
   - `--listen-host 0.0.0.0`
   - `--listen-port 38443`
   - `--public-host <域名>`
   - `--public-port 443`
   - `--public-tls`
3. 用 `local ensure-tenant` 创建首个租户，并只在安全位置保存一次性输出的 secret；
4. 正式启动时将配置改为只读挂载。

这样不需要维护一套把环境变量翻译成 JSON 的 shell 脚本，也不会让秘密进入镜像层或普通环境变量。Docker 官方提醒环境变量可能出现在容器配置中，不适合承载敏感值。[Docker CLI 配置安全提示](https://docs.docker.com/reference/cli/docker/)

## 5. Healthcheck

Relay 已有 `GET /health`，当前返回固定 `200 {"status":"ok"}`：[internal/relay/server.go](../../internal/relay/server.go#L133)。它足够作为首版 liveness/基本 HTTP 可用性检查，但不是数据库深度 readiness 检查。

推荐代理终止 TLS 的默认镜像或 Compose 探针：

```text
wget -qO- http://127.0.0.1:38443/health
```

正式参数建议 `interval=30s`、`timeout=3s`、`start_period=10s`、`retries=3`。最终运行镜像必须真实包含 `wget` 或专用探针，不能在 `scratch`/distroless 镜像里声明一个不存在的命令。Docker 的 `HEALTHCHECK` 根据命令退出码生成 `starting/healthy/unhealthy` 状态，但本身不等于自动恢复策略。[Dockerfile HEALTHCHECK](https://docs.docker.com/reference/dockerfile/#healthcheck)

直连 TLS 模式可配置 Relay 的 loopback internal listener，让探针检查明文内部端口；或在 Compose 中覆盖探针 URL。没有实际需求前，不增加新的 `/ready` 端点或自定义健康检查子命令。

## 6. 优雅停止：已完成

Docker 默认向 PID 1 发送 `SIGTERM`，等待宽限期后再发 `SIGKILL`。exec-form `ENTRYPOINT` 可让 Go 进程直接成为 PID 1 并收到信号。[Dockerfile STOPSIGNAL/ENTRYPOINT](https://docs.docker.com/reference/dockerfile/#stopsignal)、[Compose stop_grace_period](https://docs.docker.com/reference/compose-file/services/#stop_grace_period)

评估时的代码问题：

1. `main` 调用 `cli.Run`，而 `Run` 使用 `context.Background()`，没有 `signal.NotifyContext`：[cmd/mycodex-relay/main.go](../../cmd/mycodex-relay/main.go#L1)、[internal/cli/app.go](../../internal/cli/app.go#L21)。Go 的默认行为是收到 `SIGTERM` 直接退出，因此 `runServe` 的 `defer st.Close()` 不保证执行。[Go os/signal](https://pkg.go.dev/os/signal)
2. Server 虽然在 context 取消时调用 `http.Server.Shutdown`，却使用无超时的 `context.Background()`：[internal/relay/server.go](../../internal/relay/server.go#L119)。
3. Go 官方说明 `http.Server.Shutdown` 不会关闭或等待 WebSocket 这类 hijacked 长连接；Relay 需要主动关闭当前 WebSocket 并等待 handler 退出，才能再关闭 SQLite。[Go http.Server.Shutdown](https://pkg.go.dev/net/http#Server.Shutdown)

当前实现：

- `main` 用标准库 `signal.NotifyContext` 监听 `os.Interrupt` 与 `SIGTERM`，把 context 传给 `RunWithContext`；
- Server shutdown 使用有上限的 context；当前实现为 15 秒；
- shutdown 时停止接受新连接、关闭已登记 WebSocket、等待 handler 退出，然后由现有 `defer st.Close()` 关闭数据库；
- Dockerfile 使用 exec-form `ENTRYPOINT ["/usr/local/bin/mycodex-relay"]` 和 `STOPSIGNAL SIGTERM`；
- Compose 设置大于应用停机超时的 `stop_grace_period`，建议 20 秒。

已经增加 WebSocket 随服务取消关闭的回归测试，并在 Linux 二进制和 Docker
Compose 中验证 `SIGTERM` 后退出码为 0。该路径同时修复 Docker 和现有
systemd 部署的停机缺口。

## 7. 多架构构建与标签

Docker Buildx 可以一次构建 `linux/amd64,linux/arm64`，并在推送 Registry 时生成多平台 manifest；Docker 拉取时会自动选择当前架构。[Docker 多平台构建](https://docs.docker.com/build/building/multi-platform/)

推荐 Dockerfile 构建阶段固定在 `$BUILDPLATFORM`，使用 BuildKit 的 `$TARGETOS/$TARGETARCH` 给 Go 做原生交叉编译，避免为了编译 Go 而依赖 QEMU：

```text
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag <registry>/<namespace>/mycodex-relay:0.1.0 \
  --tag <registry>/<namespace>/mycodex-relay:stable \
  --push .
```

标签规则：

- `0.1.0`：不可变，和源码 `VERSION`、Git 标签 `relay-v0.1.0` 一致；
- `stable`：发布完整验证后最后更新；
- 不覆盖已发布的版本标签；
- 镜像 label 至少记录 version、revision、source；
- Release 记录每个平台 manifest/image digest。

Docker 官方指出镜像 tag 可以变动；需要可复现部署时应使用具体版本或 digest。[Docker 构建最佳实践：pin base image](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions)

## 8. 正式分发边界

截至本报告日期，从 GitCode 官方公开资料中**未能验证 GitCode 提供自有 OCI/Container Registry**。GitCode 流水线文档可以消费外部 Registry 镜像，但示例使用 `myregistry.example.com`，没有给出 GitCode 自有 Registry 地址、认证方式或 OCI push/pull 协议。[GitCode 流水线镜像配置](https://docs.gitcode.com/docs/help/home/org_project/pipeline/runner-management/configuring-images-toolchains/)

因此必须区分：

- **GitCode Release 附件**：普通文件下载，可上传 `.tar.gz`、校验文件并生成固定/版本化直链；
- **OCI Registry**：提供 manifest、blob、digest、tag 和 Registry API，支持 `docker pull`/`docker push`。

把容器镜像 tar 上传到 GitCode Release，不会让它自动变成可 `docker pull` 的镜像仓库。Docker 官方定义的 Registry 推送需要 `docker buildx build --push` 指向 Registry；本地 OCI/Docker layout 则由 exporter 输出到 tar 文件。[Docker exporters](https://docs.docker.com/build/exporters/)、[Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)

正式方案使用腾讯云 TCR 公有仓库：

```text
ccr.ccs.tencentyun.com/mycodex/mycodex-relay:<version>
```

每个版本标签包含 `linux/amd64` 与 `linux/arm64` 的 OCI manifest，Compose 直接
在线拉取。GitCode Release 继续使用不可变 `relay-v<version>` 标签，但只保存五个
原生平台二进制包和 `SHA256SUMS.txt`。不再生成或发布新的 Docker 离线包。

## 9. 升级、备份与恢复

镜像不可变，升级只替换容器，不修改配置和状态卷：

1. 停止 Relay，让 SQLite 停止写入并完成关闭；
2. 备份配置目录和完整 `/var/lib/mycodex-relay` 卷；
3. 拉取/加载新版本镜像；
4. 用新版本标签重建单个容器；
5. 等待 healthcheck，检查 `/.well-known/mycodex-relay` 的身份指纹不变；
6. 确认 Windows 和 Android 能重新连接后再清理旧镜像。

Docker 官方给出的卷备份方式是用临时容器同时挂载数据卷和备份目录，再用 tar 导出；恢复时反向操作。[Docker Volume 备份、恢复和迁移](https://docs.docker.com/engine/storage/volumes/#back-up-restore-or-migrate-data-volumes)

对本项目，必须先停止服务再 tar，避免在 SQLite 写入过程中得到不一致快照。备份集合至少包括：

- `/etc/mycodex-relay/relay-config.json`；
- 完整 `/var/lib/mycodex-relay`；
- 若 Relay 自己终止 TLS，再包括证书和私钥挂载源。

不要使用 `docker compose down -v` 升级，因为 `-v` 会删除命名卷。回滚镜像也不等于回滚数据库 schema；发生迁移前必须先生成可恢复备份。[Docker Compose 数据持久化](https://docs.docker.com/compose/gettingstarted/#step-5-persist-data-with-named-volumes)

## 10. 实施状态与后续发布清单

### 已完成的 Docker RC 前置验证

1. 已补齐 `SIGTERM`、WebSocket 关闭等待和有界 HTTP shutdown。
2. 已在 Apple Silicon Mac 的 OrbStack 环境完成真实 Compose smoke test。
3. 已构建并运行 ARM64 镜像，构建并执行 AMD64 镜像，并生成同时包含
   `linux/amd64` 与 `linux/arm64` 的 OCI 多架构归档。
4. 已验证健康检查、非 root、只读根文件系统、状态卷、正常停止、备份、身份与
   租户跨容器重建保持不变。
5. 已验证双架构镜像均不包含源码；正式发布改为腾讯云 TCR 多架构在线镜像。
6. 已匿名拉取 `ccr.ccs.tencentyun.com/mycodex/mycodex-relay:0.1.0`，并确认
   AMD64、ARM64 均运行并报告 `mycodex-relay 0.1.0`。

### 不是阻断，但必须写清的限制

- 首版只支持单实例；
- 默认要求外部反向代理提供公网 TLS；
- 配置必须使用 `listenHost=0.0.0.0` 和绝对状态路径；
- 状态卷必须整体保留 DB、identity 和迁移备份；
- 腾讯云个人版 TCR 是共享服务，适合当前发布规模，但不承诺企业级 SLA。

### 后续发布改动

1. Docker 发布脚本向腾讯云 TCR 推送 AMD64/ARM64 多架构镜像；
2. GitCode 发布脚本只处理原生平台二进制和校验文件；
3. 发布 RC 前通过实际反向代理完成公网 TLS/WebSocket 端到端验证。

无需新增配置框架、数据库容器、入口脚本、Kubernetes manifests 或自动扩缩容。首版把单实例 Docker Compose 做稳即可。

## 一手资料索引

- [Docker Go 指南](https://docs.docker.com/guides/golang/)
- [Docker 多阶段构建](https://docs.docker.com/build/building/multi-stage/)
- [Docker 构建最佳实践](https://docs.docker.com/build/building/best-practices/)
- [Dockerfile reference](https://docs.docker.com/reference/dockerfile/)
- [Docker 多平台构建](https://docs.docker.com/build/building/multi-platform/)
- [Docker Storage](https://docs.docker.com/engine/storage)
- [Docker Volumes](https://docs.docker.com/engine/storage/volumes/)
- [Docker Bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)
- [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/)
- [Docker Build exporters](https://docs.docker.com/build/exporters/)
- [Go os/signal](https://pkg.go.dev/os/signal)
- [Go net/http Server.Shutdown](https://pkg.go.dev/net/http#Server.Shutdown)
- [GitCode Release API](https://docs.gitcode.com/en/docs/repos/release/)
- [GitCode 流水线镜像配置](https://docs.gitcode.com/docs/help/home/org_project/pipeline/runner-management/configuring-images-toolchains/)
