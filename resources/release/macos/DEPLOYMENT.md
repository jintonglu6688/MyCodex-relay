# MyCodex Relay macOS 使用说明

本文适用于 `macos-intel` 和 `macos-apple-silicon` 发布包。本发布包主要用于本地测试、受控网络、自托管验证和问题诊断；正式公网服务推荐使用 Linux 发布包。

## 1. 选择正确的包

在“终端”运行：

```bash
uname -m
```

| 输出 | 发布包 |
| --- | --- |
| `x86_64` | `macos-intel` |
| `arm64` | `macos-apple-silicon` |

`macos-apple-silicon` 适用于 M1、M2、M3、M4 等 Apple 芯片。

## 2. 解压和执行权限

完整解压发布包，在“终端”进入解压目录：

```bash
cd /path/to/extracted/package
chmod +x mycodex-relay *.command
```

如果 macOS 阻止运行，请在“系统设置 → 隐私与安全性”中确认该程序来源，并只对你已经核对来源和 SHA-256 的发布包放行。

## 3. 快速启动

在 Finder 双击 `start-relay.command`，或在终端运行：

```bash
./start-relay.command
```

首次启动会自动创建：

```text
relay-config.json
relay-state.db
relay-state.db.identity.pk8
relay.out.log
relay.err.log
mycodex-relay.pid
```

查看服务器信息并确保存在名为 `Local` 的租户：

```bash
./show-relay-info.command
```

首次创建租户时，输出中的访问密钥只显示一次，请立即保存。数据库只保存访问密钥的哈希，之后无法读取原密钥。

停止服务：

```bash
./stop-relay.command
```

## 4. 配置文件选择

脚本按以下顺序选择配置：

1. 命令行明确传入的配置文件。
2. 当前目录中的 `relay-config.local.json`。
3. 当前目录中的 `relay-config.json`。

使用自定义配置：

```bash
./start-relay.command my-relay.json
./show-relay-info.command my-relay.json
```

自定义配置会使用同名数据库，例如 `my-relay.json` 对应 `my-relay.db`。

## 5. 日志和服务器信息

日志位于：

```text
relay.out.log
relay.err.log
```

查看版本：

```bash
./mycodex-relay version
```

读取机器可用的服务器信息：

```bash
./mycodex-relay info --config ./relay-config.json --json
```

已有租户的信息不会包含原访问密钥。密钥遗失时需要显式轮换：

```bash
./mycodex-relay tenant rotate-secret \
  --config ./relay-config.json \
  --tenant xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

轮换后旧密钥立即失效。

## 6. 局域网或公网使用

默认配置主要用于本机测试。允许其他设备访问前，需要同时确认：

1. Relay 监听地址不是仅限回环地址。
2. macOS 防火墙允许 Relay 接收入站连接。
3. 客户端使用的主机名或 IP 与实际访问路径一致。
4. 公网访问使用可信 TLS。
5. 路由器端口转发、反向代理和 WebSocket 头配置正确。
6. 配置中的公网主机、端口和 `publicTls` 与实际入口一致。

macOS 包不会自动配置 `launchd`、可信 TLS 证书、自动续期或反向代理。长期公网服务请使用 Linux 包，或者自行维护这些系统组件。

## 7. 备份

至少备份：

```text
relay-config.json
relay-state.db
relay-state.db.identity.pk8
```

如果使用自定义配置和数据库，请备份对应文件。备份前先停止 Relay，数据库与身份私钥必须作为一组保存。

丢失或替换 `*.identity.pk8` 会改变 Relay 签名指纹，已经信任旧身份的客户端会拒绝连接。

## 8. 常见问题

- 无法执行：重新运行 `chmod +x mycodex-relay *.command`，并检查 macOS 隐私与安全性设置。
- 无法启动：检查 `relay.err.log`，并确认端口未被其他程序占用。
- `connection_unavailable`：确认主机已连接 Relay，手机能够访问所填地址和端口。
- HTTP 401：检查租户 ID、访问密钥以及密钥是否被轮换。
- Relay identity mismatch：确认没有删除身份私钥，也没有把地址切换到另一台 Relay。
- 外部设备无法连接：检查监听地址、防火墙、路由器转发、TLS 和 WebSocket 反向代理。
