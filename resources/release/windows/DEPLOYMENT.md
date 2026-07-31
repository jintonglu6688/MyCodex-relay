# MyCodex Relay Windows 使用说明

本文适用于 `windows-x64` 发布包。普通 MyCodex 用户应优先使用 Windows 客户端内置的远程服务；本独立发布包主要用于本地测试、局域网、自托管验证和问题诊断。

正式公网服务推荐使用 Linux 发布包。Windows 发布包不会自动配置 Windows 服务、可信 TLS 证书、证书续期、防火墙或 WebSocket 反向代理。

## 1. 系统要求与包内文件

- 64 位 Windows 10、Windows 11 或 Windows Server。
- `mycodex-relay.exe`：Relay 服务。
- `start-relay.bat`：后台启动。
- `start-relay-silent.vbs`：无控制台窗口启动器。
- `show-relay-info.bat`：初始化本地配置并显示连接 JSON。
- `stop-relay.bat`：停止本机所有 `mycodex-relay.exe` 进程。

请把发布包完整解压到普通用户可写目录，不要直接在压缩包预览窗口中运行脚本。

## 2. 快速启动

双击或在命令提示符运行：

```bat
start-relay.bat
```

首次启动会自动创建：

```text
relay-config.json
relay-state.db
relay-state.db.identity.pk8
relay.out.log
relay.err.log
```

查看服务器信息并确保存在名为 `Local` 的租户：

```bat
show-relay-info.bat
```

首次创建租户时，输出中的访问密钥只显示一次，请立即保存。数据库只保存访问密钥的哈希，之后无法读取原密钥。

停止服务：

```bat
stop-relay.bat
```

注意：该脚本会停止当前 Windows 系统中的所有 `mycodex-relay.exe` 进程。

## 3. 配置文件选择

脚本按以下顺序选择配置：

1. 命令行明确传入的配置文件。
2. 当前目录中的 `relay-config.local.json`。
3. 当前目录中的 `relay-config.json`。

使用自定义配置：

```bat
start-relay.bat my-relay.json
show-relay-info.bat my-relay.json
```

自定义配置会使用同名数据库，例如 `my-relay.json` 对应 `my-relay.db`。

## 4. 日志和运行状态

标准输出和错误日志位于：

```text
relay.out.log
relay.err.log
```

查看进程：

```powershell
Get-Process mycodex-relay
```

查看版本：

```powershell
.\mycodex-relay.exe version
```

读取机器可用的服务器信息：

```powershell
.\mycodex-relay.exe info --config .\relay-config.json --json
```

已有租户的信息不会包含原访问密钥。密钥遗失时需要显式轮换：

```powershell
.\mycodex-relay.exe tenant rotate-secret `
  --config .\relay-config.json `
  --tenant xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

轮换后旧密钥立即失效。

## 5. 局域网或公网使用

默认配置主要用于本机测试。允许其他设备访问前，需要同时确认：

1. Relay 监听地址不是仅限回环地址。
2. Windows 防火墙允许配置的 Relay 端口。
3. 客户端使用的主机名或 IP 与实际访问路径一致。
4. 公网访问使用可信 TLS。
5. 路由器端口转发、反向代理和 WebSocket 头配置正确。
6. 配置中的公网主机、端口和 `publicTls` 与实际入口一致。

公网环境不要直接暴露未加密 HTTP。Windows 包没有自动申请或续期证书的脚本；如果需要长期公网服务，请使用 Linux 包，或者自行维护 Windows 服务、TLS 终止和反向代理。

## 6. 备份

至少备份：

```text
relay-config.json
relay-state.db
relay-state.db.identity.pk8
```

如果使用自定义配置和数据库，请备份对应文件。备份前先停止 Relay，数据库与身份私钥必须作为一组保存。

丢失或替换 `*.identity.pk8` 会改变 Relay 签名指纹，已经信任旧身份的客户端会拒绝连接。

## 7. 常见问题

- 无法启动：检查 `relay.err.log`，并确认端口未被其他程序占用。
- `connection_unavailable`：确认 Windows 主机已连接 Relay，手机能够访问所填地址和端口。
- HTTP 401：检查租户 ID、访问密钥以及密钥是否被轮换。
- Relay identity mismatch：确认没有删除身份私钥，也没有把地址切换到另一台 Relay。
- 外部设备无法连接：检查监听地址、Windows 防火墙、路由器转发、TLS 和 WebSocket 反向代理。
