# MyCodex Relay 发布包

MyCodex Relay 为 MyCodex Windows 主机与移动设备提供认证、配对和加密消息转发。业务消息在 Windows 与移动设备之间端到端加密。

## 包内文件

- `mycodex-relay` 或 `mycodex-relay.exe`：当前平台的 Relay 服务程序。
- `DEPLOYMENT.md`：当前平台专用的安装、启动、升级和故障诊断说明。
- `VERSION.txt`：本发布包的版本。
- 其余 `.sh`、`.bat`、`.vbs` 或 `.command` 文件：当前平台的部署和管理脚本。

请先阅读同目录的 `DEPLOYMENT.md`，不要直接套用其他平台的命令。

## 平台包

- `windows-x64`：64 位 Windows。
- `linux-x64`：`x86_64` 或 `amd64` Linux。
- `linux-arm64`：`aarch64` 或 `arm64` Linux。
- `macos-intel`：Intel 芯片 Mac。
- `macos-apple-silicon`：M1、M2、M3、M4 等 Apple 芯片 Mac。

## 安全提示

- 首次创建租户时，访问密钥只显示一次，请立即保存到安全位置。
- 不要把访问密钥、云平台密钥、私钥或完整连接 JSON 写入日志或代码仓库。
- Relay 数据库与身份私钥必须一起备份；丢失身份私钥会改变 Relay 签名指纹。
- 使用公网服务时必须启用可信 TLS，并限制管理文件的访问权限。

如果文件来自下载，请先使用发布页提供的 `SHA256SUMS.txt` 验证归档完整性。
