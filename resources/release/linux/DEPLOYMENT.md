# MyCodex Relay Linux 部署说明

本文适用于 `linux-x64` 和 `linux-arm64` 发布包。正式公网服务推荐使用 Ubuntu 22.04/24.04 或 Debian 12，并通过包内的 `deploy-relay.sh` 部署。

Docker 部署使用仓库根目录的 `Dockerfile`、`compose.yaml` 和 `docker/README.md`。
本文的一键脚本只自动管理 Ubuntu/Debian 上的二进制服务，避免用未经验证的流程修改其他发行版。

## 1. 选择正确的包

在服务器运行：

```bash
uname -m
```

| 输出 | 发布包 |
| --- | --- |
| `x86_64`、`amd64` | `linux-x64` |
| `aarch64`、`arm64` | `linux-arm64` |

当前不提供 32 位 `i386`/`x86` 发布包。

## 2. 部署前准备

需要：

1. 一台具有公网 IPv4 或 IPv6 地址的 Linux 服务器。
2. 一个域名，例如 `relay.example.com`。
3. 域名的 A/AAAA 记录已经指向服务器。
4. 云防火墙和系统防火墙允许 TCP 80、443。
5. 可以使用 `sudo` 的 SSH 账号。
6. 与服务器架构匹配的 Relay 发布包。

先确认 DNS：

```bash
getent hosts relay.example.com
```

不要把腾讯云、Cloudflare 或其他 DNS 服务的长期主账号密钥复制进命令、日志或部署文档。需要 AI 修改 DNS 时，应使用仅允许修改目标域名记录的临时或最小权限凭据。

## 3. Ubuntu/Debian 一键部署

解压发布包后，把其中的程序和脚本上传到服务器：

```bash
scp mycodex-relay deploy-relay.sh ubuntu@server:/tmp/mycodex-relay/
```

登录服务器并执行：

```bash
ssh ubuntu@server
cd /tmp/mycodex-relay
chmod +x mycodex-relay deploy-relay.sh
sudo ./deploy-relay.sh install \
  --domain relay.example.com \
  --email admin@example.com \
  --tenant-name Production
```

脚本会：

1. 安装 Nginx、Certbot、CA 证书和 `curl`。
2. 创建不可登录的 `mycodex-relay` 系统账号。
3. 安装 Relay 到 `/opt/mycodex-relay`。
4. 将配置写入 `/etc/mycodex-relay/relay-config.json`。
5. 将数据库和服务身份保存在 `/var/lib/mycodex-relay`。
6. 创建并启用加固后的 systemd 服务。
7. 配置 Nginx WebSocket 反向代理。
8. 申请并自动续期 Let's Encrypt 证书。
9. 创建第一个租户并验证健康检查和元数据端点。
10. 输出机器可读的连接 JSON。

脚本不会覆盖不是由它管理的同名 Nginx 站点。检测到已有配置使用其他域名或未声明公网 TLS 时，也会停止并报告错误。

首次创建租户时，输出中的 `secret.value` 只显示一次。立即把完整 JSON 保存到安全位置；Relay 数据库只保存访问密钥的哈希，之后无法读取原密钥。

## 4. 导入 Windows 客户端

部署成功后的 JSON 包含：

```json
{
  "relayHost": "relay.example.com",
  "relayPort": 443,
  "tlsRequired": true,
  "tenants": [
    {
      "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "displayName": "Production",
      "enabled": true
    }
  ],
  "secret": {
    "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "value": "一次性显示的访问密钥",
    "source": "created"
  }
}
```

在 MyCodex Windows 客户端的“服务器设置”中选择独立公网服务器，然后使用“导入服务器信息”粘贴完整 JSON。也可以手工填写：

| 客户端字段 | JSON 字段 |
| --- | --- |
| 对外访问地址 | `relayHost` |
| 端口 | `relayPort` |
| 使用 TLS | `tlsRequired` |
| 租户 ID | `secret.tenantId`；没有 `secret` 时使用唯一启用租户的 `tenantId` |
| 访问密钥 | `secret.value` |

公开元数据不会泄露租户或访问密钥：

```bash
curl https://relay.example.com/.well-known/mycodex-relay
curl https://relay.example.com/health
```

## 5. 再次查看服务器信息

```bash
sudo /opt/mycodex-relay/mycodex-relay info \
  --config /etc/mycodex-relay/relay-config.json \
  --json
```

也可以在新版发布包目录运行：

```bash
sudo ./deploy-relay.sh info
```

已有租户的信息不会包含原访问密钥。如果密钥遗失，必须轮换：

```bash
sudo /opt/mycodex-relay/mycodex-relay tenant rotate-secret \
  --config /etc/mycodex-relay/relay-config.json \
  --tenant xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

轮换后旧密钥立即失效，需要在 Windows 客户端保存新密钥。

## 6. 升级

上传新版 `mycodex-relay` 和 `deploy-relay.sh`，然后运行：

```bash
chmod +x mycodex-relay deploy-relay.sh
sudo ./deploy-relay.sh upgrade --binary ./mycodex-relay
```

升级只替换程序并重启服务，不覆盖配置、数据库、租户或 Relay 身份。

验证：

```bash
systemctl status mycodex-relay --no-pager
curl https://relay.example.com/health
curl https://relay.example.com/.well-known/mycodex-relay
```

## 7. 备份与恢复

需要备份：

```text
/etc/mycodex-relay/relay-config.json
/var/lib/mycodex-relay/relay-state.db
/var/lib/mycodex-relay/relay-state.db.identity.pk8
```

身份私钥与数据库必须作为一组备份。丢失身份私钥会改变 Relay 签名指纹，已保存旧身份的客户端会拒绝连接。

一致性备份：

```bash
sudo systemctl stop mycodex-relay
sudo tar -C / -czf mycodex-relay-backup.tar.gz \
  etc/mycodex-relay \
  var/lib/mycodex-relay
sudo systemctl start mycodex-relay
```

恢复时先停止服务，恢复原路径和权限，再启动服务：

```bash
sudo chown -R mycodex-relay:mycodex-relay /var/lib/mycodex-relay
sudo chown root:mycodex-relay /etc/mycodex-relay/relay-config.json
sudo chmod 0640 /etc/mycodex-relay/relay-config.json
sudo systemctl restart mycodex-relay
```

## 8. 日志和故障诊断

查看 Relay：

```bash
sudo journalctl -u mycodex-relay -n 200 --no-pager
sudo journalctl -u mycodex-relay -f
```

查看 Nginx 和证书：

```bash
sudo nginx -t
sudo systemctl status nginx --no-pager
sudo certbot renew --dry-run
```

常见问题：

- `connection_unavailable`：检查 Windows 主机通道、手机网络、443 端口和 WebSocket 代理头。
- HTTP 401：检查租户 ID、访问密钥以及密钥是否刚被轮换。
- Relay identity mismatch：确认没有删除或替换 `relay-state.db.identity.pk8`，也没有把域名指向另一台 Relay。
- CLI 显示错误协议：公网由 Nginx 提供 HTTPS 时，配置必须包含 `"publicTls": true`。
- 证书申请失败：先确认 DNS 已生效，且 TCP 80、443 能从公网访问。

## 9. 让 AI 完成部署

可以把以下任务交给具有终端和 SSH 能力的 AI：

```text
请部署 MyCodex Relay：
1. 只使用我指定的服务器和域名，不修改其他服务。
2. 检查 CPU 架构、系统版本、DNS、80/443 端口占用和现有 Nginx 配置。
3. 上传匹配架构的 mycodex-relay 与 deploy-relay.sh。
4. 执行一键部署脚本，不覆盖无关 Nginx 站点。
5. 验证 systemd、Nginx、证书、/health 和 /.well-known/mycodex-relay。
6. 返回完整连接 JSON；不要把访问密钥写入日志、仓库或聊天之外的文件。
7. 如果服务器已有同名服务、配置或数据库，先停止并向我说明，不要直接覆盖。
```

AI 仍应遵守两个边界：

1. DNS、云防火墙和云账号权限属于外部系统；没有明确授权和最小权限凭据时只能检查，不能猜测或越权修改。
2. 删除服务、轮换密钥、覆盖数据库和恢复备份都是高影响操作，必须由用户明确确认。
