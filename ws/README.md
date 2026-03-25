# Lightway WebSocket 部署指南

将 Lightway VPN 流量封装在 WebSocket 中，使其看起来像普通的 HTTPS/WebSocket 应用流量，用于对抗 DPI 深度包检测。

## 架构

```
客户端                           服务端
┌──────────────┐            ┌─────────────────────────────────┐
│ lightway     │  WS / TLS  │  nginx/caddy ──► lightway-server │
│  client      │ ◄────────► │  (TLS终止+WS代理)  (--websocket)  │
│ --websocket  │            │  :443              :9443          │
│ --ws_tls     │            │                                   │
└──────────────┘            └─────────────────────────────────┘
```

**数据流：**
1. 客户端通过外层 TLS（`ws_tls: true`）连接到 nginx/caddy 的 443 端口
2. 外层 TLS 由 nginx/caddy 终止（可挂真实网站伪装）
3. nginx/caddy 将 WebSocket 连接以纯 HTTP 代理到 lightway-server
4. lightway-server（`--websocket` 模式）直接接收 WebSocket 帧并解包
5. lightway 内层 TLS（`ca_cert` / `server_dn`）在 WebSocket 内部提供 VPN 加密

**无需额外桥接工具**——lightway-server 内置 WebSocket 支持。

## 快速开始

### 方法一：自动化脚本（推荐）

```bash
# nginx 方案
sudo bash setup.sh --proxy nginx --domain vpn.example.com --ws-path /api

# caddy 方案（自动 HTTPS）
sudo bash setup.sh --proxy caddy --domain vpn.example.com --ws-path /api

# 卸载
sudo bash uninstall.sh          # 保留证书
sudo bash uninstall.sh --purge  # 彻底清除
```

### 方法二：Docker Compose

```bash
# nginx 方案
cd nginx && docker compose up -d

# caddy 方案
cd caddy && docker compose up -d
```

### 方法三：手动部署

参见下方各配置文件的详细说明。

## 文件说明

```
ws/
├── README.md               # 本文档
├── setup.sh                # 自动化部署脚本（裸机）
├── uninstall.sh            # 卸载脚本
├── example/
│   ├── client/
│   │   ├── config.yml      # 客户端配置示例
│   │   └── ca.crt          # CA 证书（客户端用）
│   └── server/
│       ├── config.yml      # 服务端配置示例
│       ├── server_start.sh # 服务端启动脚本（配置 TUN/iptables）
│       ├── server.crt      # 服务端证书
│       ├── server.key      # 服务端私钥
│       ├── ca.crt / ca.key # CA 证书/私钥
│       └── lwpasswd        # 用户密码文件
├── nginx/
│   ├── lightway-ws.conf    # nginx 站点配置模板
│   └── docker-compose.yml  # nginx + lightway-server
└── caddy/
    ├── Caddyfile           # Caddy 配置模板
    └── docker-compose.yml  # caddy + lightway-server
```

## 手动部署步骤

### 1. 生成证书和用户数据库

```bash
# 生成 CA 证书
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout ca.key -out ca.crt -nodes -days 3650 -subj '/CN=RapidSSL TLS RSA CA G1'

# 生成服务端证书（CN 必须匹配客户端 server_dn）
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout server.key -out server.csr -nodes -subj '/CN=*.ixigua.com'
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 3650

# 生成用户密码文件
htpasswd -bcB lwpasswd user password
```

### 2. 启动服务端

将证书文件和 `lwpasswd` 放到服务器上（例如 `/etc/lightway/`），创建配置文件 `server_config.yaml`：

```yaml
---
bind_address: 0.0.0.0:9443
mode: tcp
websocket: true
ws_path: "/api"
server_cert: "/etc/lightway/server.crt"
server_key: "/etc/lightway/server.key"
user_db: "/etc/lightway/lwpasswd"
tun_name: lightway
ip_pool: 10.125.0.0/16
tun_ip: 10.125.0.1
lightway_server_ip: 169.254.10.1
lightway_client_ip: 169.254.10.2
lightway_dns_ip: 169.254.10.5
log_level: info
log_format: full
enable_pqc: false
enable_expresslane: false
enable_tun_iouring: false
iouring_entry_count: 1024
key_update_interval: 15m
udp_buffer_size: 15 MiB
```

使用 `server_start.sh` 启动（会自动配置 TUN 接口、IP 转发和 iptables）：

```bash
sudo ./server_start.sh /etc/lightway/server_config.yaml
```

或通过 `setup.sh` 部署为 systemd 服务，脚本会自动处理。

验证服务端已监听：

```bash
ss -tlnp | grep 9443
```

### 3. 部署反向代理

使用自动化脚本：

```bash
sudo bash setup.sh --proxy nginx --domain vpn.example.com --ws-path /api
```

或手动配置 nginx/caddy，参考 `nginx/lightway-ws.conf` 或 `caddy/Caddyfile`。

### 4. 启动客户端

将 `ca.crt` 拷贝到客户端，创建配置文件 `client_config.yaml`：

**通过反向代理连接（推荐）：**

```yaml
---
server: "vpn.example.com:443"
mode: tcp
websocket: true
ws_path: "/api"
ws_tls: true
ws_host: "vpn.example.com"
ca_cert: "/path/to/ca.crt"
server_dn: ixigua.com
user: user
password: password
tun_name: lightway
tun_local_ip: 100.64.0.6
tun_peer_ip: 100.64.0.5
tun_dns_ip: 100.64.0.1
outside_mtu: 1500
cipher: aes256
log_level: info
enable_pqc: false
enable_tun_iouring: false
iouring_entry_count: 1024
keepalive_interval: 10s
keepalive_timeout: 30s
keepalive_continuous: true
enable_expresslane: false
enable_pmtud: false
route_mode: default
dns_config_mode: noexec
```

**直连模式（不经过反代）：**

```yaml
---
server: "vpn.example.com:9443"
mode: tcp
websocket: true
ws_path: "/api"
# ws_tls: false  (默认值，不需要外层 TLS)
ca_cert: "/path/to/ca.crt"
server_dn: ixigua.com
user: user
password: password
# ... 其他配置同上
```

启动命令：

```bash
sudo lightway-client --config-file /path/to/client_config.yaml
```

### 5. 验证连接

```bash
# 检查 TUN 接口
ip addr show lightway

# 测试隧道连通
ping 169.254.10.1

# 测试 DNS（如果 route_mode 为 default）
curl ifconfig.me
```

## 关键配置说明

### 两层 TLS

| | 外层 TLS（`ws_tls`） | 内层 TLS（`ca_cert` / `server_dn`） |
|--|--|--|
| **用途** | 伪装成 HTTPS 流量 | VPN 隧道加密 |
| **证书** | Let's Encrypt（nginx/caddy 自动管理） | 自签名（openssl 生成） |
| **域名** | 真实域名（`ws_host`），需 DNS 解析到服务器 | 任意值（`server_dn`），与服务端证书 CN 匹配即可 |
| **终止点** | nginx/caddy | lightway-server |

### ws_tls 选项

- `ws_tls: true` — 连接到反向代理的 443 端口时**必须开启**，否则 nginx 收到明文 HTTP 会返回 400
- `ws_tls: false`（默认） — 直连 lightway-server 时使用，无需外层 TLS

### 注意事项

- **证书 CN 一致**：服务端证书的 CN（如 `*.ixigua.com`）必须和客户端配置的 `server_dn` 匹配
- **ws_path 一致**：客户端、nginx/caddy、lightway-server 三端的 `ws_path` 必须完全相同
- **权限**：两端都需要 root 权限（创建 TUN 设备需要 `CAP_NET_ADMIN`）

## 前置条件

- 一台有公网 IP 的服务器
- 一个解析到该服务器的域名（用于申请 Let's Encrypt TLS 证书）
- `lightway-server` 和 `lightway-client` 二进制（均需包含 WebSocket 支持）
- 已生成 CA 证书和服务端证书

## 安全建议

1. **伪装网站**：在 nginx/caddy 的根路径挂一个正常的静态网站，只有特定 path 走 WebSocket 代理
2. **修改 ws_path**：不要使用默认的 `/ws`，换成随机路径如 `/app/v2/stream`
3. **CDN 中转**：可以通过 Cloudflare 等 CDN 中转 WebSocket 流量，进一步隐藏服务器 IP
