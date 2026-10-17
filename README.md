<div align="center">

<img src="assets/logo.png" alt="ghostpipe" width="200"/>

# ghostpipe

**自研二进制协议的轻量内网隧道工具**

[![CI](https://github.com/Cypewake/ghostpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/Cypewake/ghostpipe/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Cypewake/ghostpipe)](https://github.com/Cypewake/ghostpipe/releases)
[![Stars](https://img.shields.io/github/stars/Cypewake/ghostpipe?style=social)](https://github.com/Cypewake/ghostpipe/stargazers)

`Go 1.26` · 零第三方依赖 · 单二进制跨平台 · 全链路中文文档 · [**English**](README_EN.md)

</div>

---

> ## ⚠️ 合规声明
>
> 本工具**仅限授权测试与自用远程访问**（如：管理自己的服务器、红队授权项目内的隧道搭建教学）。
> 纯流量转发，无任何攻击性功能；不内置凭据窃取、持久化、反取证能力。
> 与 frp / rathole 属同类工具，请遵守所在地法律法规，未授权环境禁止使用。

---

## 1. 这是什么

ghostpipe 是一个 frp 同类的内网穿透工具，核心差异：**传输协议 100% 自研**——从帧格式、双向认证、流控到多路复用，全部从头设计并实现，目的是完整走一遍"自定义应用层隧道协议"的设计全链路（设计 → 对抗式评审 → 实现 → 测试 → 发布）。

```
外部用户 ──► VPS:10022 (server 映射端口)
                │ ghostpipe-server
                │ 控制连接(信令) + 数据通道(Stream)
                ▼
      内网 ghostpipe-client ──► localhost:22
```

- **两个二进制**：`ghostpipe-server`（公网 VPS 侧）、`ghostpipe-client`（内网机器，主动出网，无需公网 IP / 无需开入站端口）。
- **四种工作模式**，同一套帧协议：

| 模式 | 名称 | 说明 |
|---|---|---|
| M1 | `conn` | 每个转发会话一条独立数据连接（DATA_BIND 令牌绑定） |
| M2 | `mux` | 单连接多路复用 + 双层信用流控（默认模式） |
| M3 | `-ws` | WebSocket 载体（零依赖手写 RFC 6455 子集），可过 nginx 反代部署形态 |
| M4 | `-socks5` | SOCKS5 动态代理，**双向**：客户端本地入口（经隧道由服务端出网）/ 服务端入口（经隧道由**客户端内网**拨号，= frp socks5 插件等价能力） |

## 2. 快速开始

### 安装

```bash
# 方式一：go install（需 Go 1.26+）
go install github.com/Cypewake/ghostpipe/cmd/server@latest
go install github.com/Cypewake/ghostpipe/cmd/client@latest

# 方式二：Releases 下载预编译二进制（linux / windows / macOS，amd64 / arm64）
# https://github.com/Cypewake/ghostpipe/releases

# 方式三：源码构建
go build -o bin/ ./cmd/...
```

### 生成密钥

```bash
# 生成 64 位 hex PSK（32 字节）
openssl rand -hex 32
```

### 服务端（公网 VPS）

```bash
./ghostpipe-server -listen 0.0.0.0:9000 -psk <64位hex>
# 启动日志会打印自签证书 SPKI 指纹，复制给客户端
```

### 客户端（内网机器）

```bash
# 端口转发：VPS 的 10022 → 内网 22，10080 → 内网 80
./ghostpipe-client -server vps.example.com:9000 \
    -psk <64位hex> \
    -fingerprint <服务端SPKI指纹> \
    -tunnel "10022=127.0.0.1:22,10080=127.0.0.1:80"

# 从外部验证
ssh -p 10022 user@vps.example.com
curl http://vps.example.com:10080
```

### SOCKS5 动态代理（mux 模式，双向）

```bash
# 方向一：客户端本地入口 —— 内网机器借道 VPS 出网（frp 没有的反向能力）
./ghostpipe-client -server vps:9000 -psk <hex> -fingerprint <fp> \
    -mode mux -socks5 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://example.com/   # 从 VPS 侧出网

# 方向二：服务端入口 —— 外部经代理访问客户端所在内网任意设备（frp socks5 插件等价）
./ghostpipe-server -listen 0.0.0.0:9000 -psk <hex> -socks5 0.0.0.0:1080
# 客户端正常连接后（无需任何额外配置）：
curl --socks5-hostname vps:1080 http://192.168.1.20:8080/   # 访问客户端内网设备
```

方向二即"代理工具访问内网"用法：把 VPS 的 `1080` 配进浏览器/proxychains，流量穿透隧道后由**客户端在其内网发起连接**——内网任何可达的 `IP:端口` 都能访问，等价于 frp 的 socks5 插件。

### WebSocket 载体（过 nginx 反代）

```bash
# 两端都加 -ws；nginx 对 /ghostpipe 路径做普通 HTTP 升级转发即可
./ghostpipe-server -listen 0.0.0.0:9000 -psk <hex> -ws
./ghostpipe-client -server vps:9000 -psk <hex> -fingerprint <fp> -ws \
    -tunnel "10022=127.0.0.1:22"
```

> 明文实验模式：两端同时加 `-insecure-tls`（免指纹，启动打印醒目警告），仅限本地实验。

## 3. 协议规范（摘要）

### 帧格式（13 字节定长帧头 + Payload，大端）

```
+--------+-----+------+-------+-----------+----------------+
| Magic  | Ver | Type | Flags | StreamID  | Length         |
| 2B     | 1B  | 1B   | 1B    | 4B        | 4B             |
| 0x4750 | 会话 | 见下 | 恒0   | 流标识    | 仅计Payload    |
+--------+-----+------+-------+-----------+----------------+
Payload ≤ 16KB；Length 先校验后分配（防恶意预分配耗尽内存）
```

### 信令类型

| Type | 名称 | 方向 | 用途 |
|---|---|---|---|
| 0x01-0x03 | AUTH_REQ/RESP/OK | S→C→S→C | 双向 HMAC-SHA256 质询应答（PSK，防重放） |
| 0x04 | DATA_BIND | C→S | M1 数据连接令牌绑定 |
| 0x10-0x12 | REGISTER/OK/UNREGISTER | C→S/S→C/C→S | 隧道注册 / 注销（同端口原子替换） |
| 0x20 | OPEN | S→C | 请求客户端建立转发流（M1 带 port+token；M2 带 port） |
| 0x22 | OPEN_ADDR | 双向 | SOCKS5 动态目标开流：发起方=代理入口侧，接收方在己侧拨号出网 |
| 0x30 | DATA | 双向 | 透传字节 |
| 0x31 | CREDIT | 双向 | 流量信用窗口补充 |
| 0x40 | CLOSE | 双向 | 关闭流 |
| 0x50 | ERROR | 双向 | 8 种错误码回传 |
| 0x60/0x61 | PING/PONG | 双向 | 心跳 |

完整规范（含流控规则、生命周期、全部错误码）见 [docs/设计文档.md](docs/设计文档.md)。

## 4. 安全设计

| 威胁 | 对策 |
|---|---|
| 被动嗅探 | TLS 1.3 默认开启 |
| 主动中间人 | 自签证书 + **SPKI 指纹 pinning 强制**（未配置拒绝连接，无静默降级） |
| 恶意服务端冒充 | 客户端校验服务端 HMAC（双向认证，非仅单向） |
| 恶意客户端 | 认证闸门 + 10s 握手时限 + 全资源上限 + Length 先校验后分配 |
| 资源耗尽（慢连接 / 流风暴 / 僵尸连接） | 握手时限 + 流≤256/连接 + 令牌≤64 + TCP keepalive 探死 |
| 重放攻击 | nonce 单次使用（CSPRNG，内存消费集合） |

## 5. 作品集映射（安全岗）

| ATT&CK 技术 | 对应实现 |
|---|---|
| T1572 协议隧道 | 自定义帧协议全双工隧道 |
| T1090 代理 | SOCKS5 动态代理（双向：服务端入口访问内网 / 客户端入口借道出网） |
| T1095 非应用层协议 | 自定义二进制协议（非 HTTP 语义） |
| T1071.001 Web 协议 | M3 WebSocket 载体形态 |

## 6. 构建与测试

```bash
go build -o bin/ ./cmd/...   # 编译三个二进制（server / client / filesrv 测试靶）
go vet ./...                 # 静态检查
go test ./... -v             # 单元测试（协议/认证/传输/多路复用 4 包）

bash verify-all.sh           # 端到端回归：6 场景 11 项断言（mux/conn/SOCKS5/WS/断线重连/坏密钥负路径）
```

`verify-all.sh` 覆盖：正向转发 ×4 模式、进程击杀后自动重连与端口恢复、错误 PSK 拒绝认证、日志语义探针防网络轮询误判。

## 7. 目录结构

```
ghostpipe/
├── cmd/
│   ├── server/       # 服务端入口
│   ├── client/       # 客户端入口
│   └── filesrv/      # 测试用文件服务器（验证脚本靶标）
├── internal/
│   ├── protocol/     # 帧编解码 + 信令 Payload + 错误码（含 fuzz 用例）
│   ├── auth/         # 双向 HMAC 质询应答
│   ├── transport/    # 连接封装 / TLS pinning / WebSocket 载体
│   ├── stream/       # Stream 接口 + ConnStream + 双向泵
│   ├── mux/          # 多路复用 + 双层信用流控
│   ├── socks5/       # SOCKS5 入口（无认证 + CONNECT）
│   ├── server/       # 会话管理 / 隧道注册 / 端口归属表 / 心跳
│   └── client/       # 重连循环 / 隧道处理 / 优雅退出
├── docs/
│   ├── 设计文档.md    # 协议设计定稿（两轮对抗式评审 + 实现偏差记录）
│   └── 开发文档.md    # 实现讲解：模块细节、关键决策、踩坑实录
├── assets/logo.png
└── verify-all.sh     # 一键端到端回归
```

## 8. 文档索引

- [docs/设计文档.md](docs/设计文档.md) —— 协议设计 v3 定稿：帧协议 / 认证 / 流控 / 生命周期 / 威胁模型，含两轮对抗式评审记录（40 条发现全部折入）与实现偏差追溯。
- [docs/开发文档.md](docs/开发文档.md) —— 实现讲解：逐模块代码结构、关键并发决策（单写者队列为何必须）、测试策略、踩坑实录（真死锁复现与修复）。

## 许可

MIT
