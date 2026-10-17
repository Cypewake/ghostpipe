<div align="center">

<img src="assets/logo.png" alt="ghostpipe" width="200"/>

# ghostpipe

**A lightweight tunnel tool built on a fully custom binary protocol**

[![CI](https://github.com/Cypewake/ghostpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/Cypewake/ghostpipe/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Cypewake/ghostpipe)](https://github.com/Cypewake/ghostpipe/releases)
[![Stars](https://img.shields.io/github/stars/Cypewake/ghostpipe?style=social)](https://github.com/Cypewake/ghostpipe/stargazers)

`Go 1.26` · Zero dependencies · Single binary · Cross-platform

**[中文文档](README.md)**

</div>

---

> ## ⚠️ Compliance Notice
>
> For **authorized testing and self-hosted remote access only** (e.g., managing your own servers, tunnel-building education in authorized red-team engagements).
> Pure traffic forwarding — no offensive capability built in; no credential theft, persistence, or anti-forensics.
> Same category as frp / rathole. Comply with local laws; never use against unauthorized environments.

---

## 1. What is this

ghostpipe is an frp-like reverse tunnel tool. The difference: **the wire protocol is 100% custom** — frame format, mutual authentication, flow control and multiplexing are all designed and implemented from scratch. The goal is to walk through the entire lifecycle of "designing a custom application-layer tunnel protocol": design → adversarial review → implementation → testing → release.

```
External user ──► VPS:10022 (server mapped port)
                │ ghostpipe-server
                │ control connection (signaling) + data channel (Stream)
                ▼
      intranet ghostpipe-client ──► localhost:22
```

- **Two binaries**: `ghostpipe-server` (public VPS), `ghostpipe-client` (intranet host, outbound-only — no public IP or inbound port needed).
- **Four working modes**, one frame protocol:

| Mode | Flag | Description |
|---|---|---|
| M1 | `-mode conn` | One independent data connection per session (DATA_BIND token binding) |
| M2 | `-mode mux` | Single-connection multiplexing + two-layer credit-based flow control (default) |
| M3 | `-ws` | WebSocket carrier (hand-written RFC 6455 subset, zero deps) — passes nginx reverse proxies |
| M4 | `-socks5` | SOCKS5 dynamic proxy, **bidirectional** (see below) |

## 2. Quick Start

### Install

```bash
# From source
go install github.com/Cypewake/ghostpipe/cmd/server@latest
go install github.com/Cypewake/ghostpipe/cmd/client@latest

# Or grab a prebuilt binary from Releases (linux/windows/macOS, amd64/arm64)
```

### Generate a key

```bash
openssl rand -hex 32   # 32-byte PSK (64 hex chars)
```

### Server (public VPS)

```bash
./ghostpipe-server -listen 0.0.0.0:9000 -psk <64-hex-psk>
# Startup log prints the self-signed cert SPKI fingerprint — give it to clients
```

### Client (intranet host)

```bash
# Port forwarding: VPS:10022 → intranet 22, VPS:10080 → intranet 80
./ghostpipe-client -server vps.example.com:9000 \
    -psk <64-hex-psk> \
    -fingerprint <server-SPKI-fingerprint> \
    -tunnel "10022=127.0.0.1:22,10080=192.168.1.10:80"

# Verify from outside
ssh -p 10022 user@vps.example.com
curl http://vps.example.com:10080
```

### SOCKS5 dynamic proxy (mux mode, bidirectional)

```bash
# Direction A: client-side entry — intranet host egresses via the VPS
./ghostpipe-client -server vps:9000 -psk <hex> -fingerprint <fp> \
    -mode mux -socks5 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://example.com/

# Direction B: server-side entry — reach ANY device on the client's intranet
# through the proxy (equivalent of frp's socks5 plugin)
./ghostpipe-server -listen 0.0.0.0:9000 -psk <hex> -socks5 0.0.0.0:1080
# With the client connected (no extra config needed):
curl --socks5-hostname vps:1080 http://192.168.1.20:8080/
```

### WebSocket carrier (through nginx)

```bash
# Add -ws on both ends; nginx just forwards the /ghostpipe upgrade request
./ghostpipe-server -listen 0.0.0.0:9000 -psk <hex> -ws
./ghostpipe-client -server vps:9000 -psk <hex> -fingerprint <fp> -ws \
    -tunnel "10022=127.0.0.1:22"
```

> Plaintext lab mode: add `-insecure-tls` on **both** ends (local experiments only).

## 3. Protocol (summary)

Frame: 13-byte fixed header + payload, big-endian:

```
| Magic 2B (0x4750) | Ver 1B | Type 1B | Flags 1B | StreamID 4B | Length 4B |
Payload ≤ 16KB; Length is validated BEFORE allocation (anti memory-exhaustion)
```

Key signaling: `AUTH_REQ/RESP/OK` (mutual HMAC-SHA256 challenge-response over PSK), `DATA_BIND` (one-time 32B token), `REGISTER/UNREGISTER` (atomic port takeover), `OPEN / OPEN_ADDR` (server- and client-initiated streams), `DATA/CREDIT` (two-layer credit window: 256KB per stream + 1MB per connection), `CLOSE/ERROR/PING/PONG`.

Full spec (flow-control rules, lifecycle, all 8 error codes): [docs/设计文档.md](docs/设计文档.md) (Chinese).

## 4. Security Design

| Threat | Mitigation |
|---|---|
| Passive sniffing | TLS 1.3 by default |
| Active MITM | Self-signed cert + **mandatory SPKI pinning** (refuses to connect without fingerprint; no silent downgrade) |
| Malicious server impersonation | Client verifies server's HMAC (true mutual auth) |
| Malicious client | Auth gate + 10s handshake deadline + all-resource caps + validate-before-allocate |
| Resource exhaustion (slowloris / stream floods / zombies) | Handshake deadline + ≤256 streams/conn + ≤64 pending tokens + TCP keepalive |
| Replay | Single-use CSPRNG nonces (in-memory consumed set) |

## 5. Build & Test

```bash
go build -o bin/ ./cmd/...
go vet ./...
go test ./... -v

bash verify-all.sh   # E2E regression: 7 scenarios / 13 assertions, all green
```

Scenarios: mux / conn / SOCKS5 (both directions) / WebSocket / kill-9 reconnect with atomic port takeover / wrong-PSK negative path.

## 6. Why it's interesting (for reviewers)

- **Custom binary protocol** end to end: framing, versioning, signaling, error codes.
- **Mutual HMAC + SPKI pinning**: server always sends the first challenge (eliminates a peek-frame race); client verifies the server — protects against malicious endpoints, not just malicious clients.
- **Two-layer credit flow control** with per-stream backpressure; control frames exempt from windows (deadlock-free by construction).
- **Single-writer queue concurrency**: a real 20-stream deadlock under `net.Pipe` backpressure was reproduced, root-caused and fixed — documented in the dev log.
- **Adversarial design review**: two rounds, 40 findings, all folded into the spec with a public change trail.
- Full Chinese documentation: [design doc](docs/设计文档.md) + [implementation deep-dive](docs/开发文档.md) with a post-mortem table.

## 7. Documentation

- [docs/设计文档.md](docs/设计文档.md) — protocol spec v3 (frame format / auth / flow control / lifecycle / threat model / two-round adversarial review trail / implementation-deviation log)
- [docs/开发文档.md](docs/开发文档.md) — implementation walkthrough (module by module, key concurrency decisions, pitfalls & post-mortems)

## License

MIT
