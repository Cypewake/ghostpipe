// ghostpipe-server —— 服务端（公网 VPS 侧）。
//
// 用法：
//
//	ghostpipe-server -listen 0.0.0.0:9000 -psk <64位hex>
//
// 默认仅监听 127.0.0.1（合规默认值）；公网部署显式指定 -listen 0.0.0.0:端口。
// PSK 留空则自动生成 32 字节随机密钥并打印（客户端需使用同一 PSK）。
// TLS 默认开启，启动打印自签证书 SPKI 指纹（供客户端 pinning）。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"ghostpipe/internal/server"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9000", "控制监听地址（映射端口绑定同 host；公网部署用 0.0.0.0:端口）")
	pskHex := flag.String("psk", "", "预共享密钥（64 位 hex = 32 字节；留空自动生成）")
	insecure := flag.Bool("insecure-tls", false, "关闭 TLS（明文模式，仅限本地实验！）")
	mode := flag.String("mode", "mux", "数据通道模式：mux（M2 多路复用）| conn（M1 独立数据连接）")
	ws := flag.Bool("ws", false, "启用 WebSocket 载体（M3，路径 /ghostpipe）")
	flag.Parse()

	psk, err := parsePSK(*pskHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(2)
	}
	if *insecure {
		log.Println("==========================================================")
		log.Println("⚠️  警告：TLS 已关闭，全部流量明文传输！仅限本地实验使用！")
		log.Println("==========================================================")
	}

	cfg := server.Config{
		Listen: *listen,
		PSK:    psk,
		UseTLS: !*insecure,
		WS:     *ws,
		Mode:   *mode,
	}
	log.Printf("[server] ghostpipe 服务端启动 | 授权声明：仅限授权测试与自用远程访问")
	if err := server.Run(cfg); err != nil {
		log.Fatalf("[server] 退出: %v", err)
	}
}

func parsePSK(s string) ([]byte, error) {
	if s == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		log.Printf("[server] 未提供 -psk，已随机生成（请复制给客户端）: %s", hex.EncodeToString(b))
		return b, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("-psk 必须是 64 位 hex（32 字节）")
	}
	return b, nil
}
