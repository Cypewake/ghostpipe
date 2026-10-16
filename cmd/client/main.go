// ghostpipe-client —— 客户端（内网机器侧）。
//
// 用法：
//
//	ghostpipe-client -server vps:9000 -psk <64位hex> -fingerprint <服务端SPKI指纹> \
//	    -tunnel "10022=127.0.0.1:22,10080=127.0.0.1:80" -socks5 127.0.0.1:1080
//
// TLS 默认开启；-fingerprint 必填（防中间人，见服务端启动输出）。
// 明文实验模式：-insecure-tls（同时免 fingerprint，打印醒目警告）。
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ghostpipe/internal/client"
)

func main() {
	server := flag.String("server", "", "服务端地址 host:port（必填）")
	pskHex := flag.String("psk", "", "预共享密钥（64 位 hex，必填）")
	fp := flag.String("fingerprint", "", "服务端 SPKI 指纹（TLS 模式必填）")
	insecure := flag.Bool("insecure-tls", false, "关闭 TLS（明文模式，仅限本地实验！）")
	mode := flag.String("mode", "mux", "数据通道模式：mux（M2 多路复用）| conn（M1 独立数据连接）")
	ws := flag.Bool("ws", false, "WebSocket 载体（M3，与服务端 -ws 配对）")
	socks5 := flag.String("socks5", "", "本地 SOCKS5 监听地址（可选，如 127.0.0.1:1080；仅 mux 模式）")
	tunnels := flag.String("tunnel", "", "隧道清单：\"远端端口=本地目标,远端端口=本地目标\"")
	flag.Parse()

	if *server == "" || *pskHex == "" {
		fmt.Fprintln(os.Stderr, "错误: -server 与 -psk 必填")
		flag.Usage()
		os.Exit(2)
	}
	psk, err := hex.DecodeString(*pskHex)
	if err != nil || len(psk) != 32 {
		fmt.Fprintln(os.Stderr, "错误: -psk 必须是 64 位 hex（32 字节）")
		os.Exit(2)
	}
	if !*insecure && *fp == "" {
		fmt.Fprintln(os.Stderr, "错误: TLS 模式下 -fingerprint 必填（防中间人；或用 -insecure-tls 显式关闭 TLS）")
		os.Exit(2)
	}
	specs, err := client.ParseTunnels(*tunnels)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(2)
	}
	if *insecure {
		log.Println("==========================================================")
		log.Println("⚠️  警告：TLS 已关闭，全部流量明文传输！仅限本地实验使用！")
		log.Println("==========================================================")
	}

	cfg := client.Config{
		ServerAddr:  *server,
		PSK:         psk,
		Fingerprint: *fp,
		UseTLS:      !*insecure,
		WS:          *ws,
		Mode:        *mode,
		Socks5Addr:  *socks5,
		Tunnels:     specs,
	}
	log.Printf("[client] ghostpipe 客户端启动 | 授权声明：仅限授权测试与自用远程访问")

	cl, err := client.Start(cfg)
	if err != nil {
		log.Fatalf("[client] 启动失败: %v", err)
	}
	// 优雅退出：Ctrl+C → UNREGISTER 全部隧道后退出
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Printf("[client] 收到退出信号，注销隧道…")
	cl.Shutdown()
}
