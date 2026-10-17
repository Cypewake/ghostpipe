// Package socks5 实现客户端本地 SOCKS5 正向代理入口（M4，设计文档 §7）。
//
// 仅支持：无认证 + CONNECT 命令（覆盖 curl/proxychains/N 的主流用法）。
// 动态目标经 OPEN_ADDR 流由服务端出网——这是 mux 模式专属能力。
package socks5

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Cypewake/ghostpipe/internal/stream"
)

// Serve 在 ln 上提供 SOCKS5 服务。dial 由上层注入（mux.OpenAddr）。
func Serve(ln net.Listener, dial func(target string) (io.ReadWriteCloser, error)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handle(c, dial)
	}
}

var errBadReply = errors.New("SOCKS5 协商失败")

func handle(c net.Conn, dial func(string) (io.ReadWriteCloser, error)) {
	defer c.Close()
	br := bufio.NewReader(c)

	// ---- 方法协商：只接受无认证 ----
	var head [2]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return
	}
	if head[0] != 5 || head[1] == 0 || int(head[1]) > 8 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{0x00}) {
		_, _ = c.Write([]byte{5, 0xFF}) // 无可接受方法
		return
	}
	if _, err := c.Write([]byte{5, 0x00}); err != nil {
		return
	}

	// ---- CONNECT 请求 ----
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return
	}
	if req[0] != 5 || req[1] != 1 { // 仅 CONNECT
		reply(c, 0x07) // command not supported
		return
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 0x03: // 域名
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(br, d); err != nil {
			return
		}
		host = string(d)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	default:
		reply(c, 0x08) // address type not supported
		return
	}
	var portB [2]byte
	if _, err := io.ReadFull(br, portB[:]); err != nil {
		return
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(portB[:])))

	// ---- 经隧道拨号 ----
	st, err := dial(target)
	if err != nil {
		reply(c, 0x01) // general failure
		return
	}
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = st.Close()
		return
	}
	stream.Pump(c, st)
}

func reply(c net.Conn, rep byte) {
	_, _ = c.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}
