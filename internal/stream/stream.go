// Package stream 定义 M1/M2 通用的流抽象与转发泵（设计文档 §5.1）。
//
// 抽象的目的：上层转发逻辑只面向 Stream 接口，M1（独立数据连接 ConnStream）
// 与 M2（多路复用 MuxStream）可互换，转发层零改动——消除"核心模块写两遍"。
package stream

import (
	"io"
	"net"
)

// Stream 统一流接口
type Stream interface {
	io.ReadWriteCloser
	ID() uint32
}

// ConnStream M1 模式：一条独立数据连接即一条流（绑定后进入纯字节转发）。
type ConnStream struct {
	net.Conn
}

// NewConnStream 包装数据连接
func NewConnStream(c net.Conn) *ConnStream { return &ConnStream{Conn: c} }

// ID M1 流无复用 ID，恒 0
func (s *ConnStream) ID() uint32 { return 0 }

// Pump 双向转发：任一方向出错即关闭两端。
// 典型用法：Pump(外部连接, Stream)。
func Pump(a, b io.ReadWriteCloser) {
	go func() {
		_, _ = io.Copy(a, b)
		_ = a.Close()
		_ = b.Close()
	}()
	_, _ = io.Copy(b, a)
	_ = a.Close()
	_ = b.Close()
}
