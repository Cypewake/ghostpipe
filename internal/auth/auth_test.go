package auth

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Cypewake/ghostpipe/internal/protocol"
	"github.com/Cypewake/ghostpipe/internal/transport"
)

func newPipeConns(t *testing.T) (*transport.Conn, *transport.Conn) {
	t.Helper()
	a, b := net.Pipe()
	ca := transport.NewConn(a, protocol.ProtocolVersion)
	cb := transport.NewConn(b, protocol.ProtocolVersion)
	t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
	return ca, cb
}

// TestHandshakeSuccess 正常双向认证
func TestHandshakeSuccess(t *testing.T) {
	psk := make([]byte, 32)
	ca, cb := newPipeConns(t)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- Server(cb, psk)
	}()
	if err := Client(ca, psk); err != nil {
		t.Fatalf("客户端认证失败: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("服务端认证失败: %v", err)
	}
}

// TestHandshakeWrongPSK PSK 不匹配必须失败（两侧都报错）
func TestHandshakeWrongPSK(t *testing.T) {
	pskA := make([]byte, 32)
	pskB := make([]byte, 32)
	pskB[0] = 1
	ca, cb := newPipeConns(t)

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- Server(cb, pskA)
	}()
	if err := Client(ca, pskB); err == nil {
		t.Fatal("错误 PSK 下客户端认证竟成功")
	}
	if err := <-serverDone; err == nil {
		t.Fatal("错误 PSK 下服务端认证竟成功")
	}
}

// TestHandshakeTimeout 服务端不发 challenge，客户端必须在握手时限内失败
func TestHandshakeTimeout(t *testing.T) {
	ca, _ := newPipeConns(t)
	start := time.Now()
	err := Client(ca, make([]byte, 32))
	if err == nil {
		t.Fatal("无响应时认证不应成功")
	}
	if el := time.Since(start); el > HandshakeTimeout+2*time.Second {
		t.Fatalf("超时未生效: 耗时 %v", el)
	}
}

// TestServerRejectsBadResponse 服务端挑战后收到非 AUTH_RESP 帧 → 拒绝
func TestServerRejectsBadResponse(t *testing.T) {
	ca, cb := newPipeConns(t)
	serverDone := make(chan error, 1)
	go func() {
		nonceS, err := ServerChallenge(cb)
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- ServerVerify(cb, make([]byte, 32), nonceS, nil)
	}()
	// 客户端不按协议回应，直接发 PING
	if _, err := ca.Receive(); err != nil { // 吃掉 AUTH_REQ
		t.Fatal(err)
	}
	if err := ca.Send(protocol.TypePING, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err == nil {
		t.Fatal("错误应答帧应被拒绝")
	} else if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("期望 ErrAuthFailed，实际: %v", err)
	}
}
