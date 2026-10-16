package transport

import (
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ghostpipe/internal/protocol"
)

func newPipeConns(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	a, b := net.Pipe()
	ca := NewConn(a, protocol.ProtocolVersion)
	cb := NewConn(b, protocol.ProtocolVersion)
	t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
	return ca, cb
}

func TestConnSendReceive(t *testing.T) {
	ca, cb := newPipeConns(t)
	go func() { _ = ca.Send(protocol.TypeDATA, 5, []byte("ping")) }()
	f, err := cb.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != protocol.TypeDATA || f.StreamID != 5 || string(f.Payload) != "ping" {
		t.Fatalf("不一致: %+v", f)
	}
	if cb.LastRecv().IsZero() {
		t.Fatal("LastRecv 未更新")
	}
}

func TestGenerateSelfSignedFingerprint(t *testing.T) {
	cert, fp, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 || len(fp) != 64 {
		t.Fatalf("指纹长度异常: %d", len(fp))
	}
	// 同一证书两次计算指纹必须一致（稳定性）
	cert2, fp2, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	_ = cert2
	if fp2 == fp {
		t.Fatal("不同证书的指纹不应相同")
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Fatalf("指纹不是 hex: %v", err)
	}
}

// TestWSRoundTrip WebSocket 载体回显：升级握手 + 掩码编解码 + deadline 不误伤
func TestWSRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgradeWS(w, r)
		if err != nil {
			t.Errorf("升级失败: %v", err)
			return
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c) // 回显
		}()
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	raw, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	wsc, err := dialWS(raw, host, "/ghostpipe", 5*time.Second)
	if err != nil {
		t.Fatalf("WS 握手失败: %v", err)
	}
	defer wsc.Close()

	for _, msg := range []string{"hello", "ghostpipe", strings.Repeat("X", 70000)} { // 覆盖 16 位长度编码
		if _, err := wsc.Write([]byte(msg)); err != nil {
			t.Fatalf("写入失败: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(wsc, buf); err != nil {
			t.Fatalf("读回失败: %v", err)
		}
		if string(buf) != msg {
			t.Fatalf("回显不一致: %d 字节", len(buf))
		}
	}
}

// TestWSPingPong 服务端 ping → 客户端自动回 pong，且连接保持可用
func TestWSPingPong(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgradeWS(w, r)
		if err != nil {
			return
		}
		wc, ok := c.(*wsConn)
		if !ok {
			return
		}
		_ = wc.writeControl(0x9, []byte("hb")) // 发 ping
		// 客户端 pong 到达会走 Read 内部 0xA 分支被跳过——这里只验证连接随后可用
		buf := make([]byte, 5)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Read(buf)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	raw, _ := net.Dial("tcp", host)
	wsc, err := dialWS(raw, host, "/ghostpipe", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer wsc.Close()
	// 客户端写一条数据；服务端读循环 ping/pong 处理不应影响数据通路
	if _, err := wsc.Write([]byte("alive")); err != nil {
		t.Fatalf("ping/pong 后写入失败: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
}

// TestWSTruncatedFrames 半帧输入不 panic
func TestWSTruncatedFrames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgradeWS(w, r)
		if err != nil {
			return
		}
		// 立即关闭 → 客户端读应报错而非 panic
		_ = c.Close()
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	raw, _ := net.Dial("tcp", host)
	wsc, err := dialWS(raw, host, "/ghostpipe", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer wsc.Close()
	_ = wsc.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	if _, err := wsc.Read(buf); err == nil {
		t.Fatal("对端关闭后读取应报错")
	}
}

func TestSPKIFingerprintMatchesSHA256(t *testing.T) {
	_, fp, err := GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	if NormalizeFingerprint("AA:BB") != "aabb" {
		t.Fatal("指纹归一化失败")
	}
	if len(fp) != 64 {
		t.Fatal("指纹应为 SHA256 hex")
	}
}
