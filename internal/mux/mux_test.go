package mux

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghostpipe/internal/protocol"
	"ghostpipe/internal/transport"
)

type fixture struct {
	client *Mux // 奇数 ID
	server *Mux // 偶数 ID
}

func newFixture(t *testing.T, serverOpenAddr func(*Stream, string)) *fixture {
	t.Helper()
	a, b := net.Pipe()
	ca := transport.NewConn(a, protocol.ProtocolVersion)
	cb := transport.NewConn(b, protocol.ProtocolVersion)
	t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })

	mCli := New(ca, true)
	mSrv := New(cb, false)
	// 客户端：对 OPEN（服务端发起的隧道流）做回显；服务端：对 OPEN_ADDR 回显
	mCli.SetHandlers(func(s *Stream, _ uint16) {
		go echo(s)
	}, nil, nil)
	if serverOpenAddr == nil {
		serverOpenAddr = func(s *Stream, _ string) {
			go echo(s)
		}
	}
	mSrv.SetHandlers(nil, serverOpenAddr, nil)
	go mCli.Run()
	go mSrv.Run()
	t.Cleanup(func() { _ = mCli.Close(); _ = mSrv.Close() })
	return &fixture{client: mCli, server: mSrv}
}

func echo(s *Stream) {
	defer s.Close()
	buf := make([]byte, 16*1024)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			if _, werr := s.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// TestBasicEcho 基本开流-写-回显-读
func TestBasicEcho(t *testing.T) {
	fx := newFixture(t, nil)
	st, err := fx.client.OpenAddr("echo")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello ghostpipe")
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatal("回显不一致")
	}
	_ = st.Close()
}

// TestStreamIDParity StreamID 分配规则：client 奇数 / server 偶数，单调递增
func TestStreamIDParity(t *testing.T) {
	fx := newFixture(t, nil)
	s1, _ := fx.client.OpenAddr("a")
	s2, _ := fx.client.OpenAddr("b")
	if s1.ID()%2 != 1 || s2.ID()%2 != 1 || s2.ID() <= s1.ID() {
		t.Fatalf("客户端流 ID 应为递增奇数: %d %d", s1.ID(), s2.ID())
	}
	t1, err := fx.server.OpenTunnel(8080)
	if err != nil {
		t.Fatal(err)
	}
	if t1.ID()%2 != 0 || t1.ID() < 2 {
		t.Fatalf("服务端流 ID 应为偶数: %d", t1.ID())
	}
}

// TestConcurrentStreams 20 流并发回显，数据完整性
func TestConcurrentStreams(t *testing.T) {
	fx := newFixture(t, nil)
	const n = 20
	const size = 100 * 1024
	var wg sync.WaitGroup
	var fails atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			st, err := fx.client.OpenAddr("echo")
			if err != nil {
				fails.Add(1)
				return
			}
			defer st.Close()
			payload := bytes.Repeat([]byte{seed}, size)
			go st.Write(payload)
			got := make([]byte, size)
			if _, err := io.ReadFull(st, got); err != nil {
				fails.Add(1)
				return
			}
			if !bytes.Equal(got, payload) {
				fails.Add(1)
			}
		}(byte(i + 1))
	}
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatalf("%d 条流失败", fails.Load())
	}
}

// TestFlowControlBlocksAndResumes 流级窗口：写满 256KB 窗口后阻塞，
// 对端应用消费后继续 —— 且阻塞期间 PING/PONG 仍通（控制帧豁免，无死锁）。
func TestFlowControlBlocksAndResumes(t *testing.T) {
	var blocked atomic.Bool
	release := make(chan struct{})
	fx := newFixture(t, func(s *Stream, _ string) {
		// 故意先不读：让发送方写满窗口阻塞；放开后消费全部数据 → 信用归还
		<-release
		_, _ = io.Copy(io.Discard, s)
		_ = s.Close()
	})
	st, err := fx.client.OpenAddr("stall")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x77}, 2*1024*1024) // 2MB ≫ 256KB 窗口

	writeDone := make(chan error, 1)
	go func() {
		blocked.Store(true)
		_, err := st.Write(payload)
		writeDone <- err
	}()
	// 等写阻塞：流级信用耗尽后写必须停住（窗口 256KB ≪ 2MB）
	waitFor(t, 10*time.Second, func() bool {
		if !blocked.Load() {
			return false
		}
		fx.client.mu.Lock()
		defer fx.client.mu.Unlock()
		return st.streamCredit <= 0
	})

	// 阻塞期间控制帧必须仍然通畅（第二轮 #3 修正的验收）
	before := fx.client.conn.LastRecv()
	if err := fx.client.conn.Send(protocol.TypePING, 0, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		return fx.client.conn.LastRecv().After(before) // 收到 PONG
	})
	if selectDone(writeDone) {
		t.Fatal("写窗口未满却已返回")
	}

	// 放开对端 → 信用归还 → 写完成
	close(release)
	if err := <-writeDone; err != nil {
		t.Fatalf("写最终失败: %v", err)
	}
}

// TestLateFramesDiscarded 已关闭流上的 DATA 静默丢弃，连接不受影响
func TestLateFramesDiscarded(t *testing.T) {
	fx := newFixture(t, nil)
	st, _ := fx.client.OpenAddr("echo")
	io.ReadAll(io.LimitReader(st, 0)) // no-op
	_, _ = st.Write([]byte("x"))
	id := st.ID()
	_ = st.Close()
	time.Sleep(200 * time.Millisecond) // 让 CLOSE 送达

	// 注入"迟到"DATA 帧：伪造对端视角的已关闭流数据
	// （直接用底层连接发，绕过本端 mux 的流生命周期）
	if err := fx.client.conn.Send(protocol.TypeDATA, id, []byte("late")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	// 连接必须仍然可用：再开一条流完成一次回显
	st2, err := fx.client.OpenAddr("echo")
	if err != nil {
		t.Fatalf("迟到帧导致连接不可用: %v", err)
	}
	_, _ = st2.Write([]byte("ok"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(st2, buf); err != nil {
		t.Fatalf("回显失败: %v", err)
	}
	if fx.server.LateFrames() == 0 {
		t.Fatal("迟到帧未被计数")
	}
}

// TestUnknownStreamKillsConn DATA 指向从未存在的流 = 协议违规 → 断连
func TestUnknownStreamKillsConn(t *testing.T) {
	fx := newFixture(t, nil)
	if err := fx.client.conn.Send(protocol.TypeDATA, 99999, []byte("ghost")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		fx.server.mu.Lock()
		defer fx.server.mu.Unlock()
		return fx.server.err != nil
	})
}

// TestStreamLimit 并发流上限：超过 256 条拒绝
func TestStreamLimit(t *testing.T) {
	var stall sync.WaitGroup
	stall.Add(400)
	fx := newFixture(t, func(s *Stream, _ string) {
		<-make(chan struct{}) // 永久挂起（测试结束后进程退出无妨）
	})
	var opened int
	var lastErr error
	for i := 0; i < 400; i++ {
		st, err := fx.client.OpenAddr("stall")
		if err != nil {
			lastErr = err
			break
		}
		opened++
		_ = st
	}
	if opened > MaxStreams {
		t.Fatalf("超过上限 %d 仍开出了 %d 条流", MaxStreams, opened)
	}
	if lastErr == nil {
		t.Fatal("达到上限后应返回错误")
	}
	if !errors.Is(lastErr, ErrResourceLimit) {
		t.Fatalf("期望 resource-limit，实际: %v", lastErr)
	}
}

// ---- 工具 ----

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待条件超时（%v）", d)
}

func selectDone(ch chan error) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
